package broker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/layertwo/tunnels/internal/store"
)

const sitesDomain = "w.tunnels.layertwo.dev"

type authzRig struct {
	authz  Authz
	users  *fakeUsers
	shares *fakeShares
	logs   *bytes.Buffer
}

func newAuthzRig() *authzRig {
	users := newUsers(
		store.User{Sub: "sub-alice", Handle: "alice"},
		store.User{Sub: "sub-bob", Handle: "bob"},
		store.User{Sub: "sub-dave", Handle: "dave", Disabled: true},
	)
	shares := &fakeShares{}
	logs := &bytes.Buffer{}
	return &authzRig{
		authz:  Authz{Users: users, Shares: shares, SitesDomain: sitesDomain, Log: slog.New(slog.NewJSONHandler(logs, nil))},
		users:  users,
		shares: shares,
		logs:   logs,
	}
}

// fakeShares is an in-memory Shares: a user grantee matches case-insensitively, a group grantee exactly,
// and it records every call.
type fakeShares struct {
	users   []string  // user grantees
	groups  []string  // group grantees
	expires time.Time // when non-zero and past, every grant has expired
	err     error
	calls   []shareCall

	rows     []store.Share // SharesByOwner answer
	storeErr error         // what the management methods fail with
	getSubs  []string      // ownerSub of every SharesByOwner call
	puts     []shareWrite  // every PutShare call
	deletes  []shareWrite  // every DeleteShare call
}

type shareCall struct {
	ownerSub, tunnel, username string
	groups                     []string
}

// shareWrite is one PutShare or DeleteShare call.
type shareWrite struct {
	ownerSub string
	share    store.Share
}

func (f *fakeShares) PutShare(_ context.Context, ownerSub string, sh store.Share) error {
	if f.storeErr != nil {
		return f.storeErr
	}
	f.puts = append(f.puts, shareWrite{ownerSub, sh})
	return nil
}

func (f *fakeShares) DeleteShare(_ context.Context, ownerSub string, sh store.Share) error {
	if f.storeErr != nil {
		return f.storeErr
	}
	f.deletes = append(f.deletes, shareWrite{ownerSub, sh})
	return nil
}

func (f *fakeShares) SharesByOwner(_ context.Context, ownerSub string) ([]store.Share, error) {
	f.getSubs = append(f.getSubs, ownerSub)
	if f.storeErr != nil {
		return nil, f.storeErr
	}
	return f.rows, nil
}

func (f *fakeShares) ShareMatches(_ context.Context, ownerSub, tunnel, username string, groups []string) (bool, error) {
	f.calls = append(f.calls, shareCall{ownerSub, tunnel, username, groups})
	if f.err != nil {
		return false, f.err
	}
	if !f.expires.IsZero() && !f.expires.After(time.Now()) {
		return false, nil // the store ignores expired rows
	}
	for _, grantee := range f.users {
		if strings.EqualFold(grantee, username) {
			return true, nil
		}
	}
	for _, grantee := range f.groups {
		for _, g := range groups {
			if grantee == g {
				return true, nil
			}
		}
	}
	return false, nil
}

// ownerRequest is what Traefik's forwardAuth sends for alice browsing her own site.
func ownerRequest() http.Header {
	h := http.Header{}
	h.Set("X-Forwarded-Host", "alice-blog."+sitesDomain)
	h.Set("X-Tunnels-Sub", "sub-alice")
	h.Set("X-Tunnels-User", "alice")
	return h
}

func (r *authzRig) serve(method string, h http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/authz", nil)
	for k, v := range h { // not Header.Set: a request may carry a header twice or in an odd case
		req.Header[k] = v
	}
	w := httptest.NewRecorder()
	r.authz.ServeHTTP(w, req)
	return w
}

func TestOwnerAllowed(t *testing.T) {
	for _, host := range []string{"alice." + sitesDomain, "alice-blog." + sitesDomain, "alice-a-b-c." + sitesDomain} {
		r := newAuthzRig()
		h := ownerRequest()
		h.Set("X-Forwarded-Host", host)
		w := r.serve(http.MethodGet, h)
		if w.Code != http.StatusOK || w.Header().Get("X-Tunnel-User") != "alice" || w.Body.Len() != 0 {
			t.Errorf("%s = %d %v %q, want 200, X-Tunnel-User: alice and no body", host, w.Code, w.Header(), w.Body)
		}
	}
}

// Traefik's forwardAuth uses GET, but nothing here depends on the method.
func TestAnyMethod(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		w := newAuthzRig().serve(m, ownerRequest())
		if w.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200", m, w.Code)
		}
	}
}

// The app is told who is looking, which is what the identity headers say, not who owns the site.
func TestAppSeesTheVisitorsUsername(t *testing.T) {
	for _, user := range []string{"Alice.Smith@example.com", "ünal", "a b"} {
		h := ownerRequest()
		h.Set("X-Tunnels-User", user)
		h.Set("X-Tunnel-User", "admin") // what a visitor might send; never what the app is told
		w := newAuthzRig().serve(http.MethodGet, h)
		if got := w.Header().Values("X-Tunnel-User"); w.Code != 200 || !reflect.DeepEqual(got, []string{user}) {
			t.Errorf("user %q: = %d %q, want 200 and exactly that name", user, w.Code, got)
		}
	}
}

func TestUppercaseHostIsNormalised(t *testing.T) {
	h := ownerRequest()
	h.Set("X-Forwarded-Host", "Alice-Blog.W.Tunnels.Layertwo.Dev")
	if w := newAuthzRig().serve(http.MethodGet, h); w.Code != http.StatusOK {
		t.Errorf("= %d, want 200", w.Code)
	}
	r := newAuthzRig()
	r.authz.SitesDomain = "W.Tunnels.Layertwo.Dev"
	if w := r.serve(http.MethodGet, ownerRequest()); w.Code != http.StatusOK {
		t.Errorf("sites domain in capitals = %d, want 200", w.Code)
	}
}

func TestDeniedCases(t *testing.T) {
	set := func(k string, v ...string) func(http.Header) { return func(h http.Header) { h[k] = v } }
	host := func(v string) func(http.Header) { return set("X-Forwarded-Host", v) }
	tests := []struct {
		name  string
		mod   func(http.Header)
		calls int // how many times the store may be asked
	}{
		// who
		{"another user's sub", set("X-Tunnels-Sub", "sub-bob"), 1},
		{"owner's sub in the wrong case", set("X-Tunnels-Sub", "SUB-ALICE"), 1},
		{"owner's sub with a suffix", set("X-Tunnels-Sub", "sub-alice-2"), 1},
		{"owner's sub as one of a list", set("X-Tunnels-Sub", "sub-bob, sub-alice"), 1},
		{"unknown owner", host("carol." + sitesDomain), 1},
		{"unknown owner, named tunnel", host("carol-blog." + sitesDomain), 1},
		{"disabled owner", func(h http.Header) {
			h.Set("X-Forwarded-Host", "dave."+sitesDomain)
			h.Set("X-Tunnels-Sub", "sub-dave")
		}, 1},
		{"label that is another user's tunnel", func(h http.Header) { h.Set("X-Forwarded-Host", "bob-alice."+sitesDomain) }, 1},
		// where
		{"outside the sites domain", host("alice-blog.example.com"), 0},
		{"sites domain as a suffix of another domain", host("alice-blog." + sitesDomain + ".evil.com"), 0},
		{"sites domain without a label", host(sitesDomain), 0},
		{"parent domain", host("alice-blog.tunnels.layertwo.dev"), 0},
		{"port", host("alice-blog." + sitesDomain + ":443"), 0},
		{"trailing dot", host("alice-blog." + sitesDomain + "."), 0},
		{"extra label", host("x.alice-blog." + sitesDomain), 0},
		{"comma", host("alice-blog." + sitesDomain + ",evil.example.com"), 0},
		{"comma before", host("evil.example.com,alice-blog." + sitesDomain), 0},
		{"label alice-default", host("alice-default." + sitesDomain), 0},
		{"label with an underscore", host("alice_b." + sitesDomain), 0},
		{"label with a leading dash", host("-blog." + sitesDomain), 0},
		{"label with a trailing dash", host("alice-." + sitesDomain), 0},
		{"label that is too long", host(strings.Repeat("a", 64) + "." + sitesDomain), 0},
		{"non-ASCII letter", host("alicé-blog." + sitesDomain), 0},
		{"Kelvin sign", host("\u212Aevin." + sitesDomain), 0},
		{"space", host("alice-blog. " + sitesDomain), 0},
		{"no host", func(h http.Header) { delete(h, "X-Forwarded-Host") }, 0},
		{"empty host", host(""), 0},
		{"two host lines", set("X-Forwarded-Host", "alice-blog."+sitesDomain, "alice-blog."+sitesDomain), 0},
		{"two host lines, the first foreign", set("X-Forwarded-Host", "evil.example.com", "alice-blog."+sitesDomain), 0},
		// the identity headers
		{"no sub", func(h http.Header) { delete(h, "X-Tunnels-Sub") }, 0},
		{"empty sub", set("X-Tunnels-Sub", ""), 0},
		{"two subs, equal", set("X-Tunnels-Sub", "sub-alice", "sub-alice"), 0},
		{"two subs, the first matching", set("X-Tunnels-Sub", "sub-alice", "sub-bob"), 0},
		{"two subs, the second matching", set("X-Tunnels-Sub", "sub-bob", "sub-alice"), 0},
		{"no user", func(h http.Header) { delete(h, "X-Tunnels-User") }, 0},
		{"empty user", set("X-Tunnels-User", ""), 0},
		{"two users", set("X-Tunnels-User", "alice", "alice"), 0},
		{"two users, one empty", set("X-Tunnels-User", "alice", ""), 0},
		{"no identity at all", func(h http.Header) { delete(h, "X-Tunnels-Sub"); delete(h, "X-Tunnels-User") }, 0},
	}

	// The reference: what the broker says about a name that does not exist.
	want := newAuthzRig().serve(http.MethodGet, func() http.Header { h := ownerRequest(); h.Set("X-Forwarded-Host", "nobody."+sitesDomain); return h }())
	if want.Code != http.StatusForbidden || want.Body.Len() != 0 {
		t.Fatalf("unknown owner = %d %q, want an empty 403", want.Code, want.Body)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newAuthzRig()
			h := ownerRequest()
			tt.mod(h)
			w := r.serve(http.MethodGet, h)

			if w.Code != http.StatusForbidden || w.Body.Len() != 0 {
				t.Errorf("= %d %q, want an empty 403", w.Code, w.Body)
			}
			if !reflect.DeepEqual(w.Header(), want.Header()) {
				t.Errorf("response headers %v differ from the unknown-owner answer %v", w.Header(), want.Header())
			}
			if got := len(r.users.calls); got > tt.calls {
				t.Errorf("%d store calls %q, want at most %d (cheap checks come first)", got, r.users.calls, tt.calls)
			}
		})
	}
}

func TestEmptySitesDomainDeniesEverything(t *testing.T) {
	r := newAuthzRig()
	r.authz.SitesDomain = ""
	for _, host := range []string{"alice-blog.", "alice-blog", "alice-blog." + sitesDomain, ""} {
		h := ownerRequest()
		h.Set("X-Forwarded-Host", host)
		if w := r.serve(http.MethodGet, h); w.Code != http.StatusForbidden {
			t.Errorf("host %q with no sites domain configured = %d, want 403", host, w.Code)
		}
	}
	if len(r.users.calls) != 0 {
		t.Errorf("store calls %q", r.users.calls)
	}
}

func TestStoreErrorIs503(t *testing.T) {
	r := newAuthzRig()
	r.users.byHandleErr = errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")
	w := r.serve(http.MethodGet, ownerRequest())
	if w.Code != http.StatusServiceUnavailable || w.Body.Len() != 0 || len(w.Header()) != 0 {
		t.Errorf("= %d %v %q, want an empty 503 without headers", w.Code, w.Header(), w.Body)
	}

	// Not found is an answer ("nobody owns this"), not an outage.
	r = newAuthzRig()
	r.users.byHandleErr = store.ErrNotFound
	if w := r.serve(http.MethodGet, ownerRequest()); w.Code != http.StatusForbidden {
		t.Errorf("not found = %d, want 403", w.Code)
	}
}

// Postgres that stops answering must not hold a visitor's request for ever.
func TestSlowStoreIs503WithinTheDeadline(t *testing.T) {
	r := newAuthzRig()
	r.users.block = true
	r.authz.Timeout = 50 * time.Millisecond
	start := time.Now()
	if w := r.serve(http.MethodGet, ownerRequest()); w.Code != http.StatusServiceUnavailable {
		t.Errorf("= %d, want 503", w.Code)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("took %v for a 50 ms deadline", took)
	}
	if got := (Authz{}).timeout(); got <= 0 || got > 10*time.Second {
		t.Errorf("default deadline = %v, want a few seconds", got)
	}
}

func TestAuthzLogsOneLinePerDecision(t *testing.T) {
	tests := []struct {
		name  string
		setup func(r *authzRig, h http.Header)
		want  map[string]any // keys that must be present with this value; a nil value means absent
	}{
		{"allowed", nil,
			map[string]any{"decision": "allow", "reason": "owner", "label": "alice-blog", "sub": "sub-alice"}},
		{"another user", func(r *authzRig, h http.Header) { h.Set("X-Tunnels-Sub", "sub-bob") },
			map[string]any{"decision": "deny", "reason": "not_owner", "label": "alice-blog", "sub": "sub-bob"}},
		{"unknown owner", func(r *authzRig, h http.Header) { h.Set("X-Forwarded-Host", "carol."+sitesDomain) },
			map[string]any{"decision": "deny", "reason": "unknown_owner", "label": "carol", "sub": "sub-alice"}},
		{"disabled owner", func(r *authzRig, h http.Header) {
			h.Set("X-Forwarded-Host", "dave."+sitesDomain)
			h.Set("X-Tunnels-Sub", "sub-dave")
		},
			map[string]any{"decision": "deny", "reason": "disabled", "label": "dave", "sub": "sub-dave"}},
		{"malformed host", func(r *authzRig, h http.Header) { h["X-Forwarded-Host"] = []string{"evil\n.example.com"} },
			map[string]any{"decision": "deny", "reason": "host", "label": nil, "sub": nil}},
		{"missing identity", func(r *authzRig, h http.Header) { delete(h, "X-Tunnels-Sub") },
			map[string]any{"decision": "deny", "reason": "identity", "label": "alice-blog", "sub": nil}},
		{"store down", func(r *authzRig, h http.Header) { r.users.byHandleErr = errors.New("connection refused") },
			map[string]any{"decision": "error", "reason": "store", "label": "alice-blog", "err": "connection refused"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newAuthzRig()
			h := ownerRequest()
			h.Set("X-Tunnels-User", "Distinctive.Visitor")
			if tt.setup != nil {
				tt.setup(r, h)
			}
			r.serve(http.MethodGet, h)

			lines := strings.Split(strings.TrimSpace(r.logs.String()), "\n")
			if len(lines) != 1 {
				t.Fatalf("%d log lines, want one:\n%s", len(lines), r.logs)
			}
			var got map[string]any
			if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
				t.Fatal(err)
			}
			for k, want := range tt.want {
				if _, present := got[k]; want == nil && present {
					t.Errorf("log has %q = %v, want it absent", k, got[k])
				} else if want != nil && got[k] != want {
					t.Errorf("log[%q] = %v, want %v (line %v)", k, got[k], want, got)
				}
			}
			// No header values beyond the sub: not the username, not the host as sent.
			for _, secret := range []string{"Distinctive.Visitor", "evil"} {
				if strings.Contains(r.logs.String(), secret) {
					t.Errorf("the log contains %q:\n%s", secret, r.logs)
				}
			}
		})
	}
}

// Header names arrive in any case on the wire; net/http stores them under their canonical names,
// which is what Authz looks up.
func TestHeaderNamesInAnyCase(t *testing.T) {
	r := newAuthzRig()
	srv := httptest.NewServer(r.authz)
	t.Cleanup(srv.Close)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /authz HTTP/1.1\r\nHost: broker\r\nx-forwarded-host: alice-blog.%s\r\nx-tunnels-sub: sub-alice\r\nX-TUNNELS-USER: alice\r\nConnection: close\r\n\r\n", sitesDomain)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Tunnel-User") != "alice" {
		t.Errorf("= %d %v, want 200 for the owner whatever the case of the header names", resp.StatusCode, resp.Header)
	}
}

// sharedRequest is a stranger (not the owner) browsing one of alice's sites.
func sharedRequest(host string) http.Header {
	h := http.Header{}
	h.Set("X-Forwarded-Host", host+"."+sitesDomain)
	h.Set("X-Tunnels-Sub", "sub-stranger")
	h.Set("X-Tunnels-User", "bob")
	return h
}

func TestSharedUserAllowed(t *testing.T) {
	r := newAuthzRig()
	r.shares.users = []string{"bob"}
	w := r.serve(http.MethodGet, sharedRequest("alice-blog"))
	if w.Code != http.StatusOK || w.Header().Get("X-Tunnel-User") != "bob" || w.Body.Len() != 0 {
		t.Fatalf("= %d %v %q, want 200 as bob", w.Code, w.Header(), w.Body)
	}
	if got := r.shares.calls; len(got) != 1 || got[0].ownerSub != "sub-alice" || got[0].tunnel != "blog" || got[0].username != "bob" {
		t.Errorf("ShareMatches calls %+v, want sub-alice, tunnel blog, bob", got)
	}
}

// An expired share is invisible to authz, so a visitor it once admitted is refused.
func TestAuthzIgnoresExpiredShare(t *testing.T) {
	r := newAuthzRig()
	r.shares.users = []string{"bob"}
	r.shares.expires = time.Now().Add(-time.Hour)
	w := r.serve(http.MethodGet, sharedRequest("alice-blog"))
	if w.Code != http.StatusForbidden || w.Body.Len() != 0 {
		t.Errorf("= %d %q, want an empty 403 for an expired share", w.Code, w.Body)
	}
}

func TestSharedUserCaseInsensitive(t *testing.T) {
	r := newAuthzRig()
	r.shares.users = []string{"bob"}
	h := sharedRequest("alice-blog")
	h.Set("X-Tunnels-User", "Bob")
	if w := r.serve(http.MethodGet, h); w.Code != http.StatusOK {
		t.Errorf("= %d, want 200 for Bob with a bob share", w.Code)
	}

	// A share of bob must not admit a name that only shares the prefix.
	r = newAuthzRig()
	r.shares.users = []string{"bob"}
	h = sharedRequest("alice-blog")
	h.Set("X-Tunnels-User", "bobby")
	if w := r.serve(http.MethodGet, h); w.Code != http.StatusForbidden {
		t.Errorf("= %d, want 403 for bobby with a bob share", w.Code)
	}
}

func TestSharedGroupAllowed(t *testing.T) {
	r := newAuthzRig()
	r.shares.groups = []string{"family"}
	h := sharedRequest("alice-blog")
	h.Set("X-Tunnels-Groups", "work,family")
	if w := r.serve(http.MethodGet, h); w.Code != http.StatusOK {
		t.Fatalf("= %d, want 200 for a family member", w.Code)
	}
	if got := r.shares.calls[0].groups; !reflect.DeepEqual(got, []string{"work", "family"}) {
		t.Errorf("groups passed = %q, want [work family]", got)
	}
}

func TestGroupsAcrossHeaderValues(t *testing.T) {
	r := newAuthzRig()
	r.shares.groups = []string{"family"}
	h := sharedRequest("alice-blog")
	h["X-Tunnels-Groups"] = []string{"work", "family"}
	if w := r.serve(http.MethodGet, h); w.Code != http.StatusOK {
		t.Fatalf("= %d, want 200 for a family member across header values", w.Code)
	}
	if got := r.shares.calls[0].groups; !reflect.DeepEqual(got, []string{"work", "family"}) {
		t.Errorf("groups passed = %q, want [work family]", got)
	}
}

func TestNotSharedDenied(t *testing.T) {
	r := newAuthzRig()
	w := r.serve(http.MethodGet, sharedRequest("alice-blog"))
	if w.Code != http.StatusForbidden || w.Body.Len() != 0 {
		t.Errorf("= %d %q, want an empty 403", w.Code, w.Body)
	}
}

func TestShareLookupErrorIs503(t *testing.T) {
	r := newAuthzRig()
	r.shares.err = errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")
	w := r.serve(http.MethodGet, sharedRequest("alice-blog"))
	if w.Code != http.StatusServiceUnavailable || w.Body.Len() != 0 || len(w.Header()) != 0 {
		t.Errorf("= %d %v %q, want an empty 503 without headers", w.Code, w.Header(), w.Body)
	}
}

// A broker without a shares store must answer 503 when a visitor needs the share lookup, not panic.
func TestAuthzNilSharesIs503(t *testing.T) {
	r := newAuthzRig()
	r.authz.Shares = nil
	w := r.serve(http.MethodGet, sharedRequest("alice-blog"))
	if w.Code != http.StatusServiceUnavailable || w.Body.Len() != 0 || len(w.Header()) != 0 {
		t.Errorf("= %d %v %q, want an empty 503 without headers", w.Code, w.Header(), w.Body)
	}
}

func TestOwnerStillAllowed(t *testing.T) {
	r := newAuthzRig()
	if w := r.serve(http.MethodGet, ownerRequest()); w.Code != http.StatusOK {
		t.Fatalf("= %d, want 200", w.Code)
	}
	if len(r.shares.calls) != 0 {
		t.Errorf("ShareMatches calls %+v for the owner, want none", r.shares.calls)
	}
}

// A browser page served from one creator's tunnel must not make a state-changing request to
// another creator's tunnel riding the visitor's session: the Origin names a different owner.
func TestCrossOwnerStateChangeRefused(t *testing.T) {
	h := ownerRequest()
	h.Set("Origin", "https://bob-x."+sitesDomain)
	w := newAuthzRig().serve(http.MethodPost, h)
	if w.Code != http.StatusForbidden || w.Body.Len() != 0 {
		t.Errorf("= %d %q, want an empty 403", w.Code, w.Body)
	}
}

// A non-default port on the Origin host must not slip the check: the port is not part of the
// sites host, so the owner is still bob.
func TestCrossOwnerStateChangeWithPortRefused(t *testing.T) {
	h := ownerRequest()
	h.Set("Origin", "https://bob-x."+sitesDomain+":8443")
	if w := newAuthzRig().serve(http.MethodPost, h); w.Code != http.StatusForbidden {
		t.Errorf("= %d, want 403", w.Code)
	}
}

// Safe methods cannot change anything, so they are never refused for their Origin.
func TestCrossOwnerSafeMethodAllowed(t *testing.T) {
	h := ownerRequest()
	h.Set("Origin", "https://bob-x."+sitesDomain)
	if w := newAuthzRig().serve(http.MethodGet, h); w.Code != http.StatusOK {
		t.Errorf("= %d, want 200", w.Code)
	}
}

func TestSameOwnerOriginAllowed(t *testing.T) {
	h := ownerRequest()
	h.Set("Origin", "https://alice-other."+sitesDomain)
	if w := newAuthzRig().serve(http.MethodPost, h); w.Code != http.StatusOK {
		t.Errorf("= %d, want 200", w.Code)
	}
}

func TestForeignOriginAllowed(t *testing.T) {
	h := ownerRequest()
	h.Set("Origin", "https://example.com")
	if w := newAuthzRig().serve(http.MethodPost, h); w.Code != http.StatusOK {
		t.Errorf("= %d, want 200", w.Code)
	}
}

// A non-browser client sends no Origin and is let through.
func TestOriginAbsentAllowed(t *testing.T) {
	if w := newAuthzRig().serve(http.MethodPost, ownerRequest()); w.Code != http.StatusOK {
		t.Errorf("= %d, want 200", w.Code)
	}
}

// Only a valid sites Origin owned by someone else is refused. A host that merely looks like a
// sites host (Traefik never routes it) or an unparseable Origin is foreign, so it is allowed.
func TestMalformedOriginAllowed(t *testing.T) {
	for _, origin := range []string{"https://alice-blog." + sitesDomain + ".evil", "://"} {
		h := ownerRequest()
		h.Set("Origin", origin)
		if w := newAuthzRig().serve(http.MethodPost, h); w.Code != http.StatusOK {
			t.Errorf("origin %q = %d, want 200", origin, w.Code)
		}
	}
}

func TestGroupsOf(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   []string
	}{
		{"no header", nil, nil},
		{"one", []string{"work"}, []string{"work"}},
		{"comma separated", []string{"work,family"}, []string{"work", "family"}},
		{"several values", []string{"work", "family"}, []string{"work", "family"}},
		{"spaces and empties dropped", []string{" work , ,family, "}, []string{"work", "family"}},
		{"empty", []string{""}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/authz", nil)
			r.Header["X-Tunnels-Groups"] = tt.values
			if got := groupsOf(r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("groupsOf(%q) = %q, want %q", tt.values, got, tt.want)
			}
		})
	}
}
