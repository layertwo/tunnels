package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	plugin "github.com/fatedier/frp/pkg/plugin/server"

	"github.com/layertwo/tunnels/internal/idp"
	"github.com/layertwo/tunnels/internal/mockidp"
	"github.com/layertwo/tunnels/internal/store"
)

func testConfig(issuer string) Config {
	return Config{
		ServiceHost: "tunnels.layertwo.dev", SitesDomain: sitesDomain,
		Issuer: issuer, APIResource: mockidp.APIResource, CreatorsGroup: creators,
		UsernameClaim: "preferred_username", GroupsClaim: "groups",
		CLIClientID: "tunnels-cli", MinCLIVersion: "0.2.0",
		PluginSecret: pluginSecret, MaxTunnelsPerUser: 5, BandwidthLimit: "10MB",
		Reserved: []string{"admin"},
	}
}

// serverRig is the whole handler over a real idp.Client talking to the mock identity provider.
type serverRig struct {
	h      http.Handler
	idp    *mockidp.Server
	client *idp.Client
	users  *fakeUsers
	shares *fakeShares
	frps   *fakeFrps
	cfg    Config
	logs   *bytes.Buffer
}

func newServerRig(t *testing.T) *serverRig {
	t.Helper()
	m := mockidp.New(t)
	m.AddUser(mockidp.User{Sub: "sub-alice", Username: "Alice", Groups: []string{creators, "tunnels-viewers"}})
	m.AddUser(mockidp.User{Sub: "sub-vera", Username: "vera", Groups: []string{"tunnels-viewers"}})
	client, err := idp.New(t.Context(), m.URL, mockidp.APIResource, "tunnels-test/1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	r := &serverRig{idp: m, client: client, users: newUsers(), shares: &fakeShares{}, frps: &fakeFrps{online: map[string]string{}}, cfg: testConfig(m.URL), logs: &bytes.Buffer{}}
	r.h = NewHandler(r.cfg, Deps{
		IdP: client, Verifier: client, Users: r.users, Shares: r.shares, Frps: r.frps,
		Log: slog.New(slog.NewJSONHandler(r.logs, nil)),
	})
	return r
}

func (r *serverRig) do(method, target string, hdr http.Header, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range hdr {
		req.Header[k] = v
	}
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

func bearer(token string) http.Header { return http.Header{"Authorization": {"Bearer " + token}} }

func TestRoutes(t *testing.T) {
	r := newServerRig(t)
	login := `{"version":"0.1.0","op":"Login","content":{"user":"x"}}`
	tests := []struct {
		name, method, target string
		hdr                  http.Header
		body                 string
		code                 int
		contains             string
	}{
		{"plugin with the secret", "POST", "/plugin/" + pluginSecret, nil, login, 200, `"reject_reason":"missing token"`},
		{"plugin with the secret and a query", "POST", "/plugin/" + pluginSecret + "?version=0.1.0&op=Login", nil, login, 200, `"reject":true`},
		{"plugin with a wrong secret", "POST", "/plugin/wrong", nil, login, 404, ""},
		{"plugin with a wrong secret, GET", "GET", "/plugin/wrong", nil, "", 404, ""},
		{"plugin with the secret, GET", "GET", "/plugin/" + pluginSecret, nil, "", 400, ""},
		{"plugin without a secret", "POST", "/plugin/", nil, login, 404, ""},
		{"authz without identity", "GET", "/authz", nil, "", 403, ""},
		{"authz for the owner", "GET", "/authz", ownerRequest(), "", 200, ""},
		{"authz by POST", "POST", "/authz", ownerRequest(), "", 200, ""},
		{"authz with a slash", "GET", "/authz/", ownerRequest(), "", 404, ""},
		{"healthz", "GET", "/healthz", nil, "", 200, "ok"},
		{"healthz by POST", "POST", "/healthz", nil, "", 405, ""},
		{"unknown path", "GET", "/nope", nil, "", 404, ""},
		{"root", "GET", "/", nil, "", 404, ""},
		{"api root", "GET", "/api", nil, "", 404, ""},
		{"api me by POST", "POST", "/api/me", bearer("x"), "", 405, ""},
		{"well-known by POST", "POST", "/.well-known/tunnels.json", nil, "", 405, ""},
		{"install script", "GET", "/install.sh", nil, "", 404, ""},
	}
	// alice must exist for the authz allow rows
	r.users.users["sub-alice"] = store.User{Sub: "sub-alice", Handle: "alice"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := r.do(tt.method, tt.target, tt.hdr, tt.body)
			if w.Code != tt.code || !strings.Contains(w.Body.String(), tt.contains) {
				t.Errorf("= %d %q, want %d containing %q", w.Code, w.Body, tt.code, tt.contains)
			}
		})
	}
}

// failing dependencies: the health check must say "alive" without asking any of them.
func TestHealthzAsksNoDependency(t *testing.T) {
	boom := errors.New("down")
	i := &fakeIdP{err: boom}
	users := newUsers()
	users.bySubErr, users.byHandleErr, users.createErr = boom, boom, boom
	f := &fakeFrps{runErr: boom, countErr: boom}
	v := &fakeVerifier{idp: i, err: boom}
	h := NewHandler(testConfig("https://idp.example.com"), Deps{IdP: i, Verifier: v, Users: users, Frps: f, Log: slog.New(slog.DiscardHandler)})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 || w.Body.String() != "ok" {
		t.Errorf("= %d %q, want 200 ok", w.Code, w.Body)
	}
	if i.calls+v.calls != 0 || len(users.calls) != 0 || len(f.runAsked)+len(f.countAsked) != 0 {
		t.Error("the health check asked a dependency")
	}
}

func TestAPIMe(t *testing.T) {
	r := newServerRig(t)
	alice := r.idp.Issue("sub-alice", mockidp.IssueOpts{})
	vera := r.idp.Issue("sub-vera", mockidp.IssueOpts{})
	otherAudience := r.idp.Issue("sub-alice", mockidp.IssueOpts{Audience: []string{"https://other.example", mockidp.ClientID, r.idp.URL}})
	expired := r.idp.Issue("sub-alice", mockidp.IssueOpts{TTL: -time.Minute})
	invalid := `{"error":"your session is not valid; run: tunnel login"}`

	tests := []struct {
		name string
		hdr  http.Header
		code int
		body string
	}{
		{"no header", nil, 401, invalid},
		{"basic auth", http.Header{"Authorization": {"Basic YWxpY2U6cHc="}}, 401, invalid},
		{"empty bearer", http.Header{"Authorization": {"Bearer "}}, 401, invalid},
		{"scheme only", http.Header{"Authorization": {"Bearer"}}, 401, invalid},
		{"token without the scheme", http.Header{"Authorization": {alice}}, 401, invalid},
		{"good token, wrong scheme", http.Header{"Authorization": {"Basic " + alice}}, 401, invalid},
		{"good token, another scheme", http.Header{"Authorization": {"Token " + alice}}, 401, invalid},
		{"two headers", http.Header{"Authorization": {"Bearer " + alice, "Bearer " + alice}}, 401, invalid},
		{"garbage token", bearer("not-a-jwt"), 401, invalid},
		{"token addressed to another API", bearer(otherAudience), 401, invalid},
		{"expired token", bearer(expired), 401, invalid},
		{"viewer who may not publish", bearer(vera), 403, `{"error":"your account is not allowed to publish tunnels: ask an admin to add you to tunnels-creators"}`},
		{"creator", bearer(alice), 200, `{"sub":"sub-alice","username":"Alice","handle":"alice"}`},
		{"creator, scheme in capitals", http.Header{"Authorization": {"BEARER " + alice}}, 200, `{"sub":"sub-alice","username":"Alice","handle":"alice"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := r.do("GET", "/api/me", tt.hdr, "")
			if w.Code != tt.code || strings.TrimSpace(w.Body.String()) != tt.body {
				t.Errorf("= %d %q, want %d %s", w.Code, w.Body, tt.code, tt.body)
			}
			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q", ct)
			}
			if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", cc)
			}
		})
	}

	// Only the creator got a row, and it is the one /api/me reported.
	if u, ok := r.users.users["sub-alice"]; !ok || u.Handle != "alice" || len(r.users.users) != 1 {
		t.Errorf("rows = %v, want only alice", r.users.users)
	}
}

func TestAPIMeKeepsTheStoredHandle(t *testing.T) {
	r := newServerRig(t)
	r.users.users["sub-alice"] = store.User{Sub: "sub-alice", Handle: "ally"}
	w := r.do("GET", "/api/me", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"handle":"ally"`) {
		t.Errorf("= %d %q, want the stored handle", w.Code, w.Body)
	}
}

// A token can pass the local check (signature, audience, expiry) for a person the provider has since
// deleted or revoked; userinfo is what notices, and the person is told to log in again.
func TestAPIMeUnknownToTheProviderIs401(t *testing.T) {
	r := newServerRig(t)
	token := r.idp.Issue("sub-ghost", mockidp.IssueOpts{}) // the mock has no such user
	w := r.do("GET", "/api/me", bearer(token), "")
	if w.Code != 401 || !strings.Contains(w.Body.String(), "run: tunnel login") {
		t.Errorf("= %d %q, want 401 telling the person to log in again", w.Code, w.Body)
	}
	if len(r.users.users) != 0 {
		t.Errorf("rows = %v for an account the provider does not know", r.users.users)
	}
}

func TestAPIMeDependencyDownIs503(t *testing.T) {
	r := newServerRig(t)
	token := r.idp.Issue("sub-alice", mockidp.IssueOpts{})
	r.users.bySubErr = errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")
	w := r.do("GET", "/api/me", bearer(token), "")
	if w.Code != 503 || strings.TrimSpace(w.Body.String()) != `{"error":"login unavailable, try again"}` {
		t.Errorf("= %d %q, want 503 with the fixed sentence", w.Code, w.Body)
	}
	if !strings.Contains(r.logs.String(), "connection refused") {
		t.Errorf("the cause was not logged:\n%s", r.logs)
	}
	if strings.Contains(r.logs.String(), token) || strings.Contains(w.Body.String(), "5432") {
		t.Error("a token or an internal address leaked")
	}
}

func TestWellKnown(t *testing.T) {
	r := newServerRig(t)
	w := r.do("GET", "/.well-known/tunnels.json", nil, "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("= %d %s", w.Code, w.Header())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"issuer": r.idp.URL, "cli_client_id": "tunnels-cli", "api_resource": mockidp.APIResource,
		"service_host": "tunnels.layertwo.dev", "sites_domain": sitesDomain, "min_cli_version": "0.2.0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("document =\n%v\nwant\n%v", got, want)
	}
	// Nothing in it is a secret, and the endpoint needs no login.
	if strings.Contains(w.Body.String(), pluginSecret) {
		t.Error("the document contains the plugin secret")
	}
}

// The mux must not send a request that looks like the plugin anywhere else.
func TestPluginReachesTheHooks(t *testing.T) {
	r := newServerRig(t)
	body, _ := json.Marshal(plugin.Request{Version: plugin.APIVersion, Op: plugin.OpLogin, Content: loginContent(r.idp.Issue("sub-alice", mockidp.IssueOpts{}))})
	w := r.do("POST", "/plugin/"+pluginSecret, nil, string(body))
	var rep reply
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil || w.Code != 200 || rep.Reject || asMap(t, rep.Content)["user"] != "alice" {
		t.Errorf("= %d %q (%v), want Login accepted as alice through the real identity provider", w.Code, w.Body, err)
	}
	if u := r.users.users["sub-alice"]; u.Handle != "alice" {
		t.Errorf("rows = %v", r.users.users)
	}
}

// The limits and lists in the configuration are what the handlers enforce, not defaults of their own.
func TestHandlersUseTheConfiguration(t *testing.T) {
	r := newServerRig(t)
	r.users.users["sub-alice"] = store.User{Sub: "sub-alice", Handle: "alice"}
	post := func() reply {
		body, _ := json.Marshal(plugin.Request{Version: plugin.APIVersion, Op: plugin.OpNewProxy, Content: newProxyContent("alice", "alice.default", "alice")})
		w := r.do("POST", "/plugin/"+pluginSecret, nil, string(body))
		var rep reply
		if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil || w.Code != 200 {
			t.Fatalf("= %d %q (%v)", w.Code, w.Body, err)
		}
		return rep
	}

	r.frps.count = r.cfg.MaxTunnelsPerUser - 1
	rep := post()
	if got := asMap(t, rep.Content); rep.Reject || got["bandwidth_limit"] != r.cfg.BandwidthLimit || got["bandwidth_limit_mode"] != "server" {
		t.Errorf("one below the limit: %+v, want accepted at %s in server mode", rep, r.cfg.BandwidthLimit)
	}
	r.frps.count = r.cfg.MaxTunnelsPerUser
	if rep := post(); !rep.Reject || rep.RejectReason != "tunnel limit of 5 reached" {
		t.Errorf("at the limit: %+v, want the limit from the configuration", rep)
	}
}

func TestAPIMeAppliesTheReservedList(t *testing.T) {
	r := newServerRig(t)
	r.idp.AddUser(mockidp.User{Sub: "sub-admin", Username: "Admin", Groups: []string{creators}})
	w := r.do("GET", "/api/me", bearer(r.idp.Issue("sub-admin", mockidp.IssueOpts{})), "")
	if w.Code != 403 || !strings.Contains(w.Body.String(), "is reserved") {
		t.Errorf("= %d %q, want 403 saying the handle is reserved", w.Code, w.Body)
	}
	if len(r.users.users) != 0 {
		t.Errorf("rows = %v", r.users.users)
	}
}

// Postgres that stops answering must not hold the CLI's request for ever.
func TestAPIMeGivesTheStoreADeadline(t *testing.T) {
	r := newServerRig(t)
	r.do("GET", "/api/me", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), "")
	if !r.users.hasDeadline {
		t.Fatal("the store was asked without a deadline")
	}
	if left := time.Until(r.users.deadline); left <= 0 || left > defaultDecisionTimeout {
		t.Errorf("deadline in %v, want within %v", left, defaultDecisionTimeout)
	}
}

func postLogin(t *testing.T, r *serverRig, token string) reply {
	t.Helper()
	body, _ := json.Marshal(plugin.Request{Version: plugin.APIVersion, Op: plugin.OpLogin, Content: loginContent(token)})
	w := r.do("POST", "/plugin/"+pluginSecret, nil, string(body))
	var rep reply
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil || w.Code != 200 {
		t.Fatalf("= %d %q (%v)", w.Code, w.Body, err)
	}
	return rep
}

func TestSharesGet(t *testing.T) {
	r := newServerRig(t)
	r.shares.rows = []store.Share{
		{Tunnel: "", Kind: "user", Grantee: "bob"},
		{Tunnel: "blog", Kind: "group", Grantee: "family"},
	}
	w := r.do("GET", "/api/shares", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), "")
	if w.Code != 200 {
		t.Fatalf("= %d %q, want 200", w.Code, w.Body)
	}
	want := `{"shares":[{"tunnel":"","kind":"user","grantee":"bob"},{"tunnel":"blog","kind":"group","grantee":"family"}]}`
	if strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("= %s, want %s", w.Body, want)
	}
	if !reflect.DeepEqual(r.shares.getSubs, []string{"sub-alice"}) {
		t.Errorf("SharesByOwner asked for %v, want sub-alice only", r.shares.getSubs)
	}
}

func TestSharesPutValidates(t *testing.T) {
	tests := []struct {
		name, body string
		code       int
	}{
		{"kind admin", `{"tunnel":"blog","kind":"admin","grantee":"bob"}`, 400},
		{"tunnel Blog", `{"tunnel":"Blog","kind":"user","grantee":"bob"}`, 400},
		{"tunnel default", `{"tunnel":"default","kind":"user","grantee":"bob"}`, 400},
		{"empty grantee", `{"tunnel":"blog","kind":"user","grantee":""}`, 400},
		{"group grantee with a comma", `{"tunnel":"blog","kind":"group","grantee":"a,b"}`, 400},
		{"expires_at not a time", `{"tunnel":"blog","kind":"user","grantee":"bob","expires_at":"soon"}`, 400},
		{"good", `{"tunnel":"blog","kind":"user","grantee":"bob"}`, 204},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newServerRig(t)
			w := r.do("PUT", "/api/shares", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), tt.body)
			if w.Code != tt.code {
				t.Errorf("= %d %q, want %d", w.Code, w.Body, tt.code)
			}
			if tt.code == 204 {
				want := []shareWrite{{"sub-alice", store.Share{Tunnel: "blog", Kind: "user", Grantee: "bob"}}}
				if !reflect.DeepEqual(r.shares.puts, want) {
					t.Errorf("recorded %+v, want %+v", r.shares.puts, want)
				}
				return
			}
			if len(r.shares.puts) != 0 {
				t.Errorf("the store was called for bad input: %+v", r.shares.puts)
			}
		})
	}
}

// The wire takes an absolute RFC3339 end; a time in the past is no share at all.
func TestSharesPutAcceptsExpiry(t *testing.T) {
	r := newServerRig(t)
	expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	body := `{"tunnel":"blog","kind":"user","grantee":"bob","expires_at":"` + expires.Format(time.RFC3339) + `"}`
	w := r.do("PUT", "/api/shares", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), body)
	if w.Code != 204 {
		t.Fatalf("= %d %q, want 204", w.Code, w.Body)
	}
	if len(r.shares.puts) != 1 {
		t.Fatalf("recorded %+v, want one put", r.shares.puts)
	}
	if got := r.shares.puts[0].share; got.Tunnel != "blog" || got.Grantee != "bob" || !got.ExpiresAt.Equal(expires) {
		t.Errorf("recorded %+v, want the share ending %v", got, expires)
	}

	// A past end cannot grant anything, so it is refused before the store sees it.
	r2 := newServerRig(t)
	past := `{"tunnel":"blog","kind":"user","grantee":"bob","expires_at":"2020-01-01T00:00:00Z"}`
	w = r2.do("PUT", "/api/shares", bearer(r2.idp.Issue("sub-alice", mockidp.IssueOpts{})), past)
	if w.Code != 400 {
		t.Errorf("= %d %q, want 400 for a past expires_at", w.Code, w.Body)
	}
	if len(r2.shares.puts) != 0 {
		t.Errorf("the store was called for a past expires_at: %+v", r2.shares.puts)
	}
}

// The store deduplicates; a second identical PUT must still answer 204.
func TestSharesPutIsIdempotent(t *testing.T) {
	r := newServerRig(t)
	token := r.idp.Issue("sub-alice", mockidp.IssueOpts{})
	body := `{"tunnel":"blog","kind":"user","grantee":"bob"}`
	for i := range 2 {
		if w := r.do("PUT", "/api/shares", bearer(token), body); w.Code != 204 {
			t.Fatalf("put %d = %d %q, want 204", i, w.Code, w.Body)
		}
	}
}

func TestSharesDelete(t *testing.T) {
	r := newServerRig(t)
	w := r.do("DELETE", "/api/shares", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), `{"tunnel":"blog","kind":"group","grantee":"family"}`)
	if w.Code != 204 {
		t.Fatalf("= %d %q, want 204", w.Code, w.Body)
	}
	want := []shareWrite{{"sub-alice", store.Share{Tunnel: "blog", Kind: "group", Grantee: "family"}}}
	if !reflect.DeepEqual(r.shares.deletes, want) {
		t.Errorf("recorded %+v, want %+v", r.shares.deletes, want)
	}
}

// A delete always removes the grant, whatever end the body carries, even one already past.
func TestSharesDeleteIgnoresExpiry(t *testing.T) {
	r := newServerRig(t)
	body := `{"tunnel":"blog","kind":"user","grantee":"bob","expires_at":"2020-01-01T00:00:00Z"}`
	w := r.do("DELETE", "/api/shares", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), body)
	if w.Code != 204 {
		t.Fatalf("= %d %q, want 204 for a delete with a past expires_at", w.Code, w.Body)
	}
	want := []shareWrite{{"sub-alice", store.Share{Tunnel: "blog", Kind: "user", Grantee: "bob", ExpiresAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}}}
	if !reflect.DeepEqual(r.shares.deletes, want) {
		t.Errorf("recorded %+v, want %+v", r.shares.deletes, want)
	}
}

func TestSharesNeedsToken(t *testing.T) {
	r := newServerRig(t)
	body := `{"tunnel":"blog","kind":"user","grantee":"bob"}`
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		w := r.do(method, "/api/shares", nil, body)
		if w.Code != 401 || strings.TrimSpace(w.Body.String()) != `{"error":"your session is not valid; run: tunnel login"}` {
			t.Errorf("%s without a token = %d %q, want 401", method, w.Code, w.Body)
		}
	}
}

func TestSharesNotCreator(t *testing.T) {
	r := newServerRig(t)
	vera := bearer(r.idp.Issue("sub-vera", mockidp.IssueOpts{}))
	body := `{"tunnel":"blog","kind":"user","grantee":"bob"}`
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		w := r.do(method, "/api/shares", vera, body)
		if w.Code != 403 {
			t.Errorf("%s as a viewer = %d %q, want 403", method, w.Code, w.Body)
		}
	}
}

func TestSharesStoreError(t *testing.T) {
	r := newServerRig(t)
	r.shares.storeErr = errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")
	raw := r.idp.Issue("sub-alice", mockidp.IssueOpts{})
	body := `{"tunnel":"blog","kind":"user","grantee":"bob"}`
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		w := r.do(method, "/api/shares", bearer(raw), body)
		if w.Code != 503 || strings.Contains(w.Body.String(), "5432") {
			t.Errorf("%s = %d %q, want 503 without an internal address", method, w.Code, w.Body)
		}
	}
	if !strings.Contains(r.logs.String(), "connection refused") {
		t.Errorf("the cause was not logged:\n%s", r.logs)
	}
	if strings.Contains(r.logs.String(), raw) {
		t.Error("the token leaked into the log")
	}
}

// An owner with nothing shared must read an empty list, not null.
func TestSharesGetEmptyIsArray(t *testing.T) {
	r := newServerRig(t)
	w := r.do("GET", "/api/shares", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), "")
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"shares":[]}` {
		t.Errorf("= %d %s, want 200 {\"shares\":[]}", w.Code, w.Body)
	}
}

// A body over the cap must be refused before it is decoded into memory.
func TestSharesBodyTooLarge(t *testing.T) {
	r := newServerRig(t)
	body := `{"tunnel":"blog","kind":"user","grantee":"bob","pad":"` + strings.Repeat("x", maxBody) + `"}`
	w := r.do("PUT", "/api/shares", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), body)
	if w.Code != 400 {
		t.Errorf("= %d %q, want 400 for a body over 1 MiB", w.Code, w.Body)
	}
	if len(r.shares.puts) != 0 {
		t.Errorf("the store was called for an oversized body: %+v", r.shares.puts)
	}
}

// A second JSON value after the first is not the share the caller asked for; refuse it.
func TestSharesTrailingJSON(t *testing.T) {
	r := newServerRig(t)
	w := r.do("PUT", "/api/shares", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), `{"tunnel":"","kind":"user","grantee":"bob"}{}`)
	if w.Code != 400 {
		t.Errorf("= %d %q, want 400 for a body with trailing JSON", w.Code, w.Body)
	}
	if len(r.shares.puts) != 0 {
		t.Errorf("the store was called for a body with trailing JSON: %+v", r.shares.puts)
	}
}

// A broker that came up without a shares store must answer 503, not panic into a 500. DELETE takes
// the store method value too, so it has the same nil guard as PUT.
func TestSharesNilSharesIs503(t *testing.T) {
	r := newServerRig(t)
	h := NewHandler(r.cfg, Deps{IdP: r.client, Verifier: r.client, Users: r.users, Shares: nil, Frps: r.frps, Log: slog.New(slog.DiscardHandler)})
	token := r.idp.Issue("sub-alice", mockidp.IssueOpts{})
	for _, method := range []string{"PUT", "DELETE"} {
		req := httptest.NewRequest(method, "/api/shares", strings.NewReader(`{"tunnel":"blog","kind":"user","grantee":"bob"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "sharing is unavailable") {
			t.Errorf("%s = %d %q, want 503 saying sharing is unavailable", method, w.Code, w.Body)
		}
	}
}

// The GET side has its nil check too, after the account is resolved, so a missing store is a 503
// there as well rather than a panic.
func TestSharesGetNilSharesIs503(t *testing.T) {
	r := newServerRig(t)
	h := NewHandler(r.cfg, Deps{IdP: r.client, Verifier: r.client, Users: r.users, Shares: nil, Frps: r.frps, Log: slog.New(slog.DiscardHandler)})
	req := httptest.NewRequest("GET", "/api/shares", nil)
	req.Header.Set("Authorization", "Bearer "+r.idp.Issue("sub-alice", mockidp.IssueOpts{}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("= %d %q, want 503", w.Code, w.Body)
	}
}

// frps checks the audience too, but only if it was configured to; the broker is the first layer.
func TestLoginRefusesATokenIssuedForAnotherAPI(t *testing.T) {
	r := newServerRig(t)
	other := r.idp.Issue("sub-alice", mockidp.IssueOpts{Audience: []string{"https://other-app.example", mockidp.ClientID, r.idp.URL}})
	rep := postLogin(t, r, other)
	if !rep.Reject || rep.RejectReason != "your session is not valid; run: tunnel login" {
		t.Errorf("Login with a token issued for another API: %+v", rep)
	}
	if len(r.users.users) != 0 {
		t.Errorf("a row was created for it: %v", r.users.users)
	}
}

// frps calls the plugin before it checks anything, so anybody who can open its port can send junk.
// A token that does not verify locally costs no request to the identity provider. (A token with a
// key id nobody has seen does: go-oidc looks for new keys. A rate limit in front of the broker is
// what bounds that.)
func TestLoginDoesNotAskTheIdPAboutJunk(t *testing.T) {
	r := newServerRig(t)
	if rep := postLogin(t, r, r.idp.Issue("sub-alice", mockidp.IssueOpts{})); rep.Reject { // loads the keys
		t.Fatalf("a good login was refused: %+v", rep)
	}
	before := len(r.idp.UserAgents())
	expired := r.idp.Issue("sub-alice", mockidp.IssueOpts{TTL: -time.Minute})
	otherAudience := r.idp.Issue("sub-alice", mockidp.IssueOpts{Audience: []string{"https://other-app.example", mockidp.ClientID, r.idp.URL}})
	for i, token := range []string{"junk-0", "a.b.c", "eyJ.e30.c2ln", expired, otherAudience} {
		if rep := postLogin(t, r, token); !rep.Reject {
			t.Errorf("token %d accepted: %+v", i, rep)
		}
	}
	if n := len(r.idp.UserAgents()) - before; n != 0 {
		t.Errorf("%d requests reached the identity provider for tokens that do not verify, want 0", n)
	}
}
