package broker

import (
	"bytes"
	"context"
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
	h     http.Handler
	idp   *mockidp.Server
	users *fakeUsers
	frps  *fakeFrps
	cfg   Config
	logs  *bytes.Buffer
}

func newServerRig(t *testing.T) *serverRig {
	t.Helper()
	m := mockidp.New(t)
	m.AddUser(mockidp.User{Sub: "sub-alice", Username: "Alice", Groups: []string{creators, "tunnels-viewers"}})
	m.AddUser(mockidp.User{Sub: "sub-vera", Username: "vera", Groups: []string{"tunnels-viewers"}})
	client, err := idp.New(t.Context(), m.URL, mockidp.APIResource, "tunnels-test/1")
	if err != nil {
		t.Fatal(err)
	}
	r := &serverRig{idp: m, users: newUsers(), frps: &fakeFrps{online: map[string]string{}}, cfg: testConfig(m.URL), logs: &bytes.Buffer{}}
	r.h = NewHandler(r.cfg, Deps{
		IdP: client, Verifier: client, Users: r.users, Frps: r.frps,
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
type countingVerifier struct{ calls int }

func (v *countingVerifier) VerifyAccessToken(context.Context, string) (string, error) {
	v.calls++
	return "", errors.New("down")
}

func TestHealthzAsksNoDependency(t *testing.T) {
	boom := errors.New("down")
	i := &fakeIdP{err: boom}
	users := newUsers()
	users.bySubErr, users.byHandleErr, users.createErr = boom, boom, boom
	f := &fakeFrps{runErr: boom, countErr: boom}
	v := &countingVerifier{}
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
	invalid := `{"error":"invalid token"}`

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
	for _, secret := range []string{pluginSecret} {
		if strings.Contains(w.Body.String(), secret) {
			t.Errorf("the document contains %q", secret)
		}
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
