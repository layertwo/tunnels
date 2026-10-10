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

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	plugin "github.com/fatedier/frp/pkg/plugin/server"

	"github.com/layertwo/tunnels/internal/idp"
	"github.com/layertwo/tunnels/internal/store"
)

const (
	pluginSecret = "s3cret-0123456789abcdef"
	secretToken  = "eyJ.the-access-token.sig" // what a client sends as privilege_key
)

// fakeFrps answers the dashboard questions from memory and remembers what it was asked.
type fakeFrps struct {
	online     map[string]string // run ID -> user
	runErr     error
	count      int
	countErr   error
	runAsked   []string
	countAsked []string
}

func (f *fakeFrps) OnlineRunIDUser(_ context.Context, runID string) (string, bool, error) {
	f.runAsked = append(f.runAsked, runID)
	if f.runErr != nil {
		return "", false, f.runErr
	}
	user, ok := f.online[runID]
	return user, ok, nil
}

func (f *fakeFrps) OnlineProxyCount(_ context.Context, user string) (int, error) {
	f.countAsked = append(f.countAsked, user)
	return f.count, f.countErr
}

// rig is a Hooks wired to fakes, with alice (sub-alice) already registered.
type rig struct {
	hooks *Hooks
	idp   *fakeIdP
	users *fakeUsers
	frps  *fakeFrps
	logs  *bytes.Buffer
}

func newRig() *rig {
	users := newUsers(store.User{Sub: "sub-alice", Handle: "alice"})
	i := &fakeIdP{id: identity("sub-alice", "Alice", creators)}
	f := &fakeFrps{online: map[string]string{}}
	logs := &bytes.Buffer{}
	return &rig{
		hooks: &Hooks{
			Resolver:          Resolver{IdP: i, Users: users, CreatorsGroup: creators, Reserved: []string{"admin"}},
			Frps:              f,
			Secret:            pluginSecret,
			MaxTunnelsPerUser: 5,
			BandwidthLimit:    "10MB",
			Log:               slog.New(slog.NewJSONHandler(logs, nil)),
		},
		idp: i, users: users, frps: f, logs: logs,
	}
}

// reply is what frps reads back.
type reply struct {
	Reject       bool            `json:"reject"`
	RejectReason string          `json:"reject_reason"`
	Unchange     bool            `json:"unchange"`
	Content      json.RawMessage `json:"content"`
}

// do sends one request to the hooks.
func (r *rig) do(method, target string, body []byte) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.hooks.ServeHTTP(w, httptest.NewRequest(method, target, bytes.NewReader(body)))
	return w
}

// call sends one hook request the way frps does and decodes the answer.
func (r *rig) call(t *testing.T, op string, content any) reply {
	t.Helper()
	body, err := json.Marshal(plugin.Request{Version: plugin.APIVersion, Op: op, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	w := r.do(http.MethodPost, "/plugin/"+pluginSecret+"?version=0.1.0&op="+op, body)
	if w.Code != http.StatusOK {
		t.Fatalf("%s answered HTTP %d: %s; every decision must be 200", op, w.Code, w.Body)
	}
	var rep reply
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("%s answered %q: %v", op, w.Body, err)
	}
	return rep
}

// asMap decodes a JSON object so that a dropped or an added field shows up in a comparison.
func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, ok := v.(json.RawMessage)
	if !ok {
		var err error
		if raw, err = json.Marshal(v); err != nil {
			t.Fatal(err)
		}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not a JSON object: %q: %v", raw, err)
	}
	return m
}

func loginContent(token string) plugin.LoginContent {
	return plugin.LoginContent{
		Login: msg.Login{
			Version: "0.71.0", Hostname: "laptop", Os: "darwin", Arch: "arm64", User: "alice",
			PrivilegeKey: token, Timestamp: 1791565403, ClientID: "laptop-1",
			Metas: map[string]string{"k": "v"}, PoolCount: 1,
		},
		ClientAddress: "203.0.113.7:51234",
	}
}

func TestLoginRewritesUserAndKeepsEverythingElse(t *testing.T) {
	r := newRig()
	in := loginContent(secretToken)
	in.User = "someone-else"
	rep := r.call(t, plugin.OpLogin, in)

	if rep.Reject || rep.Unchange {
		t.Fatalf("reply = %+v, want accepted with changed content", rep)
	}
	want := asMap(t, in)
	want["user"] = "alice"
	if got := asMap(t, rep.Content); !reflect.DeepEqual(got, want) {
		t.Errorf("content =\n%v\nwant the request with only user changed to alice:\n%v", got, want)
	}
	if r.idp.token != secretToken {
		t.Errorf("the identity provider was asked about %q, want the privilege_key", r.idp.token)
	}
}

// What the client says about itself never decides who it is.
func TestLoginClaimedUserIsIgnored(t *testing.T) {
	for _, claimed := range []string{"victim", "bob", "", "alice", "ALICE", "alice\n", strings.Repeat("a", 1000)} {
		r := newRig()
		in := loginContent(secretToken)
		in.User = claimed
		rep := r.call(t, plugin.OpLogin, in)
		if rep.Reject || asMap(t, rep.Content)["user"] != "alice" {
			t.Errorf("claimed user %.20q: reply = %+v, want accepted as alice", claimed, rep)
		}
	}
}

func TestLoginRefusals(t *testing.T) {
	boom := errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")
	tests := []struct {
		name   string
		token  string
		setup  func(r *rig)
		reason string // the reject_reason, exactly
	}{
		{"missing token", "", nil, "missing token"},
		{"not a creator", secretToken, func(r *rig) { r.idp.id = identity("sub-alice", "Alice", "tunnels-viewers") },
			"your account is not allowed to publish tunnels: ask an admin to add you to tunnels-creators"},
		{"disabled", secretToken, func(r *rig) {
			r.users.users["sub-alice"] = store.User{Sub: "sub-alice", Handle: "alice", Disabled: true}
		},
			"your account is disabled: ask an admin"},
		{"bad username", secretToken, func(r *rig) { r.idp.id = identity("sub-new", "alice_b", creators) },
			`username "alice_b" cannot be a tunnel handle: use 2 to 20 letters and digits; ask an admin to change your username`},
		{"handle taken", secretToken, func(r *rig) { r.idp.id = identity("sub-new", "ALICE", creators) },
			`the handle "alice" belongs to another account; ask an admin to change your username`},
		{"token not valid", secretToken, func(r *rig) { r.idp.err = idp.ErrInvalidToken }, "your session is not valid; run: tunnel login"},
		{"identity provider down", secretToken, func(r *rig) { r.idp.err = boom }, "login unavailable, try again"},
		{"store down", secretToken, func(r *rig) { r.users.bySubErr = boom }, "login unavailable, try again"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig()
			if tt.setup != nil {
				tt.setup(r)
			}
			in := loginContent(tt.token)
			in.RunID = "run-1" // so that asking the dashboard before the refusal would show
			rep := r.call(t, plugin.OpLogin, in)
			if !rep.Reject || rep.RejectReason != tt.reason {
				t.Errorf("reply = %+v, want reject with %q", rep, tt.reason)
			}
			if len(r.users.users) != 1 {
				t.Errorf("rows after a refused login: %v, want only alice", r.users.users)
			}
			if tt.token == "" && r.idp.calls != 0 {
				t.Error("the identity provider was asked about an empty token")
			}
			if len(r.frps.runAsked)+len(r.frps.countAsked) != 0 {
				t.Errorf("the dashboard was asked (%q, %q) about a refused login", r.frps.runAsked, r.frps.countAsked)
			}
		})
	}
}

func TestLoginRunID(t *testing.T) {
	tests := []struct {
		name       string
		runID      string
		online     map[string]string
		runErr     error
		reject     string // "" when accepted
		wantAsked  bool
		wantReason string
	}{
		{name: "empty run id", runID: "", wantAsked: false},
		{name: "unknown run id", runID: "run-1", online: map[string]string{}, wantAsked: true},
		{name: "online under the same handle", runID: "run-1", online: map[string]string{"run-1": "alice"}, wantAsked: true},
		{name: "online under another handle", runID: "run-1", online: map[string]string{"run-1": "bob"}, wantAsked: true,
			reject: "run id belongs to another session"},
		{name: "online under a handle that only looks like ours", runID: "run-1", online: map[string]string{"run-1": "Alice"}, wantAsked: true,
			reject: "run id belongs to another session"},
		{name: "dashboard error", runID: "run-1", runErr: errors.New("boom"), wantAsked: true,
			reject: "login unavailable, try again"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig()
			r.frps.online, r.frps.runErr = tt.online, tt.runErr
			in := loginContent(secretToken)
			in.RunID = tt.runID
			rep := r.call(t, plugin.OpLogin, in)

			if tt.reject == "" && (rep.Reject || asMap(t, rep.Content)["user"] != "alice") {
				t.Errorf("reply = %+v, want accepted as alice", rep)
			}
			if tt.reject != "" && (!rep.Reject || rep.RejectReason != tt.reject) {
				t.Errorf("reply = %+v, want reject with %q", rep, tt.reject)
			}
			if asked := len(r.frps.runAsked) > 0; asked != tt.wantAsked {
				t.Errorf("dashboard asked = %v (%q), want %v", asked, r.frps.runAsked, tt.wantAsked)
			}
			if tt.wantAsked && r.frps.runAsked[0] != tt.runID {
				t.Errorf("dashboard asked about %q, want %q", r.frps.runAsked[0], tt.runID)
			}
		})
	}
}

func newProxyContent(handle, name, sub string) plugin.NewProxyContent {
	return plugin.NewProxyContent{
		User: plugin.UserInfo{User: handle, RunID: "run-1", Metas: map[string]string{"m": "1"}},
		NewProxy: msg.NewProxy{
			ProxyName: name, ProxyType: "http", SubDomain: sub, UseEncryption: true, UseCompression: true,
			BandwidthLimit: "1GB", BandwidthLimitMode: "client", HostHeaderRewrite: "localhost",
			Headers: map[string]string{"X-From": "frpc"}, Metas: map[string]string{"k": "v"},
		},
	}
}

func TestNewProxy(t *testing.T) {
	type mod func(*plugin.NewProxyContent)
	typ := func(s string) mod { return func(c *plugin.NewProxyContent) { c.ProxyType = s } }
	name42 := strings.Repeat("b", 42)
	tests := []struct {
		name        string
		handle      string
		proxy, sub  string
		mod         mod
		count       int
		countErr    error
		reason      string // "" when accepted
		wantCounted bool
	}{
		{name: "default tunnel", handle: "alice", proxy: "alice.default", sub: "alice", count: 0, wantCounted: true},
		{name: "named tunnel", handle: "alice", proxy: "alice.blog", sub: "alice-blog", count: 1, wantCounted: true},
		{name: "name with inner dashes", handle: "alice", proxy: "alice.a-b-c", sub: "alice-a-b-c", wantCounted: true},
		{name: "longest name", handle: "alice", proxy: "alice." + name42, sub: "alice-" + name42, wantCounted: true},
		{name: "one below the limit", handle: "alice", proxy: "alice.default", sub: "alice", count: 4, wantCounted: true},

		{name: "another user's name", handle: "alice", proxy: "bob.default", sub: "alice", reason: "name bob.default is not yours"},
		{name: "another user's label", handle: "alice", proxy: "alice.default", sub: "bob", reason: "name alice.default is not yours"},
		{name: "label of another user's tunnel", handle: "alice", proxy: "alice.default", sub: "bob-blog", reason: "name alice.default is not yours"},
		{name: "capital in the handle", handle: "alice", proxy: "Alice.default", sub: "alice", reason: "name Alice.default is not yours"},
		{name: "capital in the name", handle: "alice", proxy: "alice.Default", sub: "alice", reason: "name alice.Default is not yours"},
		{name: "capital in the label", handle: "alice", proxy: "alice.default", sub: "ALICE", reason: "name alice.default is not yours"},
		{name: "default with a name label", handle: "alice", proxy: "alice.default", sub: "alice-default", reason: "name alice.default is not yours"},
		{name: "named tunnel with the default label", handle: "alice", proxy: "alice.blog", sub: "alice", reason: "name alice.blog is not yours"},
		{name: "name that is not a name", handle: "alice", proxy: "alice.a_b", sub: "alice-a_b", reason: "name alice.a_b is not yours"},
		{name: "empty name", handle: "alice", proxy: "alice.", sub: "alice", reason: "name alice. is not yours"},
		{name: "no name at all", handle: "alice", proxy: "alice", sub: "alice", reason: "name alice is not yours"},
		{name: "tunnel name without the handle", handle: "alice", proxy: "blog", sub: "alice-blog", reason: "name blog is not yours"},
		{name: "default without the handle", handle: "alice", proxy: "default", sub: "alice", reason: "name default is not yours"},
		{name: "dash instead of the dot", handle: "alice", proxy: "alice-blog", sub: "alice-blog", reason: "name alice-blog is not yours"},
		{name: "empty proxy name", handle: "alice", proxy: "", sub: "alice", reason: "name  is not yours"},
		{name: "empty label", handle: "alice", proxy: "alice.default", sub: "", reason: "name alice.default is not yours"},
		{name: "dot in the name", handle: "alice", proxy: "alice.blog.x", sub: "alice-blog.x", reason: "name alice.blog.x is not yours"},
		{name: "dash at the start of the name", handle: "alice", proxy: "alice.-x", sub: "alice--x", reason: "name alice.-x is not yours"},
		{name: "dash at the end of the name", handle: "alice", proxy: "alice.x-", sub: "alice-x-", reason: "name alice.x- is not yours"},
		{name: "name one too long", handle: "alice", proxy: "alice." + name42 + "b", sub: "alice-" + name42 + "b", reason: "name alice." + name42 + "b is not yours"},
		{name: "label with a space", handle: "alice", proxy: "alice.default", sub: "alice ", reason: "name alice.default is not yours"},
		{name: "label with a trailing dot", handle: "alice", proxy: "alice.default", sub: "alice.", reason: "name alice.default is not yours"},
		{name: "label with a port", handle: "alice", proxy: "alice.default", sub: "alice:443", reason: "name alice.default is not yours"},
		{name: "no handle in the login", handle: "", proxy: ".default", sub: "", reason: "name .default is not yours"},
		{name: "handle with a capital", handle: "Bob", proxy: "Bob.default", sub: "Bob", reason: "name Bob.default is not yours"},
		{name: "handle with a dash", handle: "a-b", proxy: "a-b.c", sub: "a-b-c", reason: "name a-b.c is not yours"},
		{name: "handle too short", handle: "a", proxy: "a.default", sub: "a", reason: "name a.default is not yours"},

		{name: "tcp", handle: "alice", proxy: "alice.default", sub: "alice", mod: typ("tcp"), reason: "only plain http tunnels are allowed"},
		{name: "https", handle: "alice", proxy: "alice.default", sub: "alice", mod: typ("https"), reason: "only plain http tunnels are allowed"},
		{name: "tcpmux", handle: "alice", proxy: "alice.default", sub: "alice", mod: typ("tcpmux"), reason: "only plain http tunnels are allowed"},
		{name: "udp", handle: "alice", proxy: "alice.default", sub: "alice", mod: typ("udp"), reason: "only plain http tunnels are allowed"},
		{name: "stcp", handle: "alice", proxy: "alice.default", sub: "alice", mod: typ("stcp"), reason: "only plain http tunnels are allowed"},
		{name: "sudp", handle: "alice", proxy: "alice.default", sub: "alice", mod: typ("sudp"), reason: "only plain http tunnels are allowed"},
		{name: "xtcp", handle: "alice", proxy: "alice.default", sub: "alice", mod: typ("xtcp"), reason: "only plain http tunnels are allowed"},
		{name: "no type", handle: "alice", proxy: "alice.default", sub: "alice", mod: typ(""), reason: "only plain http tunnels are allowed"},
		{name: "type in capitals", handle: "alice", proxy: "alice.default", sub: "alice", mod: typ("HTTP"), reason: "only plain http tunnels are allowed"},
		{name: "custom domain", handle: "alice", proxy: "alice.default", sub: "alice", reason: "only plain http tunnels are allowed",
			mod: func(c *plugin.NewProxyContent) { c.CustomDomains = []string{"victim.example.com"} }},
		{name: "empty custom domain", handle: "alice", proxy: "alice.default", sub: "alice", reason: "only plain http tunnels are allowed",
			mod: func(c *plugin.NewProxyContent) { c.CustomDomains = []string{""} }},
		{name: "locations", handle: "alice", proxy: "alice.default", sub: "alice", reason: "only plain http tunnels are allowed",
			mod: func(c *plugin.NewProxyContent) { c.Locations = []string{"/admin"} }},

		{name: "at the limit", handle: "alice", proxy: "alice.default", sub: "alice", count: 5, reason: "tunnel limit of 5 reached", wantCounted: true},
		{name: "over the limit", handle: "alice", proxy: "alice.default", sub: "alice", count: 9, reason: "tunnel limit of 5 reached", wantCounted: true},
		{name: "dashboard error", handle: "alice", proxy: "alice.default", sub: "alice", countErr: errors.New("boom"),
			reason: "cannot verify your tunnels right now, try again", wantCounted: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig()
			r.frps.count, r.frps.countErr = tt.count, tt.countErr
			in := newProxyContent(tt.handle, tt.proxy, tt.sub)
			if tt.mod != nil {
				tt.mod(&in)
			}
			rep := r.call(t, plugin.OpNewProxy, in)

			if tt.reason != "" {
				if !rep.Reject || rep.RejectReason != tt.reason {
					t.Errorf("reply = %+v, want reject with %q", rep, tt.reason)
				}
			} else {
				if rep.Reject || rep.Unchange {
					t.Fatalf("reply = %+v, want accepted with changed content", rep)
				}
				// The whole request comes back; only the bandwidth limit is ours.
				want := asMap(t, in)
				want["bandwidth_limit"], want["bandwidth_limit_mode"] = "10MB", "server"
				if got := asMap(t, rep.Content); !reflect.DeepEqual(got, want) {
					t.Errorf("content =\n%v\nwant the request with the bandwidth limit set:\n%v", got, want)
				}
			}
			counted := len(r.frps.countAsked) > 0
			if counted != tt.wantCounted {
				t.Errorf("dashboard asked = %v, want %v (cheap checks come first)", counted, tt.wantCounted)
			}
			if counted && r.frps.countAsked[0] != tt.handle {
				t.Errorf("counted tunnels of %q, want %q", r.frps.countAsked[0], tt.handle)
			}
		})
	}
}

// The limit is the configured one and a limit of zero allows nothing.
func TestNewProxyLimitFollowsTheConfiguration(t *testing.T) {
	for _, tt := range []struct {
		max, count int
		accepted   bool
	}{{1, 0, true}, {1, 1, false}, {0, 0, false}, {-1, 0, false}, {20, 19, true}, {20, 20, false}} {
		r := newRig()
		r.hooks.MaxTunnelsPerUser, r.frps.count = tt.max, tt.count
		rep := r.call(t, plugin.OpNewProxy, newProxyContent("alice", "alice.default", "alice"))
		if rep.Reject == tt.accepted {
			t.Errorf("max %d, online %d: reply = %+v, want accepted = %v", tt.max, tt.count, rep, tt.accepted)
		}
	}
}

func TestCloseProxy(t *testing.T) {
	r := newRig()
	rep := r.call(t, plugin.OpCloseProxy, plugin.CloseProxyContent{
		User:       plugin.UserInfo{User: "alice", RunID: "run-1"},
		CloseProxy: msg.CloseProxy{ProxyName: "alice.default"},
	})
	if rep.Reject || !rep.Unchange {
		t.Errorf("reply = %+v, want unchanged and not rejected", rep)
	}
	if len(r.frps.runAsked)+len(r.frps.countAsked) != 0 || r.idp.calls != 0 {
		t.Error("closing a proxy asked a dependency something")
	}
	line := lastLog(t, r.logs)
	if line["op"] != "CloseProxy" || line["handle"] != "alice" || line["proxy"] != "alice.default" {
		t.Errorf("log = %v, want op, handle and proxy", line)
	}
}

func TestSecret(t *testing.T) {
	good := func() []byte {
		b, _ := json.Marshal(plugin.Request{Version: plugin.APIVersion, Op: plugin.OpLogin, Content: loginContent(secretToken)})
		return b
	}()
	targets := []string{
		"/plugin/wrong", "/plugin/", "/plugin", "/plugin//", "/",
		"/plugin/" + pluginSecret + "/", "/plugin/" + pluginSecret + "x", "/plugin/" + pluginSecret + "/extra",
		"/plugin/" + pluginSecret[:len(pluginSecret)-1], "/plugin/" + strings.ToUpper(pluginSecret),
		"/" + pluginSecret, "/plugin/wrong?secret=" + pluginSecret, "/plugin/%2e%2e/" + pluginSecret,
	}
	var first string
	for _, target := range targets {
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			r := newRig()
			w := r.do(method, target, good)
			if w.Code != http.StatusNotFound {
				t.Errorf("%s %s = %d, want 404", method, target, w.Code)
			}
			if strings.Contains(w.Body.String(), pluginSecret) || w.Header().Get("Content-Type") == "application/json" {
				t.Errorf("%s %s leaked: %q (%s)", method, target, w.Body, w.Header().Get("Content-Type"))
			}
			if first == "" {
				first = w.Body.String()
			} else if w.Body.String() != first {
				t.Errorf("%s %s answered %q, others %q: the body tells wrong secrets apart", method, target, w.Body, first)
			}
			if r.idp.calls != 0 {
				t.Errorf("%s %s reached the identity provider", method, target)
			}
		}
	}

	// A hook that was never given a secret refuses everything, including the empty secret.
	r := newRig()
	r.hooks.Secret = ""
	for _, target := range []string{"/plugin/", "/plugin", "/plugin/" + pluginSecret} {
		if w := r.do(http.MethodPost, target, good); w.Code != http.StatusNotFound {
			t.Errorf("no secret configured: POST %s = %d, want 404", target, w.Code)
		}
	}

	// And the right secret gets through.
	r = newRig()
	if w := r.do(http.MethodPost, "/plugin/"+pluginSecret, good); w.Code != http.StatusOK {
		t.Errorf("right secret = %d, want 200", w.Code)
	}
}

func TestMalformedRequests(t *testing.T) {
	target := "/plugin/" + pluginSecret
	valid := `{"version":"0.1.0","op":"Login","content":{"privilege_key":"tok"}}`
	tests := []struct {
		name   string
		method string
		body   string
	}{
		{"get", http.MethodGet, valid},
		{"put", http.MethodPut, valid},
		{"delete", http.MethodDelete, ""},
		{"empty body", http.MethodPost, ""},
		{"not json", http.MethodPost, "<html>"},
		{"json array", http.MethodPost, "[]"},
		{"truncated", http.MethodPost, valid[:len(valid)-6]},
		{"no op", http.MethodPost, `{"content":{"privilege_key":"tok"}}`},
		{"unknown op", http.MethodPost, `{"op":"Ping","content":{}}`},
		{"op in the wrong case", http.MethodPost, `{"op":"login","content":{"privilege_key":"tok"}}`},
		{"login without content", http.MethodPost, `{"op":"Login"}`},
		{"login with a string for content", http.MethodPost, `{"op":"Login","content":"tok"}`},
		{"login with an array for content", http.MethodPost, `{"op":"Login","content":[]}`},
		{"new proxy with a number for content", http.MethodPost, `{"op":"NewProxy","content":1}`},
		{"close proxy without content", http.MethodPost, `{"op":"CloseProxy"}`},
		{"over a megabyte", http.MethodPost, `{"op":"Login","content":{"privilege_key":"` + strings.Repeat("a", 2<<20) + `"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig()
			w := r.do(tt.method, target, []byte(tt.body))
			if w.Code != http.StatusBadRequest {
				t.Errorf("= %d %q, want 400", w.Code, w.Body)
			}
			if r.idp.calls != 0 || len(r.users.calls) != 0 {
				t.Error("a malformed request reached a dependency")
			}
		})
	}
}

// lastLog is the last JSON line the hooks logged.
func lastLog(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
		t.Fatalf("no log line in %q: %v", buf, err)
	}
	return m
}

func TestLogsRecordTheDecisionAndNeverTheToken(t *testing.T) {
	boom := errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")
	tests := []struct {
		name  string
		setup func(r *rig)
		call  func(t *testing.T, r *rig)
		want  map[string]any
	}{
		{"login accepted", nil,
			func(t *testing.T, r *rig) { r.call(t, plugin.OpLogin, loginContent(secretToken)) },
			map[string]any{"op": "Login", "handle": "alice", "sub": "sub-alice", "result": "accepted"}},
		{"login rejected as not a creator", func(r *rig) { r.idp.id = identity("sub-alice", "Alice") },
			func(t *testing.T, r *rig) { r.call(t, plugin.OpLogin, loginContent(secretToken)) },
			map[string]any{"op": "Login", "result": "rejected", "reason": "your account is not allowed to publish tunnels: ask an admin to add you to tunnels-creators", "err": nil}},
		{"login rejected as a foreign run id", func(r *rig) { r.frps.online["run-9"] = "bob" },
			func(t *testing.T, r *rig) {
				in := loginContent(secretToken)
				in.RunID = "run-9"
				r.call(t, plugin.OpLogin, in)
			},
			map[string]any{"op": "Login", "handle": "alice", "sub": "sub-alice", "result": "rejected", "reason": "run id belongs to another session"}},
		{"login with the identity provider down", func(r *rig) { r.idp.err = boom },
			func(t *testing.T, r *rig) { r.call(t, plugin.OpLogin, loginContent(secretToken)) },
			map[string]any{"op": "Login", "result": "rejected", "reason": "login unavailable, try again", "err": boom.Error()}},
		{"login with an invalid token", func(r *rig) { r.idp.err = idp.ErrInvalidToken },
			func(t *testing.T, r *rig) { r.call(t, plugin.OpLogin, loginContent(secretToken)) },
			map[string]any{"op": "Login", "result": "rejected", "reason": "your session is not valid; run: tunnel login", "err": nil}},
		{"new proxy accepted", nil,
			func(t *testing.T, r *rig) {
				r.call(t, plugin.OpNewProxy, newProxyContent("alice", "alice.blog", "alice-blog"))
			},
			map[string]any{"op": "NewProxy", "handle": "alice", "proxy": "alice.blog", "result": "accepted"}},
		{"new proxy rejected", nil,
			func(t *testing.T, r *rig) {
				r.call(t, plugin.OpNewProxy, newProxyContent("alice", "bob.default", "bob"))
			},
			map[string]any{"op": "NewProxy", "handle": "alice", "proxy": "bob.default", "result": "rejected", "reason": "name bob.default is not yours"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig()
			if tt.setup != nil {
				tt.setup(r)
			}
			tt.call(t, r)

			line := lastLog(t, r.logs)
			for k, want := range tt.want {
				if _, present := line[k]; want == nil && present {
					t.Errorf("log has %q = %v, want it absent (line %v)", k, line[k], line)
				} else if want != nil && line[k] != want {
					t.Errorf("log[%q] = %v, want %v (line %v)", k, line[k], want, line)
				}
			}
			for _, secret := range []string{secretToken, "the-access-token", pluginSecret} {
				if strings.Contains(r.logs.String(), secret) {
					t.Errorf("the log contains %q:\n%s", secret, r.logs)
				}
			}
		})
	}
}

// slowIdP and slowFrps hang until the context says stop.
type slowIdP struct{}

func (slowIdP) UserInfo(ctx context.Context, _ string) (idp.Identity, error) {
	<-ctx.Done()
	return idp.Identity{}, ctx.Err()
}

type slowFrps struct{ fakeFrps }

func (*slowFrps) OnlineProxyCount(ctx context.Context, _ string) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

// A client gives up on its Login after 10 s with a bare i/o timeout. Within the deadline it gets a reason.
func TestADependencyThatHangsIsRefusedWithinTheDeadline(t *testing.T) {
	r := newRig()
	r.hooks.Timeout = 50 * time.Millisecond
	r.hooks.Resolver.IdP = slowIdP{}
	start := time.Now()
	rep := r.call(t, plugin.OpLogin, loginContent(secretToken))
	if !rep.Reject || rep.RejectReason != "login unavailable, try again" {
		t.Errorf("Login with a hanging identity provider: %+v", rep)
	}

	r = newRig()
	r.hooks.Timeout = 50 * time.Millisecond
	r.hooks.Frps = &slowFrps{}
	rep = r.call(t, plugin.OpNewProxy, newProxyContent("alice", "alice.default", "alice"))
	if !rep.Reject || rep.RejectReason != "cannot verify your tunnels right now, try again" {
		t.Errorf("NewProxy with a hanging dashboard: %+v", rep)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("both took %v for a 50 ms deadline", took)
	}
}

func TestDefaultDeadlineIsBelowTheClientsLoginTimeout(t *testing.T) {
	if got := (&Hooks{}).timeout(); got <= 0 || got >= 10*time.Second {
		t.Errorf("default decision timeout = %v, want under the 10 s a frp client waits for its Login answer", got)
	}
}

// frps calls the hooks through its own plugin client. Driving that client against the handler checks
// the wire format from the consumer's side: how it encodes the request and decodes the answer.
func TestFrpsPluginClientUnderstandsTheAnswers(t *testing.T) {
	r := newRig()
	srv := httptest.NewServer(r.hooks)
	defer srv.Close()
	frps := plugin.NewHTTPPluginOptions(v1.HTTPPluginOptions{
		Name: "tunnels", Addr: srv.URL, Path: "/plugin/" + pluginSecret,
		Ops: []string{plugin.OpLogin, plugin.OpNewProxy, plugin.OpCloseProxy},
	})

	in := loginContent(secretToken)
	in.User = "someone-else"
	res, content, err := frps.Handle(t.Context(), plugin.OpLogin, in)
	if err != nil || res.Reject || res.Unchange {
		t.Fatalf("Login = %+v, %v, want accepted with changed content", res, err)
	}
	got, ok := content.(*plugin.LoginContent)
	if !ok {
		t.Fatalf("Login content is a %T, frps needs a *plugin.LoginContent", content)
	}
	want := in
	want.User = "alice"
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("Login content =\n%+v\nwant\n%+v", *got, want)
	}

	res, content, err = frps.Handle(t.Context(), plugin.OpNewProxy, newProxyContent("alice", "alice.blog", "alice-blog"))
	if err != nil || res.Reject || res.Unchange {
		t.Fatalf("NewProxy = %+v, %v, want accepted with changed content", res, err)
	}
	if np, ok := content.(*plugin.NewProxyContent); !ok || np.BandwidthLimit != "10MB" || np.BandwidthLimitMode != "server" || np.ProxyName != "alice.blog" {
		t.Errorf("NewProxy content = %+v, want alice.blog limited to 10MB in server mode", content)
	}

	res, _, err = frps.Handle(t.Context(), plugin.OpNewProxy, newProxyContent("alice", "bob.default", "bob"))
	if err != nil || !res.Reject || res.RejectReason != "name bob.default is not yours" {
		t.Errorf("NewProxy of another user's name = %+v, %v, want a reject with the reason", res, err)
	}

	res, _, err = frps.Handle(t.Context(), plugin.OpCloseProxy, plugin.CloseProxyContent{User: plugin.UserInfo{User: "alice"}, CloseProxy: msg.CloseProxy{ProxyName: "alice.blog"}})
	if err != nil || res.Reject {
		t.Errorf("CloseProxy = %+v, %v, want no error and no reject", res, err)
	}

	// The wrong secret is an error to frps, which then refuses the client (it fails closed).
	wrong := plugin.NewHTTPPluginOptions(v1.HTTPPluginOptions{Name: "tunnels", Addr: srv.URL, Path: "/plugin/wrong", Ops: []string{plugin.OpLogin}})
	if _, _, err := wrong.Handle(t.Context(), plugin.OpLogin, in); err == nil {
		t.Error("Login with the wrong secret: no error")
	}
}
