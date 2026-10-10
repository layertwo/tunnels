package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/layertwo/tunnels/internal/httpx"
	"github.com/layertwo/tunnels/internal/idp"
	"github.com/layertwo/tunnels/internal/mockidp"
)

const ua = "tunnels-test/1"

func client() *http.Client { return httpx.Client(ua, 10*time.Second) }

// ---- Discover and GetMe

const bootstrapJSON = `{"issuer":"https://idp.example","cli_client_id":"tunnels-cli","api_resource":"https://tunnels.example","service_host":"tunnels.example","sites_domain":"w.tunnels.example","min_cli_version":"0.2.0","extra":"ignored"}`

func TestDiscover(t *testing.T) {
	var gotPath, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotUA = r.URL.Path, r.UserAgent()
		io.WriteString(w, bootstrapJSON)
	}))
	defer srv.Close()

	want := Bootstrap{Issuer: "https://idp.example", CLIClientID: "tunnels-cli", APIResource: "https://tunnels.example",
		ServiceHost: "tunnels.example", SitesDomain: "w.tunnels.example", MinCLIVersion: "0.2.0"}
	for _, base := range []string{srv.URL, srv.URL + "/"} {
		got, err := Discover(t.Context(), client(), base)
		if err != nil || got != want {
			t.Errorf("Discover(%q) = %+v, %v, want %+v", base, got, err, want)
		}
		if gotPath != "/.well-known/tunnels.json" || gotUA != ua {
			t.Errorf("asked %q with User-Agent %q", gotPath, gotUA)
		}
	}
}

func TestDiscoverErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string // part of the error text
	}{
		{"not found", 404, "nope", "404"},
		{"server error", 500, "", "500"},
		{"bad json", 200, "<html>", "tunnels.json"},
		{"empty object", 200, "{}", "issuer"},
		{"no client id", 200, `{"issuer":"i","api_resource":"a","service_host":"h","sites_domain":"s"}`, "cli_client_id"},
		{"no api resource", 200, `{"issuer":"i","cli_client_id":"c","service_host":"h","sites_domain":"s"}`, "api_resource"},
		{"no service host", 200, `{"issuer":"i","cli_client_id":"c","api_resource":"a","sites_domain":"s"}`, "service_host"},
		{"no sites domain", 200, `{"issuer":"i","cli_client_id":"c","api_resource":"a","service_host":"h"}`, "sites_domain"},
		// a complete document, padded past the limit: only reading less than all of it makes this fail
		{"too large", 200, `{"issuer":"i","cli_client_id":"c","api_resource":"a","service_host":"h","sites_domain":"s","pad":"` + strings.Repeat("a", 2<<20) + `"}`, "tunnels.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				io.WriteString(w, tt.body)
			}))
			defer srv.Close()
			got, err := Discover(t.Context(), client(), srv.URL)
			if err == nil || !strings.Contains(err.Error(), tt.want) || got != (Bootstrap{}) {
				t.Errorf("Discover = %+v, %v, want the zero value and an error containing %q", got, err, tt.want)
			}
		})
	}

	if _, err := Discover(t.Context(), client(), "http://127.0.0.1:1"); err == nil {
		t.Error("Discover of a closed port: no error")
	}
}

// The minimum version is advice for the CLI; a service that has none yet need not name one.
func TestDiscoverWithoutMinimumVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"issuer":"i","cli_client_id":"c","api_resource":"a","service_host":"h","sites_domain":"s"}`)
	}))
	defer srv.Close()
	if got, err := Discover(t.Context(), client(), srv.URL); err != nil || got.MinCLIVersion != "" {
		t.Errorf("Discover = %+v, %v", got, err)
	}
}

func TestGetMe(t *testing.T) {
	var gotAuth, gotPath, gotUA string
	var status = http.StatusOK
	var body = `{"sub":"sub-alice","username":"Alice","handle":"alice"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotUA = r.Header.Get("Authorization"), r.URL.Path, r.UserAgent()
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer srv.Close()

	got, err := GetMe(t.Context(), client(), srv.URL, "tok-123")
	if err != nil || got != (Me{Sub: "sub-alice", Username: "Alice", Handle: "alice"}) {
		t.Fatalf("GetMe = %+v, %v", got, err)
	}
	if gotAuth != "Bearer tok-123" || gotPath != "/api/me" || gotUA != ua {
		t.Errorf("asked %q with Authorization %q and User-Agent %q", gotPath, gotAuth, gotUA)
	}

	for _, tt := range []struct {
		name   string
		status int
		body   string
		want   string // the exact error text
	}{
		{"refusal", 403, `{"error":"your account is not allowed to publish tunnels: ask an admin to add you to tunnels-creators"}`,
			"your account is not allowed to publish tunnels: ask an admin to add you to tunnels-creators"},
		{"session", 401, `{"error":"your session is not valid; run: tunnel login"}`, "your session is not valid; run: tunnel login"},
		{"outage", 503, `{"error":"login unavailable, try again"}`, "login unavailable, try again"},
		{"no json", 502, "<html>bad gateway</html>", "the service answered 502"},
		{"json without a message", 500, `{}`, "the service answered 500"},
		{"ok but not json", 200, "<html>", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status, body = tt.status, tt.body
			got, err := GetMe(t.Context(), client(), srv.URL, "tok-123")
			if err == nil || got != (Me{}) {
				t.Fatalf("GetMe = %+v, %v, want the zero value and an error", got, err)
			}
			if tt.want != "" && err.Error() != tt.want {
				t.Errorf("error = %q, want %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "tok-123") {
				t.Errorf("the error repeats the token: %v", err)
			}
		})
	}
	status, body = 200, `{"sub":"s","username":"u"}`
	if got, err := GetMe(t.Context(), client(), srv.URL, "tok"); err == nil {
		t.Errorf("an answer without a handle was accepted: %+v", got)
	}
}

// ---- the device flow and refresh, against the mock identity provider

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *safeBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

var userCodeRE = regexp.MustCompile(`[A-Z]{4}-[A-Z]{4}`)

func newOIDC(t *testing.T) (OIDC, *mockidp.Server) {
	t.Helper()
	m := mockidp.New(t)
	m.AddUser(mockidp.User{Sub: "sub-alice", Username: "Alice", Groups: []string{"tunnels-creators"}})
	return OIDC{Issuer: m.URL, ClientID: mockidp.ClientID, Resource: mockidp.APIResource, HTTP: client()}, m
}

// verifies reports the sub of an access token the way the broker does: signed by the provider, meant for the API.
func verifies(t *testing.T, m *mockidp.Server, token string) string {
	t.Helper()
	c, err := idp.New(t.Context(), m.URL, mockidp.APIResource, ua, "", "")
	if err != nil {
		t.Fatal(err)
	}
	sub, err := c.VerifyAccessToken(t.Context(), token)
	if err != nil {
		t.Fatalf("access token does not verify for the API: %v", err)
	}
	return sub
}

type loginResult struct {
	tokens Tokens
	err    error
}

// startLogin runs DeviceLogin and returns once it has printed the user code.
func startLogin(t *testing.T, o OIDC, ctx context.Context) (code string, out *safeBuffer, done <-chan loginResult) {
	t.Helper()
	out = &safeBuffer{}
	ch := make(chan loginResult, 1)
	go func() {
		tok, err := o.DeviceLogin(ctx, out)
		ch <- loginResult{tok, err}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if code = userCodeRE.FindString(out.String()); code != "" {
			return code, out, ch
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("DeviceLogin printed no user code:\n%s", out)
	return
}

func wait(t *testing.T, done <-chan loginResult) loginResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(15 * time.Second):
		t.Fatal("DeviceLogin did not return")
		return loginResult{}
	}
}

func TestDeviceLogin(t *testing.T) {
	t.Parallel()
	o, m := newOIDC(t)
	code, out, done := startLogin(t, o, t.Context())
	time.Sleep(1200 * time.Millisecond) // the first poll, at one second, finds the code still pending
	m.Approve(code, "sub-alice")
	r := wait(t, done)

	if r.err != nil {
		t.Fatal(r.err)
	}
	if sub := verifies(t, m, r.tokens.AccessToken); sub != "sub-alice" {
		t.Errorf("access token is for %q, want sub-alice", sub)
	}
	if r.tokens.RefreshToken == "" {
		t.Error("no refresh token: offline_access was not asked for")
	}
	if r.tokens.Handle != "" || r.tokens.Server != "" {
		t.Errorf("DeviceLogin filled in %q and %q; the caller learns those from the service", r.tokens.Handle, r.tokens.Server)
	}

	// What the person is shown: where to go and the code, and nothing secret.
	for _, want := range []string{m.URL + "/device", code} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{r.tokens.AccessToken, r.tokens.RefreshToken} {
		if strings.Contains(out.String(), secret) {
			t.Errorf("the output contains a token:\n%s", out)
		}
	}

	// What was asked of the provider: a public client, the API as the resource, the four scopes.
	reqs := m.DeviceRequests()
	if len(reqs) != 1 {
		t.Fatalf("%d device authorization requests, want 1", len(reqs))
	}
	form := reqs[0]
	if form.Get("client_id") != mockidp.ClientID || form.Get("resource") != mockidp.APIResource {
		t.Errorf("client_id = %q, resource = %q", form.Get("client_id"), form.Get("resource"))
	}
	if got := strings.Fields(form.Get("scope")); strings.Join(got, " ") != "openid profile groups offline_access" {
		t.Errorf("scope = %q", form.Get("scope"))
	}
	for k := range form {
		if strings.Contains(k, "secret") || k == "client_assertion" {
			t.Errorf("the request carried %q: the client is public", k)
		}
	}
	for _, agent := range m.UserAgents() {
		if agent != ua {
			t.Errorf("a request carried User-Agent %q, want %q", agent, ua)
		}
	}
}

func TestDeviceLoginDenied(t *testing.T) {
	t.Parallel()
	o, m := newOIDC(t)
	code, _, done := startLogin(t, o, t.Context())
	m.Deny(code)
	r := wait(t, done)
	if r.err == nil || r.err.Error() != "the login was denied" || r.tokens != (Tokens{}) {
		t.Errorf("= %+v, %v, want no tokens and the sentence saying it was denied", r.tokens, r.err)
	}
}

func TestDeviceLoginExpired(t *testing.T) {
	t.Parallel()
	o, m := newOIDC(t)
	m.SetDeviceTTL(2 * time.Second)
	_, _, done := startLogin(t, o, t.Context())
	r := wait(t, done)
	if r.err == nil || !strings.Contains(r.err.Error(), "expired") || !strings.Contains(r.err.Error(), "tunnel login") || r.tokens != (Tokens{}) {
		t.Errorf("= %+v, %v, want no tokens and an error saying the code expired and what to run", r.tokens, r.err)
	}
}

func TestDeviceLoginCanceled(t *testing.T) {
	t.Parallel()
	o, _ := newOIDC(t)
	ctx, cancel := context.WithCancel(t.Context())
	_, _, done := startLogin(t, o, ctx)
	cancel()
	r := wait(t, done)
	if !errors.Is(r.err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", r.err)
	}
}

// The caller running out of time is not the code expiring; the person is told which it was.
func TestDeviceLoginCallersDeadline(t *testing.T) {
	t.Parallel()
	o, _ := newOIDC(t)
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	_, _, done := startLogin(t, o, ctx)
	r := wait(t, done)
	if !errors.Is(r.err, context.DeadlineExceeded) || strings.Contains(r.err.Error(), "expired") {
		t.Errorf("err = %v, want the caller's deadline and no talk of an expired code", r.err)
	}
}

// An identity provider that has no device flow cannot log the CLI in; say so, do not hang.
func TestDeviceLoginNeedsADeviceEndpoint(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/auth", "token_endpoint": srv.URL + "/token",
			"jwks_uri": srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer srv.Close()
	o := OIDC{Issuer: srv.URL, ClientID: "c", Resource: "r", HTTP: client()}
	_, err := o.DeviceLogin(t.Context(), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "device") {
		t.Errorf("err = %v, want one saying there is no device flow", err)
	}
}

// recorder keeps the form of every request to the token endpoint.
type recorder struct {
	mu    sync.Mutex
	forms []url.Values
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost && req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		form, _ := url.ParseQuery(string(body))
		for k, v := range req.URL.Query() { // a parameter in the URL counts as much as one in the body
			form[k] = append(form[k], v...)
		}
		r.mu.Lock()
		r.forms = append(r.forms, form)
		r.mu.Unlock()
	}
	return http.DefaultTransport.RoundTrip(req)
}

func TestRefreshRotates(t *testing.T) {
	o, m := newOIDC(t)
	rec := &recorder{}
	o.HTTP = &http.Client{Transport: rec, Timeout: 10 * time.Second}
	old := m.IssueRefreshToken("sub-alice")

	got, err := o.Refresh(t.Context(), old)
	if err != nil {
		t.Fatal(err)
	}
	if got.RefreshToken == "" || got.RefreshToken == old {
		t.Errorf("refresh token %q after refreshing with %q, want a new one", got.RefreshToken, old)
	}
	if sub := verifies(t, m, got.AccessToken); sub != "sub-alice" { // still meant for the API: the audience was kept
		t.Errorf("refreshed access token is for %q", sub)
	}

	if len(rec.forms) != 1 {
		t.Fatalf("%d token requests, want 1", len(rec.forms))
	}
	form := rec.forms[0]
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != old || form.Get("client_id") != mockidp.ClientID {
		t.Errorf("token request = %v", form)
	}
	// Pocket ID keeps the audience of the original grant; asking again for a resource could change it.
	if form.Has("resource") || form.Has("client_secret") || form.Has("scope") {
		t.Errorf("token request carried resource, secret or scope: %v", form)
	}
}

func TestRefreshFailure(t *testing.T) {
	o, m := newOIDC(t)
	rt := m.IssueRefreshToken("sub-alice")
	m.RevokeUser("sub-alice")

	_, err := o.Refresh(t.Context(), rt)
	if err == nil || !strings.Contains(err.Error(), "tunnel login") {
		t.Errorf("revoked: err = %v, want one saying to log in again", err)
	}
	if err != nil && strings.Contains(err.Error(), rt) {
		t.Errorf("the error repeats the refresh token: %v", err)
	}

	if _, err := o.Refresh(t.Context(), ""); err == nil || !strings.Contains(err.Error(), "tunnel login") {
		t.Errorf("no refresh token: err = %v, want one saying to log in again", err)
	}

	down := OIDC{Issuer: "http://127.0.0.1:1", ClientID: "c", Resource: "r", HTTP: client()}
	_, err = down.Refresh(t.Context(), "rt")
	if err == nil || strings.Contains(err.Error(), "tunnel login") {
		t.Errorf("provider unreachable: err = %v, want a plain error (logging in again would not help)", err)
	}
}

func saved(t *testing.T, s Store, m *mockidp.Server) Tokens {
	t.Helper()
	tok := Tokens{AccessToken: m.Issue("sub-alice", mockidp.IssueOpts{}), RefreshToken: m.IssueRefreshToken("sub-alice"), Handle: "alice", Server: "https://tunnels.example"}
	if err := s.Save(tok); err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestRefreshStored(t *testing.T) {
	o, m := newOIDC(t)
	s := Store{Dir: t.TempDir()}
	before := saved(t, s, m)

	got, err := RefreshStored(t.Context(), s, o)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken == before.AccessToken || got.RefreshToken == before.RefreshToken {
		t.Errorf("tokens did not change: %+v", got)
	}
	if got.Handle != "alice" || got.Server != "https://tunnels.example" {
		t.Errorf("handle and server were lost: %+v", got)
	}
	if loaded, err := s.Load(); err != nil || loaded != got {
		t.Errorf("stored = %+v, %v, want what RefreshStored returned", loaded, err)
	}
	if raw, _ := os.ReadFile(s.AccessTokenPath()); string(raw) != got.AccessToken {
		t.Error("access-token does not hold the new access token")
	}
	verifies(t, m, got.AccessToken)
}

func TestRefreshStoredWhenLoggedOut(t *testing.T) {
	o, _ := newOIDC(t)
	if _, err := RefreshStored(t.Context(), Store{Dir: t.TempDir()}, o); !errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("err = %v, want ErrNotLoggedIn", err)
	}
}

// Good tokens are worth more than fresh ones: whatever goes wrong, the files stay as they were.
func TestRefreshFailureKeepsFiles(t *testing.T) {
	o, m := newOIDC(t)
	s := Store{Dir: t.TempDir()}
	saved(t, s, m)
	snapshot := func() (string, string) {
		a, _ := os.ReadFile(s.tokensPath())
		b, _ := os.ReadFile(s.AccessTokenPath())
		return string(a), string(b)
	}
	tokens0, access0 := snapshot()

	m.RevokeUser("sub-alice")
	if _, err := RefreshStored(t.Context(), s, o); err == nil {
		t.Fatal("RefreshStored of a revoked login succeeded")
	}
	down := OIDC{Issuer: "http://127.0.0.1:1", ClientID: "c", Resource: "r", HTTP: client()}
	if _, err := RefreshStored(t.Context(), s, down); err == nil {
		t.Fatal("RefreshStored with the provider down succeeded")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := RefreshStored(ctx, s, o); err == nil {
		t.Fatal("RefreshStored with a canceled context succeeded")
	}

	if tokens1, access1 := snapshot(); tokens1 != tokens0 || access1 != access0 {
		t.Errorf("the files changed after failed refreshes:\n%s\n%s\nwas\n%s\n%s", tokens1, access1, tokens0, access0)
	}
}

// Two `tunnel up` processes share one directory. The provider retires a refresh token at once when
// it is used, so the second refresh only works with the token the first one saved.
func TestTwoProcessesShareRotation(t *testing.T) {
	o, m := newOIDC(t)
	m.SetRefreshGrace(0)
	s := Store{Dir: t.TempDir()}
	first := saved(t, s, m)

	one, err := RefreshStored(t.Context(), s, o)
	if err != nil {
		t.Fatal(err)
	}
	two, err := RefreshStored(t.Context(), s, o) // another process, starting from what the first saved
	if err != nil {
		t.Fatalf("the second refresh failed: %v", err)
	}
	if two.RefreshToken == one.RefreshToken || two.RefreshToken == first.RefreshToken {
		t.Errorf("refresh tokens did not rotate: %q %q %q", first.RefreshToken, one.RefreshToken, two.RefreshToken)
	}

	// The control: the token both started from is dead, so a process that kept it in memory would fail.
	if _, err := o.Refresh(t.Context(), first.RefreshToken); err == nil {
		t.Error("the original refresh token still works; the test proves nothing")
	}
}

func TestKeepFresh(t *testing.T) {
	o, m := newOIDC(t)
	// Short, so that only refreshing keeps a token good, but not so short that the second-resolution
	// exp of a token issued late in a second has passed by the time the test checks it.
	m.SetTTL(5 * time.Second)
	s := Store{Dir: t.TempDir()}
	saved(t, s, m)

	var mu sync.Mutex
	var errs []error
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		KeepFresh(ctx, s, o, 50*time.Millisecond, func(err error) { mu.Lock(); errs = append(errs, err); mu.Unlock() })
	}()

	seen := map[string]bool{}
	for deadline := time.Now().Add(700 * time.Millisecond); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		raw, err := os.ReadFile(s.AccessTokenPath())
		if err != nil {
			t.Fatal(err)
		}
		if !seen[string(raw)] {
			seen[string(raw)] = true
			verifies(t, m, string(raw)) // always a whole token the provider issued, never half a file
		}
	}
	if len(seen) < 3 { // the one saved at the start and at least two refreshed ones
		t.Errorf("access-token held %d different tokens in 700 ms, want at least 3", len(seen))
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("KeepFresh did not stop when its context ended")
	}
	after, _ := os.ReadFile(s.AccessTokenPath())
	time.Sleep(200 * time.Millisecond)
	if again, _ := os.ReadFile(s.AccessTokenPath()); string(again) != string(after) {
		t.Error("the access token changed after KeepFresh returned")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(errs) != 0 {
		t.Errorf("onErr was called on a healthy run: %v", errs)
	}
}

// A refresh that fails is reported and tried again; it neither ends the loop nor touches the files.
func TestKeepFreshReportsAndKeepsGoing(t *testing.T) {
	o, m := newOIDC(t)
	s := Store{Dir: t.TempDir()}
	saved(t, s, m)
	m.RevokeUser("sub-alice")
	before, _ := os.ReadFile(s.AccessTokenPath())

	var mu sync.Mutex
	calls := 0
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		KeepFresh(ctx, s, o, 30*time.Millisecond, func(err error) {
			if err == nil {
				t.Error("onErr(nil)")
			}
			mu.Lock()
			calls++
			mu.Unlock()
		})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := calls
		mu.Unlock()
		if n >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-stopped
	mu.Lock()
	defer mu.Unlock()
	if calls < 3 {
		t.Errorf("onErr called %d times, want the loop to keep trying (at least 3)", calls)
	}
	if after, _ := os.ReadFile(s.AccessTokenPath()); string(after) != string(before) {
		t.Error("a failed refresh changed the access token file")
	}
}

// Without a callback a failure is simply tried again at the next tick.
func TestKeepFreshWithoutCallback(t *testing.T) {
	o, m := newOIDC(t)
	s := Store{Dir: t.TempDir()}
	saved(t, s, m)
	m.RevokeUser("sub-alice")
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	KeepFresh(ctx, s, o, 20*time.Millisecond, nil) // must neither panic nor block past the context
}
