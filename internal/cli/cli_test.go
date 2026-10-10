package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/layertwo/tunnels/internal/auth"
	"github.com/layertwo/tunnels/internal/httpx"
	"github.com/layertwo/tunnels/internal/mockidp"
	"github.com/layertwo/tunnels/internal/tunnel"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// world is a service (bootstrap document and /api/me), the mock identity provider and a config dir.
type world struct {
	t        *testing.T
	idp      *mockidp.Server
	svc      *httptest.Server
	me       http.HandlerFunc
	dir      string
	out, err *syncBuffer

	mu           sync.Mutex
	runs         []tunnel.Options
	run          func(ctx context.Context, o tunnel.Options, onStatus func(tunnel.Status)) error
	shares       []auth.Share    // what GET /api/shares answers
	sharesStatus int             // when non-zero, GET /api/shares answers this status instead
	putStatus    int             // when non-zero, PUT or DELETE /api/shares answers this status instead
	shareReq     []recordedShare // every PUT or DELETE /api/shares
}

// recordedShare is one request to change a share.
type recordedShare struct {
	method string
	body   string
	share  auth.Share
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, dir: t.TempDir(), out: &syncBuffer{}, err: &syncBuffer{}}
	w.idp = mockidp.New(t)
	w.idp.AddUser(mockidp.User{Sub: "sub-alice", Username: "Alice", Groups: []string{"tunnels-creators"}})
	w.me = func(rw http.ResponseWriter, _ *http.Request) {
		io.WriteString(rw, `{"sub":"sub-alice","username":"Alice","handle":"alice"}`)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/tunnels.json", func(rw http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(rw).Encode(map[string]string{
			"issuer": w.idp.URL, "cli_client_id": mockidp.ClientID, "api_resource": mockidp.APIResource,
			"service_host": "tunnels.test", "sites_domain": "w.tunnels.test", "min_cli_version": "0.0.0",
		})
	})
	mux.HandleFunc("GET /api/me", func(rw http.ResponseWriter, r *http.Request) { w.me(rw, r) })
	mux.HandleFunc("GET /api/shares", func(rw http.ResponseWriter, _ *http.Request) {
		w.mu.Lock()
		status, shares := w.sharesStatus, w.shares
		w.mu.Unlock()
		if status != 0 {
			rw.WriteHeader(status)
			io.WriteString(rw, `{"error":"cannot list your shares"}`)
			return
		}
		json.NewEncoder(rw).Encode(map[string]any{"shares": shares})
	})
	mux.HandleFunc("PUT /api/shares", w.changeShare)
	mux.HandleFunc("DELETE /api/shares", w.changeShare)
	w.svc = httptest.NewServer(mux)
	t.Cleanup(w.svc.Close)
	return w
}

func (w *world) env() Env {
	return Env{
		Stdout: w.out, Stderr: w.err, ConfigDir: w.dir, DefaultServer: "tunnels.layertwo.dev", Version: "1.2.3",
		HTTP: httpx.Client("tunnels-test/1", 10*time.Second),
		Run: func(ctx context.Context, o tunnel.Options, onStatus func(tunnel.Status)) error {
			w.mu.Lock()
			w.runs = append(w.runs, o)
			run := w.run
			w.mu.Unlock()
			if run == nil {
				return nil
			}
			return run(ctx, o, onStatus)
		},
	}
}

func (w *world) main(args ...string) int { return Main(args, w.env()) }

// loggedIn leaves what a login would have left: tokens for alice at this service.
func (w *world) loggedIn() auth.Tokens {
	w.t.Helper()
	tok := auth.Tokens{AccessToken: w.idp.Issue("sub-alice", mockidp.IssueOpts{}), RefreshToken: w.idp.IssueRefreshToken("sub-alice"),
		Handle: "alice", Server: w.svc.URL}
	if err := (auth.Store{Dir: w.dir}).Save(tok); err != nil {
		w.t.Fatal(err)
	}
	return tok
}

// changeShare records a PUT or DELETE /api/shares and answers 204 like the broker.
func (w *world) changeShare(rw http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var sh auth.Share
	json.Unmarshal(raw, &sh)
	w.mu.Lock()
	w.shareReq = append(w.shareReq, recordedShare{method: r.Method, body: string(raw), share: sh})
	status := w.putStatus
	w.mu.Unlock()
	if status != 0 {
		rw.WriteHeader(status)
		io.WriteString(rw, `{"error":"you do not own that tunnel"}`)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

var userCodeRE = regexp.MustCompile(`[A-Z]{4}-[A-Z]{4}`)

func waitFor(t *testing.T, b *syncBuffer, re *regexp.Regexp) string {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if m := re.FindString(b.String()); m != "" {
			return m
		}
	}
	t.Fatalf("never printed %v:\n%s", re, b)
	return ""
}

func exitOf(t *testing.T, code <-chan int) int {
	t.Helper()
	select {
	case c := <-code:
		return c
	case <-time.After(15 * time.Second):
		t.Fatal("Main did not return")
		return -1
	}
}

func TestLoginWritesTokens(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	code := make(chan int, 1)
	go func() { code <- w.main("login", "--server", w.svc.URL) }()
	w.idp.Approve(waitFor(t, w.out, userCodeRE), "sub-alice")

	if c := exitOf(t, code); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	for _, want := range []string{w.idp.URL + "/device", "Logged in as Alice (alice)"} {
		if !strings.Contains(w.out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, w.out)
		}
	}
	tok, err := (auth.Store{Dir: w.dir}).Load()
	if err != nil || tok.Handle != "alice" || tok.Server != w.svc.URL || tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Errorf("stored %+v, %v", tok, err)
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{"tokens.json", "access-token"} {
			if fi, err := os.Stat(filepath.Join(w.dir, name)); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("%s: %v %v", name, fi, err)
			}
		}
	}
}

// What the service says when it refuses is what the person reads, and nothing is kept.
func TestLoginShowsServerRefusal(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.me = func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
		io.WriteString(rw, `{"error":"ask an admin to add you to tunnels-creators"}`)
	}
	code := make(chan int, 1)
	go func() { code <- w.main("login", "--server", w.svc.URL) }()
	w.idp.Approve(waitFor(t, w.out, userCodeRE), "sub-alice")

	if c := exitOf(t, code); c != 1 {
		t.Errorf("exit %d, want 1", c)
	}
	if !strings.Contains(w.err.String(), "ask an admin to add you to tunnels-creators") {
		t.Errorf("stderr:\n%s", w.err)
	}
	if _, err := (auth.Store{Dir: w.dir}).Load(); !errors.Is(err, auth.ErrNotLoggedIn) {
		t.Errorf("tokens were kept after a refusal: %v", err)
	}
}

func TestLoginUnreachableService(t *testing.T) {
	w := newWorld(t)
	if c := w.main("login", "--server", "http://127.0.0.1:1"); c != 1 || w.err.String() == "" {
		t.Errorf("exit %d, stderr %q", c, w.err)
	}
}

func TestBaseURL(t *testing.T) {
	for in, want := range map[string]string{
		"tunnels.layertwo.dev":         "https://tunnels.layertwo.dev",
		"tunnels.layertwo.dev:8443":    "https://tunnels.layertwo.dev:8443",
		"https://tunnels.layertwo.dev": "https://tunnels.layertwo.dev",
		"http://127.0.0.1:8080/":       "http://127.0.0.1:8080",
	} {
		if got := baseURL(in); got != want {
			t.Errorf("baseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUpArgumentErrors(t *testing.T) {
	for _, args := range [][]string{
		{"up"},
		{"up", "abc"},
		{"up", "0"},
		{"up", "65536"},
		{"up", "-1"},
		{"up", "3000", "4000"},
		{"up", "--name", "blog"},
		{"up", "3000", "--name", "Blog"},
		{"up", "3000", "--name", "default"},
		{"up", "3000", "--name", "a_b"},
		{"up", "3000", "--bogus"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			w := newWorld(t)
			w.loggedIn()
			if c := w.main(args...); c != 2 {
				t.Errorf("exit %d, want 2", c)
			}
			if !strings.Contains(w.err.String(), "tunnel up PORT") {
				t.Errorf("no usage line on stderr:\n%s", w.err)
			}
			if len(w.runs) != 0 {
				t.Error("the tunnel was started")
			}
		})
	}
}

func TestUpNotLoggedIn(t *testing.T) {
	w := newWorld(t)
	if c := w.main("up", "3000"); c != 1 || !strings.Contains(w.err.String(), "run: tunnel login") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

func TestUp(t *testing.T) {
	w := newWorld(t)
	before := w.loggedIn()
	w.run = func(ctx context.Context, o tunnel.Options, onStatus func(tunnel.Status)) error {
		onStatus(tunnel.Status{Phase: "wait start"})
		onStatus(tunnel.Status{Phase: "start error", Err: "name alice.blog is busy"})
		onStatus(tunnel.Status{Phase: "wait start"})
		onStatus(tunnel.Status{Phase: "start error", Err: "name alice.blog is busy"}) // a retry with the same answer
		onStatus(tunnel.Status{Phase: "running"})
		return nil
	}
	if c := w.main("up", "3000", "--name", "blog"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}

	if len(w.runs) != 1 {
		t.Fatalf("%d runs", len(w.runs))
	}
	o := w.runs[0]
	want := tunnel.Options{ServerHost: "tunnels.test", ServerPort: 443, Protocol: "wss", Handle: "alice", Name: "blog",
		LocalPort: 3000, TokenFile: filepath.Join(w.dir, "access-token"), CAFile: filepath.Join(w.dir, "cacert.pem"), Version: "1.2.3"}
	if o != want {
		t.Errorf("options =\n%+v\nwant\n%+v", o, want)
	}
	if fi, err := os.Stat(o.CAFile); err != nil || fi.Size() < 100_000 {
		t.Errorf("CA bundle: %v %v", fi, err)
	}
	if !strings.Contains(w.out.String(), "https://alice-blog.w.tunnels.test") {
		t.Errorf("stdout lacks the site's URL:\n%s", w.out)
	}
	if n := strings.Count(w.err.String(), "name alice.blog is busy"); n != 1 {
		t.Errorf("the start error was printed %d times, want once:\n%s", n, w.err)
	}
	// The tunnel starts with a token refreshed just now, not the one left by the login.
	after, _ := (auth.Store{Dir: w.dir}).Load()
	if after.AccessToken == before.AccessToken || after.RefreshToken == before.RefreshToken {
		t.Error("the login was not refreshed before the tunnel started")
	}
}

func TestUpDefaultTunnel(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.run = func(ctx context.Context, o tunnel.Options, onStatus func(tunnel.Status)) error {
		onStatus(tunnel.Status{Phase: "running"})
		return nil
	}
	if c := w.main("up", "8080"); c != 0 || w.runs[0].Name != "" || !strings.Contains(w.out.String(), "https://alice.w.tunnels.test") {
		t.Errorf("exit %d, runs %+v, stdout:\n%s", c, w.runs, w.out)
	}
}

// After a crash the old tunnel still counts until frps notices; say so next to the broker's answer.
func TestUpTunnelLimitHint(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.run = func(ctx context.Context, o tunnel.Options, onStatus func(tunnel.Status)) error {
		onStatus(tunnel.Status{Phase: "start error", Err: "tunnel limit of 5 reached"})
		return nil
	}
	w.main("up", "3000")
	if !strings.Contains(w.err.String(), "tunnel limit of 5 reached") || !strings.Contains(w.err.String(), "90 seconds") {
		t.Errorf("stderr:\n%s", w.err)
	}
}

func TestUpRefusedLogin(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.run = func(context.Context, tunnel.Options, func(tunnel.Status)) error {
		return errors.New("login to the server failed: your account is disabled: ask an admin")
	}
	if c := w.main("up", "3000"); c != 1 || !strings.Contains(w.err.String(), "your account is disabled: ask an admin") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

func TestUpRefreshFails(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.idp.RevokeUser("sub-alice")
	c := w.main("up", "3000")
	if c != 1 || !strings.Contains(w.err.String(), "could not refresh your session (") || !strings.Contains(w.err.String(), "); run: tunnel login") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
	if len(w.runs) != 0 {
		t.Error("the tunnel was started with a session that could not be refreshed")
	}
}

// The token refresher lives as long as the tunnel and no longer.
func TestUpStopsRefreshingWhenTheTunnelEnds(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	var ctxDone <-chan struct{}
	w.run = func(ctx context.Context, o tunnel.Options, onStatus func(tunnel.Status)) error {
		ctxDone = ctx.Done()
		return nil
	}
	w.main("up", "3000")
	select {
	case <-ctxDone:
	case <-time.After(time.Second):
		t.Error("the context handed to the tunnel is still live after up returned")
	}
}

func TestLogoutClears(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if c := w.main("logout"); c != 0 {
		t.Fatalf("exit %d", c)
	}
	if _, err := (auth.Store{Dir: w.dir}).Load(); !errors.Is(err, auth.ErrNotLoggedIn) {
		t.Errorf("after logout: %v", err)
	}
	if c := w.main("logout"); c != 0 {
		t.Errorf("logout when logged out: exit %d", c)
	}
}

func TestVersion(t *testing.T) {
	w := newWorld(t)
	if c := w.main("version"); c != 0 || w.out.String() != "tunnel 1.2.3 (server tunnels.layertwo.dev)\n" {
		t.Errorf("exit %d, stdout %q", c, w.out)
	}
}

func TestUnknownCommand(t *testing.T) {
	for _, args := range [][]string{{}, {"frobnicate"}, {"logout", "extra"}, {"version", "--x"}} {
		w := newWorld(t)
		if c := w.main(args...); c != 2 || !strings.Contains(w.err.String(), "Usage") {
			t.Errorf("%q: exit %d, stderr %q", args, c, w.err)
		}
	}
	w := newWorld(t)
	if c := w.main("help"); c != 0 || !strings.Contains(w.out.String(), "tunnel up PORT") {
		t.Errorf("help: exit %d, stdout %q", c, w.out)
	}
}

// Without a configured directory the CLI uses TUNNELS_CONFIG_DIR, then the platform's config dir.
func TestConfigDirFromTheEnvironment(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	t.Setenv("TUNNELS_CONFIG_DIR", w.dir)
	env := w.env()
	env.ConfigDir = ""
	if c := Main([]string{"logout"}, env); c != 0 {
		t.Fatalf("exit %d", c)
	}
	if _, err := (auth.Store{Dir: w.dir}).Load(); !errors.Is(err, auth.ErrNotLoggedIn) {
		t.Errorf("logout did not use TUNNELS_CONFIG_DIR: %v", err)
	}
}

// ---- share, unshare, list

func TestShareCommand(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if c := w.main("share", "--name", "blog", "bob"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	if len(w.shareReq) != 1 {
		t.Fatalf("%d share requests, want 1", len(w.shareReq))
	}
	got := w.shareReq[0]
	want := recordedShare{method: http.MethodPut, body: `{"tunnel":"blog","kind":"user","grantee":"bob"}`,
		share: auth.Share{Tunnel: "blog", Kind: "user", Grantee: "bob"}}
	if got != want {
		t.Errorf("request = %+v, want %+v", got, want)
	}
}

func TestShareGroup(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if c := w.main("share", "--name", "blog", "--group", "family"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	if len(w.shareReq) != 1 || w.shareReq[0].share.Kind != "group" {
		t.Errorf("requests = %+v, want one with kind group", w.shareReq)
	}
}

func TestShareDefaultTunnel(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if c := w.main("share", "bob"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	if len(w.shareReq) != 1 || w.shareReq[0].share.Tunnel != "" {
		t.Errorf("requests = %+v, want one with an empty tunnel", w.shareReq)
	}
}

func TestUnshare(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if c := w.main("unshare", "--name", "blog", "bob"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	want := recordedShare{method: http.MethodDelete, body: `{"tunnel":"blog","kind":"user","grantee":"bob"}`,
		share: auth.Share{Tunnel: "blog", Kind: "user", Grantee: "bob"}}
	if len(w.shareReq) != 1 || w.shareReq[0] != want {
		t.Errorf("requests = %+v, want %+v", w.shareReq, want)
	}
}

func TestListPrints(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.shares = []auth.Share{
		{Tunnel: "", Kind: "user", Grantee: "bob"},
		{Tunnel: "blog", Kind: "group", Grantee: "family"},
	}
	if c := w.main("list"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	out := w.out.String()
	for _, want := range []string{"(default)", "bob", "blog", "group", "family"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
}

func TestShareNotLoggedIn(t *testing.T) {
	w := newWorld(t)
	if c := w.main("share", "bob"); c != 1 || !strings.Contains(w.err.String(), "run: tunnel login") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

func TestShareArgumentErrors(t *testing.T) {
	for _, args := range [][]string{
		{"share"},
		{"share", "bob", "extra"},
		{"share", "--name", "blog"},
		{"share", "--name", "Blog", "bob"},
		{"share", "--name", "default", "bob"},
		{"share", "--bogus", "bob"},
		{"unshare"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			w := newWorld(t)
			w.loggedIn()
			if c := w.main(args...); c != 2 {
				t.Errorf("exit %d, want 2", c)
			}
			if !strings.Contains(w.err.String(), "Usage: tunnel") {
				t.Errorf("no usage line on stderr:\n%s", w.err)
			}
		})
	}
}

// A group share only works if the OIDC gate forwards groups; the help must say so.
func TestUsageMentionsGroupPrerequisite(t *testing.T) {
	if !strings.Contains(usage, "group shares need the gate to forward groups") {
		t.Errorf("the usage does not warn that group shares need the gate to forward groups:\n%s", usage)
	}
}

// ---- error paths

// Main fills in the HTTP client and the tunnel runner when the environment leaves them out.
func TestMainDefaultsClients(t *testing.T) {
	var out, errb bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errb, Version: "1.2.3", DefaultServer: "tunnels.layertwo.dev"}
	if c := Main([]string{"version"}, env); c != 0 {
		t.Fatalf("exit %d, stderr %q", c, errb.String())
	}
	if want := "tunnel 1.2.3 (server tunnels.layertwo.dev)\n"; out.String() != want {
		t.Errorf("stdout %q, want %q", out.String(), want)
	}

	// A command that goes through the defaulted HTTP client: pointed at a closed port so
	// it fails fast, the message names the server, proving Main supplied the client.
	t.Run("default http client", func(t *testing.T) {
		var out, errb bytes.Buffer
		env := Env{Stdout: &out, Stderr: &errb, ConfigDir: t.TempDir(), Version: "1.2.3", DefaultServer: "127.0.0.1:1"}
		if c := Main([]string{"login"}, env); c != 1 {
			t.Fatalf("exit %d, want 1; stderr %q", c, errb.String())
		}
		if !strings.Contains(errb.String(), "cannot reach https://127.0.0.1:1") {
			t.Errorf("stderr %q, want the default server named", errb.String())
		}
	})
}

// store falls back to the platform config dir when neither the environment nor ConfigDir names one.
func TestStoreUsesThePlatformConfigDir(t *testing.T) {
	t.Setenv("TUNNELS_CONFIG_DIR", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("UserConfigDir: %v", err)
	}
	s, err := store(Env{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if want := filepath.Join(base, "tunnels"); s.Dir != want {
		t.Errorf("dir = %q, want %q", s.Dir, want)
	}
}

// store says which piece of the environment is missing when the platform has no config dir either.
func TestStoreWithoutAConfigDir(t *testing.T) {
	t.Setenv("TUNNELS_CONFIG_DIR", "")
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AppData", "")
	t.Setenv("LocalAppData", "")
	if _, err := store(Env{}); err == nil || !strings.Contains(err.Error(), "no place for the login") {
		t.Errorf("store = %v, want a no-place error", err)
	}
}

// Every command that needs the login says the same thing when the machine has no config dir.
func TestCommandsWithoutAConfigDir(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		wantCode int
		want     string
	}{
		{"login", []string{"login"}, 1, "no place for the login"},
		{"up", []string{"up", "3000"}, 1, "no place for the login"},
		{"share", []string{"share", "bob"}, 1, "no place for the login"},
		{"unshare", []string{"unshare", "bob"}, 1, "no place for the login"},
		{"list", []string{"list"}, 1, "no place for the login"},
		{"logout", []string{"logout"}, 1, "no place for the login"},
		{"version", []string{"version"}, 0, "tunnel 1.2.3"}, // version never touches the config dir
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TUNNELS_CONFIG_DIR", "")
			t.Setenv("HOME", "")
			t.Setenv("XDG_CONFIG_HOME", "")
			t.Setenv("AppData", "")
			t.Setenv("LocalAppData", "")
			var out, errb bytes.Buffer
			env := Env{Stdout: &out, Stderr: &errb, ConfigDir: "", DefaultServer: "tunnels.layertwo.dev", Version: "1.2.3"}
			if c := Main(tc.args, env); c != tc.wantCode {
				t.Errorf("exit %d, want %d; stderr:\n%s", c, tc.wantCode, errb.String())
			}
			if tc.wantCode != 0 {
				if !strings.Contains(errb.String(), tc.want) {
					t.Errorf("stderr lacks %q:\n%s", tc.want, errb.String())
				}
			} else if !strings.Contains(out.String(), tc.want) {
				t.Errorf("stdout lacks %q:\n%s", tc.want, out.String())
			}
		})
	}
}

func TestLoginArgumentErrors(t *testing.T) {
	for _, args := range [][]string{{"login", "extra"}, {"login", "--bogus"}} {
		w := newWorld(t)
		if c := w.main(args...); c != 2 {
			t.Errorf("%q: exit %d, want 2", args, c)
		}
		if !strings.Contains(w.err.String(), "Usage") {
			t.Errorf("%q: no usage on stderr:\n%s", args, w.err)
		}
	}
}

// A login the person denies ends with the mock's access_denied, and nothing is kept.
func TestLoginDenied(t *testing.T) {
	w := newWorld(t)
	code := make(chan int, 1)
	go func() { code <- w.main("login", "--server", w.svc.URL) }()
	w.idp.Deny(waitFor(t, w.out, userCodeRE))

	if c := exitOf(t, code); c != 1 {
		t.Errorf("exit %d, want 1", c)
	}
	if !strings.Contains(w.err.String(), "the login was denied") {
		t.Errorf("stderr:\n%s", w.err)
	}
	if _, err := (auth.Store{Dir: w.dir}).Load(); !errors.Is(err, auth.ErrNotLoggedIn) {
		t.Errorf("tokens were kept after a denied login: %v", err)
	}
}

// A service that logged the person in but a machine that cannot write the tokens fails the login.
func TestLoginCannotSave(t *testing.T) {
	w := newWorld(t)
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := w.env()
	env.ConfigDir = file
	code := make(chan int, 1)
	go func() { code <- Main([]string{"login", "--server", w.svc.URL}, env) }()
	w.idp.Approve(waitFor(t, w.out, userCodeRE), "sub-alice")

	if c := exitOf(t, code); c != 1 {
		t.Errorf("exit %d, want 1", c)
	}
	if !strings.Contains(w.err.String(), "auth: mkdir") {
		t.Errorf("stderr:\n%s", w.err)
	}
}

// A stored login whose service is gone stops up before it starts anything.
func TestUpDiscoveryFails(t *testing.T) {
	w := newWorld(t)
	tok := w.loggedIn()
	tok.Server = "http://127.0.0.1:1"
	if err := (auth.Store{Dir: w.dir}).Save(tok); err != nil {
		t.Fatal(err)
	}
	if c := w.main("up", "3000"); c != 1 || !strings.Contains(w.err.String(), "cannot reach http://127.0.0.1:1") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
	if len(w.runs) != 0 {
		t.Error("the tunnel was started despite the discovery failure")
	}
}

// A directory where the CA bundle belongs makes the rename fail, so up stops before the tunnel.
func TestUpCannotWriteTheCABundle(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if err := os.Mkdir(filepath.Join(w.dir, "cacert.pem"), 0o700); err != nil {
		t.Fatal(err)
	}
	if c := w.main("up", "3000"); c != 1 || !strings.Contains(w.err.String(), "CA bundle") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
	if len(w.runs) != 0 {
		t.Error("the tunnel was started without a CA bundle")
	}
}

// The warning a running tunnel prints when a refresh fails says the tunnel is not over.
func TestWarnRefreshFailed(t *testing.T) {
	var b bytes.Buffer
	warnRefreshFailed(&b)(errors.New("the login has expired or was revoked; run: tunnel login"))
	want := "could not refresh your session, will try again: the login has expired or was revoked; run: tunnel login\n"
	if b.String() != want {
		t.Errorf("warning = %q, want %q", b.String(), want)
	}
}

func TestListArgumentErrors(t *testing.T) {
	w := newWorld(t)
	if c := w.main("list", "extra"); c != 2 || !strings.Contains(w.err.String(), "Usage") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

func TestListNotLoggedIn(t *testing.T) {
	w := newWorld(t)
	if c := w.main("list"); c != 1 || !strings.Contains(w.err.String(), "run: tunnel login") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

// list fails the same way as up when the stored service cannot be reached.
func TestListDiscoveryFails(t *testing.T) {
	w := newWorld(t)
	tok := w.loggedIn()
	tok.Server = "http://127.0.0.1:1"
	if err := (auth.Store{Dir: w.dir}).Save(tok); err != nil {
		t.Fatal(err)
	}
	if c := w.main("list"); c != 1 || !strings.Contains(w.err.String(), "cannot reach http://127.0.0.1:1") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

// A revoked login stops list at the refresh, before any API call.
func TestListRefreshFails(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.idp.RevokeUser("sub-alice")
	if c := w.main("list"); c != 1 || !strings.Contains(w.err.String(), "could not refresh your session (") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

// What the broker says about a share it refuses is what the person reads.
func TestShareAPIError(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.mu.Lock()
	w.putStatus = http.StatusForbidden
	w.mu.Unlock()
	if c := w.main("share", "bob"); c != 1 || !strings.Contains(w.err.String(), "you do not own that tunnel") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

func TestListSharesAPIError(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.mu.Lock()
	w.sharesStatus = http.StatusInternalServerError
	w.mu.Unlock()
	if c := w.main("list"); c != 1 || !strings.Contains(w.err.String(), "cannot list your shares") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

// A config dir that cannot be cleared fails logout instead of pretending it forgot the login.
func TestLogoutCannotClear(t *testing.T) {
	w := newWorld(t)
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TUNNELS_CONFIG_DIR", file)
	env := w.env()
	env.ConfigDir = ""
	if c := Main([]string{"logout"}, env); c != 1 || !strings.Contains(w.err.String(), "auth: remove") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}
