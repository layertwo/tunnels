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

	mu   sync.Mutex
	runs []tunnel.Options
	run  func(ctx context.Context, o tunnel.Options, onStatus func(tunnel.Status)) error
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
		LocalPort: 3000, TokenFile: filepath.Join(w.dir, "access-token"), CAFile: filepath.Join(w.dir, "cacert.pem")}
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
