package cli

import (
	"bytes"
	"context"
	"encoding/base64"
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

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/websocket"

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
	t         *testing.T
	idp       *mockidp.Server
	svc       *httptest.Server
	me        http.HandlerFunc
	dir       string
	out, err  *syncBuffer
	sshDomain string // when set, the bootstrap document advertises it

	mu             sync.Mutex
	runs           []tunnel.Options
	run            func(ctx context.Context, o tunnel.Options, onStatus func(tunnel.Status)) error
	shares         []auth.Share    // what GET /api/shares answers
	sharesStatus   int             // when non-zero, GET /api/shares answers this status instead
	putStatus      int             // when non-zero, PUT or DELETE /api/shares answers this status instead
	shareReq       []recordedShare // every PUT or DELETE /api/shares
	machines       []auth.Machine  // what GET /api/machines answers
	machinesStatus int             // when non-zero, the machine endpoints answer this status instead
	machineReq     []recordedMachine
}

// recordedMachine is one request to a machine endpoint.
type recordedMachine struct {
	method string
	path   string
	body   string
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
		doc := map[string]string{
			"issuer": w.idp.URL, "cli_client_id": mockidp.ClientID, "api_resource": mockidp.APIResource,
			"service_host": "tunnels.test", "sites_domain": "w.tunnels.test", "min_cli_version": "0.0.0",
		}
		if w.sshDomain != "" {
			doc["ssh_domain"] = w.sshDomain
		}
		json.NewEncoder(rw).Encode(doc)
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
	mux.HandleFunc("POST /api/machines", w.createMachine)
	mux.HandleFunc("GET /api/machines", w.listMachines)
	mux.HandleFunc("DELETE /api/machines/{handle}", w.deleteMachine)
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
		Handle: "alice", Server: w.svc.URL, SSHDomain: w.sshDomain}
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

// createMachine answers POST /api/machines like the broker: it registers the posted public key with
// the mock identity provider (as a federated credential) and returns the machine's client id.
func (w *world) createMachine(rw http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	w.mu.Lock()
	w.machineReq = append(w.machineReq, recordedMachine{method: r.Method, path: r.URL.Path, body: string(raw)})
	status := w.machinesStatus
	w.mu.Unlock()
	if status != 0 {
		rw.WriteHeader(status)
		io.WriteString(rw, `{"error":"the handle is taken"}`)
		return
	}
	var body struct {
		Handle    string          `json:"handle"`
		PublicKey json.RawMessage `json:"publicKey"`
	}
	var public jose.JSONWebKey
	json.Unmarshal(raw, &body)
	json.Unmarshal(body.PublicKey, &public)
	clientID := "machine-" + body.Handle
	w.idp.AddMachineKey(clientID, public)
	m := auth.Machine{Handle: body.Handle, ClientID: clientID}
	w.mu.Lock()
	w.machines = append(w.machines, m)
	w.mu.Unlock()
	rw.WriteHeader(http.StatusCreated)
	json.NewEncoder(rw).Encode(m)
}

// listMachines answers GET /api/machines.
func (w *world) listMachines(rw http.ResponseWriter, _ *http.Request) {
	w.mu.Lock()
	status, machines := w.machinesStatus, w.machines
	w.mu.Unlock()
	if status != 0 {
		rw.WriteHeader(status)
		io.WriteString(rw, `{"error":"machines unavailable, try again"}`)
		return
	}
	json.NewEncoder(rw).Encode(map[string]any{"machines": machines})
}

// deleteMachine answers DELETE /api/machines/{handle}.
func (w *world) deleteMachine(rw http.ResponseWriter, r *http.Request) {
	handle := r.PathValue("handle")
	w.mu.Lock()
	w.machineReq = append(w.machineReq, recordedMachine{method: r.Method, path: r.URL.Path})
	status := w.machinesStatus
	w.mu.Unlock()
	if status != 0 {
		rw.WriteHeader(status)
		io.WriteString(rw, `{"error":"no such machine"}`)
		return
	}
	w.mu.Lock()
	kept := w.machines[:0]
	for _, m := range w.machines {
		if m.Handle != handle {
			kept = append(kept, m)
		}
	}
	w.machines = kept
	w.mu.Unlock()
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

// In ssh mode PORT is the port on the target, --target picks the target host, and the print is the
// ssh host rather than a site URL.
func TestUpSSHPassesOptions(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.sshDomain = "ssh.tunnels.test"
	w.run = func(ctx context.Context, o tunnel.Options, onStatus func(tunnel.Status)) error {
		onStatus(tunnel.Status{Phase: "running"})
		return nil
	}
	if c := w.main("up", "22", "--ssh", "--name", "box1"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	if len(w.runs) != 1 {
		t.Fatalf("%d runs", len(w.runs))
	}
	o := w.runs[0]
	if !o.SSH || o.SSHTarget != "127.0.0.1" || o.SSHPort != 22 || o.SSHDomain != "ssh.tunnels.test" {
		t.Errorf("options = %+v, want the ssh fields", o)
	}
	if !strings.Contains(w.out.String(), "ssh alice-box1.ssh.tunnels.test") {
		t.Errorf("stdout lacks the ssh host:\n%s", w.out)
	}
}

// In ssh mode --target names another host the machine can reach.
func TestUpSSHTarget(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.sshDomain = "ssh.tunnels.test"
	w.run = func(ctx context.Context, o tunnel.Options, onStatus func(tunnel.Status)) error {
		onStatus(tunnel.Status{Phase: "running"})
		return nil
	}
	if c := w.main("up", "22", "--ssh", "--target", "192.168.1.9"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	if len(w.runs) != 1 || w.runs[0].SSHTarget != "192.168.1.9" {
		t.Errorf("runs = %+v, want a run with the target", w.runs)
	}
}

// --target is a bare host: the CLI says so before anything is dialled.
func TestUpSSHRejectsTargetWithPort(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if c := w.main("up", "22", "--ssh", "--target", "192.168.1.5:22"); c != 2 {
		t.Errorf("exit %d, want 2", c)
	}
	if !strings.Contains(w.err.String(), "192.168.1.5:22") {
		t.Errorf("stderr does not name the target:\n%s", w.err)
	}
	if len(w.runs) != 0 {
		t.Error("the tunnel was started with a bad target")
	}
}

func TestUpSSHRejectsTargetWithScheme(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if c := w.main("up", "22", "--ssh", "--target", "http://x"); c != 2 {
		t.Errorf("exit %d, want 2", c)
	}
	if !strings.Contains(w.err.String(), "http://x") {
		t.Errorf("stderr does not name the target:\n%s", w.err)
	}
	if len(w.runs) != 0 {
		t.Error("the tunnel was started with a bad target")
	}
}

func TestUpSSHRejectsEmptyTarget(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if c := w.main("up", "22", "--ssh", "--target", ""); c != 2 {
		t.Errorf("exit %d, want 2", c)
	}
	if !strings.Contains(w.err.String(), "is not a bare host") {
		t.Errorf("stderr does not name the target:\n%s", w.err)
	}
	if len(w.runs) != 0 {
		t.Error("the tunnel was started with an empty target")
	}
}

// The server has SSH off: publishing an ssh tunnel would be refused, so say so and stop.
func TestUpSSHServerDisabled(t *testing.T) {
	w := newWorld(t) // no ssh_domain in the bootstrap document
	w.loggedIn()
	if c := w.main("up", "22", "--ssh"); c != 2 {
		t.Errorf("exit %d, want 2", c)
	}
	if !strings.Contains(w.err.String(), "server has ssh disabled") {
		t.Errorf("stderr does not say ssh is disabled:\n%s", w.err)
	}
	if len(w.runs) != 0 {
		t.Error("the tunnel was started against a server with ssh off")
	}
}

// ---- ssh-config

// ssh-config prints the exact block to paste into ~/.ssh/config, for the named tunnel's label and,
// with no --name, for the default tunnel's.
func TestSSHConfigPrintsBlock(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"named", []string{"ssh-config", "--name", "box1"},
			"Host alice-box1\n\tHostName alice-box1.ssh.tunnels.test\n\tProxyCommand tunnel dial %h %p\n"},
		{"default", []string{"ssh-config"},
			"Host alice\n\tHostName alice.ssh.tunnels.test\n\tProxyCommand tunnel dial %h %p\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.loggedIn()
			w.sshDomain = "ssh.tunnels.test"
			if c := w.main(tc.args...); c != 0 {
				t.Fatalf("exit %d; stderr:\n%s", c, w.err)
			}
			if got := w.out.String(); got != tc.want {
				t.Errorf("stdout = %q, want %q", got, tc.want)
			}
		})
	}
}

// A --name the broker would refuse is refused here, like up does: the block is pasted into
// ~/.ssh/config, so a newline in the name must not smuggle in a second Host line.
func TestSSHConfigRejectsBadName(t *testing.T) {
	for _, name := range []string{"Box", "a_b", "default", "x\nHost evil"} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.loggedIn()
			w.sshDomain = "ssh.tunnels.test"
			if c := w.main("ssh-config", "--name", name); c != 2 {
				t.Errorf("exit %d, want 2", c)
			}
			if !strings.Contains(w.err.String(), "is not a tunnel name") {
				t.Errorf("stderr does not name the rule:\n%s", w.err)
			}
			if w.out.String() != "" {
				t.Errorf("stdout is not empty:\n%s", w.out)
			}
		})
	}
}

func TestSSHConfigNotLoggedIn(t *testing.T) {
	w := newWorld(t)
	if c := w.main("ssh-config", "--name", "box1"); c != 1 || !strings.Contains(w.err.String(), "tunnel login") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

// The server has SSH off: a block would point at a host that cannot work, so say so and print nothing.
func TestSSHConfigServerDisabled(t *testing.T) {
	w := newWorld(t) // no ssh_domain in the bootstrap document
	w.loggedIn()
	if c := w.main("ssh-config", "--name", "box1"); c != 2 {
		t.Errorf("exit %d, want 2", c)
	}
	if !strings.Contains(w.err.String(), "ssh disabled") {
		t.Errorf("stderr does not say ssh is disabled:\n%s", w.err)
	}
	if w.out.String() != "" {
		t.Errorf("stdout is not empty:\n%s", w.out)
	}
}

// ssh-config still discovers the server, so a stored login whose service is gone fails like the rest.
func TestSSHConfigDiscoveryFails(t *testing.T) {
	w := newWorld(t)
	tok := w.loggedIn()
	tok.Server = "http://127.0.0.1:1"
	if err := (auth.Store{Dir: w.dir}).Save(tok); err != nil {
		t.Fatal(err)
	}
	if c := w.main("ssh-config"); c != 1 || !strings.Contains(w.err.String(), "cannot reach http://127.0.0.1:1") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

func TestSSHConfigArgumentErrors(t *testing.T) {
	for _, args := range [][]string{{"ssh-config", "extra"}, {"ssh-config", "--bogus"}} {
		w := newWorld(t)
		w.loggedIn()
		if c := w.main(args...); c != 2 {
			t.Errorf("%q: exit %d, want 2", args, c)
		}
		if !strings.Contains(w.err.String(), "Usage") {
			t.Errorf("%q: no usage on stderr:\n%s", args, w.err)
		}
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

// A machine's private key is a credential: logout must remove it, not just the token.
func TestLogoutRemovesTheMachineKey(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	keyPath := filepath.Join(w.dir, auth.MachineKeyFile)
	key, err := auth.GenerateMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.SaveMachineKey(keyPath, key); err != nil {
		t.Fatal(err)
	}
	if c := w.main("logout"); c != 0 {
		t.Fatalf("exit %d", c)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the machine key survived logout: %v", err)
	}
}

// A key path that cannot be removed (a non-empty directory) is an error, not a silent success.
func TestLogoutCannotRemoveTheMachineKey(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	keyDir := filepath.Join(w.dir, auth.MachineKeyFile)
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := w.main("logout"); c != 1 || !strings.Contains(w.err.String(), "remove") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
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
	if c := w.main("share", "alice-blog", "bob"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	if len(w.shareReq) != 1 {
		t.Fatalf("%d share requests, want 1", len(w.shareReq))
	}
	got := w.shareReq[0]
	want := recordedShare{method: http.MethodPut, body: `{"handle":"alice","tunnel":"blog","kind":"user","grantee":"bob"}`,
		share: auth.Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "bob"}}
	if got != want {
		t.Errorf("request = %+v, want %+v", got, want)
	}
}

func TestShareGroup(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if c := w.main("share", "--group", "alice-blog", "family"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	if len(w.shareReq) != 1 || w.shareReq[0].share.Kind != "group" || w.shareReq[0].share.Handle != "alice" {
		t.Errorf("requests = %+v, want one with the handle and kind group", w.shareReq)
	}
}

// A label with no dash names the handle's default site.
func TestShareDefaultTunnel(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if c := w.main("share", "alice", "bob"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	if len(w.shareReq) != 1 || w.shareReq[0].share.Tunnel != "" || w.shareReq[0].share.Handle != "alice" {
		t.Errorf("requests = %+v, want one with handle alice and an empty tunnel", w.shareReq)
	}
}

// A machine's site is named by its own label: the handle before the dash is the machine, not the owner.
func TestShareMachineSite(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if c := w.main("share", "nas-blog", "bob"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	want := auth.Share{Handle: "nas", Tunnel: "blog", Kind: "user", Grantee: "bob"}
	if len(w.shareReq) != 1 || w.shareReq[0].share != want {
		t.Errorf("requests = %+v, want %+v", w.shareReq, want)
	}
}

func TestUnshare(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if c := w.main("unshare", "alice-blog", "bob"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	want := recordedShare{method: http.MethodDelete, body: `{"handle":"alice","tunnel":"blog","kind":"user","grantee":"bob"}`,
		share: auth.Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "bob"}}
	if len(w.shareReq) != 1 || w.shareReq[0] != want {
		t.Errorf("requests = %+v, want %+v", w.shareReq, want)
	}
}

func TestListPrints(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.shares = []auth.Share{
		{Handle: "alice", Tunnel: "", Kind: "user", Grantee: "bob"},
		{Handle: "nas", Tunnel: "blog", Kind: "group", Grantee: "family"},
	}
	if c := w.main("list"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	out := w.out.String()
	for _, want := range []string{"alice", "nas-blog", "bob", "group", "family"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
}

// --for turns into an absolute end a week out, and a Go duration works too.
func TestShareForADuration(t *testing.T) {
	for _, tt := range []struct {
		dur  string
		want time.Duration
	}{
		{"7d", 7 * 24 * time.Hour},
		{"24h", 24 * time.Hour},
	} {
		t.Run(tt.dur, func(t *testing.T) {
			w := newWorld(t)
			w.loggedIn()
			before := time.Now()
			if c := w.main("share", "--for", tt.dur, "alice", "bob"); c != 0 {
				t.Fatalf("exit %d; stderr:\n%s", c, w.err)
			}
			if len(w.shareReq) != 1 {
				t.Fatalf("%d share requests, want 1", len(w.shareReq))
			}
			got, want := w.shareReq[0].share.ExpiresAt, before.Add(tt.want)
			if d := got.Sub(want); d < -time.Minute || d > time.Minute {
				t.Errorf("expires_at = %v, want about %v", got, want)
			}
		})
	}
}

func TestShareForRejectsGarbage(t *testing.T) {
	for _, dur := range []string{"soon", "7d5", "xd", "d", "5"} {
		t.Run(dur, func(t *testing.T) {
			w := newWorld(t)
			w.loggedIn()
			if c := w.main("share", "--for", dur, "alice", "bob"); c != 2 {
				t.Errorf("exit %d, want 2", c)
			}
			if !strings.Contains(w.err.String(), "Usage: tunnel") {
				t.Errorf("no usage line on stderr:\n%s", w.err)
			}
			if len(w.shareReq) != 0 {
				t.Errorf("a request was sent for a bad duration: %+v", w.shareReq)
			}
		})
	}
}

// list prints a share's end, or "never" when it has none.
func TestListShowsExpiry(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	expires := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	w.shares = []auth.Share{
		{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "bob", ExpiresAt: expires},
		{Handle: "alice", Tunnel: "", Kind: "user", Grantee: "carol"},
	}
	if c := w.main("list"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	out := w.out.String()
	if !strings.Contains(out, expires.Format(time.RFC3339)) {
		t.Errorf("stdout lacks the expiry %s:\n%s", expires.Format(time.RFC3339), out)
	}
	if !strings.Contains(out, "never") {
		t.Errorf("stdout lacks \"never\" for a share without an end:\n%s", out)
	}
}

func TestShareNotLoggedIn(t *testing.T) {
	w := newWorld(t)
	if c := w.main("share", "alice", "bob"); c != 1 || !strings.Contains(w.err.String(), "run: tunnel login") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

func TestShareArgumentErrors(t *testing.T) {
	for _, args := range [][]string{
		{"share"},
		{"share", "alice"},                 // no grantee
		{"share", "alice", "bob", "extra"}, // too many
		{"share", "Blog", "bob"},           // a label is lowercase
		{"share", "a_b", "bob"},            // not a label
		{"share", "alice-", "bob"},         // a dash with no tunnel name
		{"share", "alice-default", "bob"},  // "default" is not a tunnel name
		{"share", "--bogus", "bob"},
		{"unshare"},
		{"unshare", "alice", "bob", "extra"},
		{"unshare", "--for", "7d", "alice", "bob"},
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
		{"ssh-config", []string{"ssh-config"}, 1, "no place for the login"},
		{"dial", []string{"dial", "host", "22"}, 1, "no place for the login"},
		{"share", []string{"share", "alice", "bob"}, 1, "no place for the login"},
		{"unshare", []string{"unshare", "alice", "bob"}, 1, "no place for the login"},
		{"list", []string{"list"}, 1, "no place for the login"},
		{"machine create", []string{"machine", "create", "nas"}, 1, "no place for the login"},
		{"machine list", []string{"machine", "list"}, 1, "no place for the login"},
		{"machine remove", []string{"machine", "remove", "nas"}, 1, "no place for the login"},
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
	if c := w.main("share", "alice", "bob"); c != 1 || !strings.Contains(w.err.String(), "you do not own that tunnel") {
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

// ---- machine

// machine create generates a key pair on this machine, sends only its public half, and makes the
// config dir the machine's login.
func TestMachineCreate(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if c := w.main("machine", "create", "nas"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	if len(w.machineReq) != 1 {
		t.Fatalf("%d machine requests, want 1", len(w.machineReq))
	}
	req := w.machineReq[0]
	if req.method != http.MethodPost || req.path != "/api/machines" {
		t.Errorf("asked %s %s, want POST /api/machines", req.method, req.path)
	}
	if strings.Contains(req.body, `"d"`) {
		t.Error("the request body carries the private key")
	}

	keyPath := filepath.Join(w.dir, auth.MachineKeyFile)
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"d"`) {
		t.Error("the key file has no private component")
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(keyPath); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v, want mode 0600", keyPath, fi, err)
		}
	}
	// The private component never reaches the log.
	var key map[string]string
	json.Unmarshal(raw, &key)
	for _, out := range []*syncBuffer{w.out, w.err} {
		if strings.Contains(out.String(), key["d"]) {
			t.Errorf("the output contains the private key:\n%s", out)
		}
	}

	tok, err := (auth.Store{Dir: w.dir}).Load()
	if err != nil || tok.ClientID != "machine-nas" || tok.MachineKey != keyPath || tok.Handle != "nas" || tok.Server != w.svc.URL {
		t.Errorf("stored %+v, %v", tok, err)
	}
	if tok.RefreshToken != "" {
		t.Errorf("a machine login stored a secret: %+v", tok)
	}
	if !strings.Contains(w.out.String(), "nas") {
		t.Errorf("stdout lacks the machine's handle:\n%s", w.out)
	}
}

// After machine create, up publishes as the machine: it signs an assertion and exchanges it for a
// token, with no passkey and no secret.
func TestMachineCreateThenUp(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.run = func(_ context.Context, _ tunnel.Options, onStatus func(tunnel.Status)) error {
		onStatus(tunnel.Status{Phase: "running"})
		return nil
	}
	if c := w.main("machine", "create", "nas"); c != 0 {
		t.Fatalf("machine create: exit %d; stderr:\n%s", c, w.err)
	}
	if c := w.main("up", "3000"); c != 0 {
		t.Fatalf("up: exit %d; stderr:\n%s", c, w.err)
	}
	if len(w.runs) != 1 || w.runs[0].Handle != "nas" {
		t.Errorf("runs = %+v, want one as nas", w.runs)
	}
	if raw, _ := os.ReadFile((auth.Store{Dir: w.dir}).AccessTokenPath()); len(raw) == 0 {
		t.Error("up left no access token")
	}
}

// A machine create that cannot write the key fails before it calls the broker.
func TestMachineCreateKeySaveFails(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	if err := os.Mkdir(filepath.Join(w.dir, auth.MachineKeyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if c := w.main("machine", "create", "nas"); c != 1 || !strings.Contains(w.err.String(), "machine key") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
	if len(w.machineReq) != 0 {
		t.Errorf("the broker was called without a key: %+v", w.machineReq)
	}
}

// A machine create that the broker refuses leaves no key behind.
func TestMachineCreateRefused(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.mu.Lock()
	w.machinesStatus = http.StatusConflict
	w.mu.Unlock()
	if c := w.main("machine", "create", "nas"); c != 1 || !strings.Contains(w.err.String(), "taken") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
	if _, err := os.Stat(filepath.Join(w.dir, auth.MachineKeyFile)); !os.IsNotExist(err) {
		t.Errorf("the key file was kept after a refused create: %v", err)
	}
}

func TestMachineList(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.mu.Lock()
	w.machines = []auth.Machine{{Handle: "nas", ClientID: "machine-nas"}, {Handle: "pi", ClientID: "machine-pi"}}
	w.mu.Unlock()
	if c := w.main("machine", "list"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	for _, want := range []string{"nas", "machine-nas", "pi", "machine-pi"} {
		if !strings.Contains(w.out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, w.out)
		}
	}
}

func TestMachineRemove(t *testing.T) {
	w := newWorld(t)
	w.loggedIn()
	w.mu.Lock()
	w.machines = []auth.Machine{{Handle: "nas", ClientID: "machine-nas"}}
	w.mu.Unlock()
	if c := w.main("machine", "remove", "nas"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	if len(w.machineReq) != 1 || w.machineReq[0].method != http.MethodDelete || w.machineReq[0].path != "/api/machines/nas" {
		t.Errorf("requests = %+v, want one DELETE /api/machines/nas", w.machineReq)
	}
	if w.machines != nil && len(w.machines) != 0 {
		t.Errorf("machines = %+v, want none", w.machines)
	}
	if !strings.Contains(w.out.String(), "nas") {
		t.Errorf("stdout lacks the machine's handle:\n%s", w.out)
	}
}

// Removing the machine this box is logged in as clears the local login and its private key too.
func TestMachineRemoveClearsTheLocalMachineLogin(t *testing.T) {
	w := newWorld(t)
	tok := w.loggedIn()
	tok.Handle = "nas" // this box is logged in as the machine
	if err := (auth.Store{Dir: w.dir}).Save(tok); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(w.dir, auth.MachineKeyFile)
	key, err := auth.GenerateMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.SaveMachineKey(keyPath, key); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	w.machines = []auth.Machine{{Handle: "nas", ClientID: "machine-nas"}}
	w.mu.Unlock()

	if c := w.main("machine", "remove", "nas"); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	if _, err := (auth.Store{Dir: w.dir}).Load(); !errors.Is(err, auth.ErrNotLoggedIn) {
		t.Errorf("the local login survived: %v", err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the machine key survived removal: %v", err)
	}
}

func TestMachineAPIErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		status int
		want   string
	}{
		{"list", []string{"machine", "list"}, http.StatusServiceUnavailable, "machines unavailable, try again"},
		{"remove", []string{"machine", "remove", "nas"}, http.StatusNotFound, "no such machine"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.loggedIn()
			w.mu.Lock()
			w.machinesStatus = tc.status
			w.mu.Unlock()
			if c := w.main(tc.args...); c != 1 || !strings.Contains(w.err.String(), tc.want) {
				t.Errorf("exit %d, stderr:\n%s", c, w.err)
			}
		})
	}
}

func TestMachineNotLoggedIn(t *testing.T) {
	for _, args := range [][]string{{"machine", "create", "nas"}, {"machine", "list"}, {"machine", "remove", "nas"}} {
		w := newWorld(t)
		if c := w.main(args...); c != 1 || !strings.Contains(w.err.String(), "run: tunnel login") {
			t.Errorf("%q: exit %d, stderr:\n%s", args, c, w.err)
		}
	}
}

func TestMachineArgumentErrors(t *testing.T) {
	for _, args := range [][]string{
		{"machine"},
		{"machine", "frobnicate"},
		{"machine", "create"},
		{"machine", "create", "nas", "extra"},
		{"machine", "create", "NAS"},
		{"machine", "create", "n"},
		{"machine", "remove"},
		{"machine", "remove", "NAS"},
		{"machine", "list", "extra"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			w := newWorld(t)
			w.loggedIn()
			if c := w.main(args...); c != 2 {
				t.Errorf("exit %d, want 2", c)
			}
			if !strings.Contains(w.err.String(), "tunnel machine") {
				t.Errorf("no usage line on stderr:\n%s", w.err)
			}
		})
	}
}

// ---- dial

// wsServer upgrades a WebSocket when mayUpgrade allows it and otherwise answers 401, then echoes
// every message until the connection ends. It stands in for the broker's ssh bridge.
func wsServer(t *testing.T, mayUpgrade func(*http.Request) bool) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !mayUpgrade(r) {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, err := up.Upgrade(rw, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if conn.WriteMessage(mt, msg) != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// wsURL is srv's address as the dialer's ws:// URL.
func wsURL(srv *httptest.Server) string { return "ws" + strings.TrimPrefix(srv.URL, "http") }

// The token travels only in the Authorization header, and the handshake names the CLI.
func TestDialHeader(t *testing.T) {
	h := dialHeader("tok", "1.2.3")
	if h.Get("Authorization") != "Bearer tok" || h.Get("User-Agent") != "tunnels/1.2.3" {
		t.Errorf("header = %v", h)
	}
}

// dialOIDC is the identity provider a 401 refresh needs, as Discover would describe it.
func (w *world) dialOIDC(hc *http.Client) auth.OIDC {
	return auth.OIDC{Issuer: w.idp.URL, ClientID: mockidp.ClientID, Resource: mockidp.APIResource, HTTP: hc}
}

// oidcSourceOf is an oidcSource that always answers o: in these tests a refresh never discovers.
func oidcSourceOf(o auth.OIDC) oidcSource {
	return func(context.Context) (auth.OIDC, error) { return o, nil }
}

// dialToken presents the stored token while it is still valid and refreshes it only when it is not:
// refreshing on every dial would rotate a token ssh does not need.
func TestDialTokenRefreshesOnlyWhenStale(t *testing.T) {
	for _, tc := range []struct {
		name        string
		token       func(*world) string
		wantRefresh bool
	}{
		{"valid", func(w *world) string { return w.idp.Issue("sub-alice", mockidp.IssueOpts{TTL: time.Hour}) }, false},
		{"expired", func(w *world) string { return w.idp.Issue("sub-alice", mockidp.IssueOpts{TTL: -time.Hour}) }, true},
		{"unreadable", func(*world) string { return "garbage" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			tok := auth.Tokens{AccessToken: tc.token(w), RefreshToken: w.idp.IssueRefreshToken("sub-alice"), Handle: "alice", Server: w.svc.URL}
			s := auth.Store{Dir: w.dir}
			if err := s.Save(tok); err != nil {
				t.Fatal(err)
			}
			env := w.env()
			got, err := dialToken(context.Background(), s, oidcSourceOf(w.dialOIDC(env.HTTP)), tok)
			if err != nil {
				t.Fatalf("dialToken: %v", err)
			}
			if refreshed := got != tok.AccessToken; refreshed != tc.wantRefresh {
				t.Errorf("refreshed = %v, want %v (token %q)", refreshed, tc.wantRefresh, got)
			}
			after, err := s.Load()
			if err != nil {
				t.Fatal(err)
			}
			if (after.AccessToken != tok.AccessToken) != tc.wantRefresh {
				t.Errorf("stored token refreshed = %v, want %v", after.AccessToken != tok.AccessToken, tc.wantRefresh)
			}
		})
	}
}

// A refresh that the provider refuses is the one error dialToken reports.
func TestDialTokenRefreshFails(t *testing.T) {
	w := newWorld(t)
	tok := auth.Tokens{AccessToken: w.idp.Issue("sub-alice", mockidp.IssueOpts{TTL: -time.Hour}),
		RefreshToken: w.idp.IssueRefreshToken("sub-alice"), Handle: "alice", Server: w.svc.URL}
	s := auth.Store{Dir: w.dir}
	if err := s.Save(tok); err != nil {
		t.Fatal(err)
	}
	w.idp.RevokeUser("sub-alice")
	env := w.env()
	if _, err := dialToken(context.Background(), s, oidcSourceOf(w.dialOIDC(env.HTTP)), tok); err == nil {
		t.Error("dialToken returned a token after a refused refresh")
	}
}

// jwtExpiry reads exp out of a token without verifying it; anything it cannot read is stale.
func TestJWTExpiry(t *testing.T) {
	payload := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, tc := range []struct {
		name  string
		token string
		want  time.Time
	}{
		{"exp", "a." + payload(`{"exp":1234567890}`) + ".c", time.Unix(1234567890, 0)},
		{"no exp", "a." + payload(`{"sub":"alice"}`) + ".c", time.Time{}},
		{"zero exp", "a." + payload(`{"exp":0}`) + ".c", time.Time{}},
		{"bad json", "a." + payload("not json") + ".c", time.Time{}},
		{"bad base64", "a.!!!.c", time.Time{}},
		{"not a jwt", "garbage", time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := jwtExpiry(tc.token); !got.Equal(tc.want) {
				t.Errorf("jwtExpiry(%q) = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}

// rootPool reads the CA bundle WriteCABundle writes; a file it cannot read or that holds no
// certificate is an error, not an empty pool that trusts nothing.
func TestRootPool(t *testing.T) {
	if _, err := rootPool(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("rootPool accepted a missing file")
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rootPool(empty); err == nil {
		t.Error("rootPool accepted a file with no certificates")
	}
	dir := t.TempDir()
	ca, err := tunnel.WriteCABundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if pool, err := rootPool(ca); err != nil || pool == nil {
		t.Errorf("rootPool(%s) = %v, %v", ca, pool, err)
	}
}

// The dial command pipes this process's stdin and stdout to the WebSocket; only the TLS wrapper is
// left to the e2e task, because the data route is on 443 and a test cannot bind it.
func TestDialStreamPipes(t *testing.T) {
	w := newWorld(t)
	tok := w.loggedIn()
	srv := wsServer(t, func(r *http.Request) bool {
		return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == tok.AccessToken
	})
	pr, pw := io.Pipe()
	env := w.env()
	env.Stdin = pr
	code := make(chan int, 1)
	go func() {
		code <- dialStream(context.Background(), env, websocket.DefaultDialer, wsURL(srv), auth.Store{Dir: w.dir}, oidcSourceOf(oidcFor(auth.Bootstrap{}, env.HTTP)), tok)
	}()

	if _, err := pw.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, w.out, regexp.MustCompile("hello"))
	if got := w.out.String(); got != "hello\n" {
		t.Errorf("stdout = %q, want %q", got, "hello\n")
	}
	_ = pw.Close()
	if c := exitOf(t, code); c != 0 {
		t.Errorf("exit %d; stderr:\n%s", c, w.err)
	}
}

// A 401 handshake means the token aged between the check and the dial: refresh once and retry.
func TestDialStreamRefreshesOn401(t *testing.T) {
	w := newWorld(t)
	tok := w.loggedIn()
	srv := wsServer(t, func(r *http.Request) bool {
		return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != tok.AccessToken
	})
	env := w.env()
	env.Stdin = strings.NewReader("")
	if c := dialStream(context.Background(), env, websocket.DefaultDialer, wsURL(srv), auth.Store{Dir: w.dir}, oidcSourceOf(w.dialOIDC(env.HTTP)), tok); c != 0 {
		t.Fatalf("exit %d; stderr:\n%s", c, w.err)
	}
	after, err := (auth.Store{Dir: w.dir}).Load()
	if err != nil || after.AccessToken == tok.AccessToken {
		t.Errorf("the 401 did not refresh the stored token: %+v, %v", after, err)
	}
}

// A second 401 after the refresh ends the connection with what to run.
func TestDialStreamRefusedAfterRefresh(t *testing.T) {
	w := newWorld(t)
	tok := w.loggedIn()
	srv := wsServer(t, func(*http.Request) bool { return false })
	env := w.env()
	if c := dialStream(context.Background(), env, websocket.DefaultDialer, wsURL(srv), auth.Store{Dir: w.dir}, oidcSourceOf(w.dialOIDC(env.HTTP)), tok); c != 1 {
		t.Errorf("exit %d, want 1", c)
	}
	if !strings.Contains(w.err.String(), "run: tunnel login") {
		t.Errorf("stderr:\n%s", w.err)
	}
}

// A refresh failing after a 401 is reported like any other failed refresh, not as a refused login.
func TestDialStreamRefreshAfter401Fails(t *testing.T) {
	w := newWorld(t)
	tok := w.loggedIn()
	w.idp.RevokeUser("sub-alice")
	srv := wsServer(t, func(*http.Request) bool { return false })
	env := w.env()
	if c := dialStream(context.Background(), env, websocket.DefaultDialer, wsURL(srv), auth.Store{Dir: w.dir}, oidcSourceOf(w.dialOIDC(env.HTTP)), tok); c != 1 {
		t.Errorf("exit %d, want 1", c)
	}
	if !strings.Contains(w.err.String(), "could not refresh your session") {
		t.Errorf("stderr:\n%s", w.err)
	}
}

// A stale stored token with a refused refresh never reaches the socket.
func TestDialStreamRefreshFails(t *testing.T) {
	w := newWorld(t)
	tok := w.loggedIn()
	tok.AccessToken = w.idp.Issue("sub-alice", mockidp.IssueOpts{TTL: -time.Hour})
	if err := (auth.Store{Dir: w.dir}).Save(tok); err != nil {
		t.Fatal(err)
	}
	w.idp.RevokeUser("sub-alice")
	env := w.env()
	if c := dialStream(context.Background(), env, websocket.DefaultDialer, wsURL(wsServer(t, func(*http.Request) bool { return true })),
		auth.Store{Dir: w.dir}, oidcSourceOf(w.dialOIDC(env.HTTP)), tok); c != 1 {
		t.Errorf("exit %d, want 1", c)
	}
	if !strings.Contains(w.err.String(), "could not refresh your session") {
		t.Errorf("stderr:\n%s", w.err)
	}
}

func TestDialArgumentErrors(t *testing.T) {
	for _, args := range [][]string{
		{"dial"},
		{"dial", "host"},
		{"dial", "host", "22", "extra"},
		{"dial", "host", "abc"},
		{"dial", "host", "0"},
		{"dial", "host", "65536"},
		{"dial", "--bogus", "host", "22"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			w := newWorld(t)
			w.loggedIn()
			if c := w.main(args...); c != 2 {
				t.Errorf("exit %d, want 2", c)
			}
			if !strings.Contains(w.err.String(), "tunnel dial HOST PORT") {
				t.Errorf("no usage line on stderr:\n%s", w.err)
			}
		})
	}
}

func TestDialNotLoggedIn(t *testing.T) {
	w := newWorld(t)
	if c := w.main("dial", "host", "22"); c != 1 || !strings.Contains(w.err.String(), "run: tunnel login") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

// dial discovers the server only when it must refresh: a fresh token dials with no .well-known
// request, so a broken one cannot fail a dial that does not refresh; a stale token still surfaces
// the discovery failure. The ssh host is checked against the domain stored at login, so a valid
// dial never needs the bootstrap.
func TestDialDiscoveryFails(t *testing.T) {
	w := newWorld(t)
	w.sshDomain = "ssh.tunnels.test"
	tok := w.loggedIn()
	tok.Server = "http://127.0.0.1:1"
	if err := (auth.Store{Dir: w.dir}).Save(tok); err != nil {
		t.Fatal(err)
	}
	// Fresh: TLS to the (unresolvable) host is as far as it gets; no discovery is tried.
	if c := w.main("dial", "alice.ssh.tunnels.test", "22"); c != 1 || strings.Contains(w.err.String(), "cannot reach") {
		t.Errorf("fresh token: exit %d, stderr:\n%s", c, w.err)
	}

	// Stale: the refresh needs the provider, so the broken discovery is surfaced.
	tok.AccessToken = w.idp.Issue("sub-alice", mockidp.IssueOpts{TTL: -time.Hour})
	if err := (auth.Store{Dir: w.dir}).Save(tok); err != nil {
		t.Fatal(err)
	}
	w.err = &syncBuffer{}
	if c := w.main("dial", "alice.ssh.tunnels.test", "22"); c != 1 || !strings.Contains(w.err.String(), "cannot reach http://127.0.0.1:1") {
		t.Errorf("stale token: exit %d, stderr:\n%s", c, w.err)
	}
}

// A stale token is refreshed (which discovers the provider) before the socket is opened.
func TestDialRefreshesWhenStale(t *testing.T) {
	w := newWorld(t)
	w.sshDomain = "ssh.tunnels.test"
	before := w.loggedIn()
	before.AccessToken = w.idp.Issue("sub-alice", mockidp.IssueOpts{TTL: -time.Hour})
	if err := (auth.Store{Dir: w.dir}).Save(before); err != nil {
		t.Fatal(err)
	}
	if c := w.main("dial", "alice.ssh.tunnels.test", "22"); c != 1 {
		t.Errorf("exit %d, want 1", c)
	}
	after, err := (auth.Store{Dir: w.dir}).Load()
	if err != nil || after.AccessToken == before.AccessToken {
		t.Errorf("the stale token was not refreshed before dialling: %+v, %v", after, err)
	}
}

// dial refuses to send the access token to a host that is not one of this service's ssh hosts; a
// host carrying a port is refused the same way rather than reaching the URL parser.
func TestDialRefusesForeignHost(t *testing.T) {
	for _, host := range []string{"evil.example", "alice.other.test", "alice.ssh.tunnels.test:22", "ssh.tunnels.test"} {
		t.Run(host, func(t *testing.T) {
			w := newWorld(t)
			w.sshDomain = "ssh.tunnels.test"
			w.loggedIn()
			if c := w.main("dial", host, "22"); c != 2 {
				t.Errorf("exit %d, want 2", c)
			}
			if !strings.Contains(w.err.String(), host) {
				t.Errorf("stderr does not name the host:\n%s", w.err)
			}
			if !strings.Contains(w.err.String(), "Usage: tunnel dial") {
				t.Errorf("stderr has no dial usage line:\n%s", w.err)
			}
		})
	}
}

// A login made before the ssh domain was stored has no stored domain: dial falls back to the live
// bootstrap rather than rejecting every host. A bootstrap that names none, or that cannot be
// reached, says what to do.
func TestDialWithoutAStoredSSHDomain(t *testing.T) {
	t.Run("bootstrap advertises it", func(t *testing.T) {
		w := newWorld(t)
		w.loggedIn()                     // the stored login has no ssh domain
		w.sshDomain = "ssh.tunnels.test" // but the live service now advertises one
		if c := w.main("dial", "alice.ssh.tunnels.test", "22"); c != 1 {
			t.Errorf("exit %d, want 1 (the connection, not the argument)", c)
		}
		if strings.Contains(w.err.String(), "is not an ssh host") || strings.Contains(w.err.String(), "Usage: tunnel dial") {
			t.Errorf("dial rejected a host although the bootstrap named the domain:\n%s", w.err)
		}
	})

	t.Run("bootstrap has none", func(t *testing.T) {
		w := newWorld(t)
		w.loggedIn()
		if c := w.main("dial", "alice.ssh.tunnels.test", "22"); c != 1 {
			t.Errorf("exit %d, want 1", c)
		}
		if !strings.Contains(w.err.String(), "tunnel login") {
			t.Errorf("stderr does not say to log in again:\n%s", w.err)
		}
	})

	t.Run("server unreachable", func(t *testing.T) {
		w := newWorld(t)
		tok := w.loggedIn()
		tok.Server = "http://127.0.0.1:1"
		if err := (auth.Store{Dir: w.dir}).Save(tok); err != nil {
			t.Fatal(err)
		}
		if c := w.main("dial", "alice.ssh.tunnels.test", "22"); c != 1 || !strings.Contains(w.err.String(), "cannot reach http://127.0.0.1:1") {
			t.Errorf("exit %d, stderr:\n%s", c, w.err)
		}
	})
}

// A directory where the CA bundle belongs makes the rename fail, so dial never opens a socket.
func TestDialCannotWriteTheCABundle(t *testing.T) {
	w := newWorld(t)
	w.sshDomain = "ssh.tunnels.test"
	w.loggedIn()
	if err := os.Mkdir(filepath.Join(w.dir, "cacert.pem"), 0o700); err != nil {
		t.Fatal(err)
	}
	if c := w.main("dial", "alice.ssh.tunnels.test", "22"); c != 1 || !strings.Contains(w.err.String(), "CA bundle") {
		t.Errorf("exit %d, stderr:\n%s", c, w.err)
	}
}

// The command dials the data route on 443, whatever PORT ssh passed; a host that answers nothing is
// a connection error, not a crash. The ssh domain is matched case-insensitively, as the broker does.
func TestDialUnreachableHost(t *testing.T) {
	w := newWorld(t)
	w.sshDomain = "ssh.tunnels.test"
	w.loggedIn()
	if c := w.main("dial", "Alice.SSH.Tunnels.Test", "22"); c != 1 {
		t.Errorf("exit %d, want 1", c)
	}
	if w.err.String() == "" {
		t.Error("no error on stderr for an unreachable host")
	}
}
