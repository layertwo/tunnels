//go:build e2e

// Package e2e runs the whole thing: a real frps built from the pinned module, the broker with its
// real identity provider client, store and dashboard client, and the frp client the CLI embeds.
// It needs TEST_DATABASE_URL (Postgres) and skips without it.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatedier/frp/pkg/msg"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/hashicorp/yamux"
	"github.com/jackc/pgx/v5"

	"github.com/layertwo/tunnels/internal/auth"
	"github.com/layertwo/tunnels/internal/broker"
	"github.com/layertwo/tunnels/internal/frpsapi"
	"github.com/layertwo/tunnels/internal/httpx"
	"github.com/layertwo/tunnels/internal/idp"
	"github.com/layertwo/tunnels/internal/mockidp"
	"github.com/layertwo/tunnels/internal/store"
	"github.com/layertwo/tunnels/internal/tunnel"
)

const (
	secret       = "e2e-plugin-secret-0123456789abcdef"
	sites        = "w.test"
	dashUser     = "admin"
	dashPassword = "dash-pw"
	ua           = "tunnels-e2e/1"
)

var frpsBin string

func TestMain(m *testing.M) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		fmt.Println("skipping the end-to-end test: TEST_DATABASE_URL is not set")
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "tunnels-e2e-")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	frpsBin = filepath.Join(dir, "frps")
	if runtime.GOOS == "windows" {
		frpsBin += ".exe"
	}
	// The same source as the frps image: the module version go.mod pins.
	build := exec.Command("go", "build", "-tags", "noweb", "-o", frpsBin, "github.com/fatedier/frp/cmd/frps")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Println("build frps:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// schemaURL makes a schema for the test alone and returns the database URL that uses it.
func schemaURL(t *testing.T) string {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	schema := fmt.Sprintf("e2e_%d", time.Now().UnixNano())
	exec := func(sql string) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, base)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec("create schema " + schema)
	t.Cleanup(func() { exec("drop schema " + schema + " cascade") })
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func eventually(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("%s: not within %v", what, d)
}

// stack is one frps with its broker, the mock identity provider and a web server to publish.
type stack struct {
	mock    *mockidp.Server
	bind    int
	vhost   string // frps's http address
	dash    string // frps's dashboard
	plugin  string // the broker's plugin URL
	backend int    // the local port the tunnels publish
	frps    *frpsapi.Client

	mu        sync.Mutex
	proto     string // X-Forwarded-Proto of the last request the backend got
	brokerLog *lockedBuffer
}

func newStack(t *testing.T, maxTunnels int) *stack {
	t.Helper()
	s := &stack{mock: mockidp.New(t)}
	s.mock.AddUser(mockidp.User{Sub: "sub-alice", Username: "Alice", Groups: []string{"tunnels-creators"}})
	s.mock.AddUser(mockidp.User{Sub: "sub-bob", Username: "Bob", Groups: []string{"tunnels-creators"}})
	s.mock.AddUser(mockidp.User{Sub: "sub-carol", Username: "Carol", Groups: []string{"tunnels-viewers"}})

	users, err := store.Open(t.Context(), schemaURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(users.Close)
	provider, err := idp.New(t.Context(), s.mock.URL, mockidp.APIResource, ua, "", "")
	if err != nil {
		t.Fatal(err)
	}
	bind, vhost, dash := freePort(t), freePort(t), freePort(t)
	s.bind, s.vhost, s.dash = bind, fmt.Sprintf("127.0.0.1:%d", vhost), fmt.Sprintf("http://127.0.0.1:%d", dash)
	s.frps = frpsapi.New(s.dash, dashUser, dashPassword, ua)

	brokerLog := &lockedBuffer{}
	s.brokerLog = brokerLog
	b := httptest.NewServer(broker.NewHandler(broker.Config{
		ServiceHost: "tunnels.test", SitesDomain: sites, Issuer: s.mock.URL, APIResource: mockidp.APIResource,
		CreatorsGroup: "tunnels-creators", CLIClientID: mockidp.ClientID, MinCLIVersion: "0.0.0",
		PluginSecret: secret, MaxTunnelsPerUser: maxTunnels, BandwidthLimit: "10MB", Reserved: []string{"admin"},
	}, broker.Deps{IdP: provider, Verifier: provider, Users: users, Shares: users, Frps: s.frps, Log: slog.New(slog.NewJSONHandler(brokerLog, nil))}))
	t.Cleanup(b.Close)
	s.plugin = b.URL + "/plugin/" + secret

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.proto = r.Header.Get("X-Forwarded-Proto")
		s.mu.Unlock()
		io.WriteString(w, "hello")
	}))
	t.Cleanup(backend.Close)
	s.backend = backend.Listener.Addr().(*net.TCPAddr).Port

	conf, _ := json.Marshal(map[string]any{
		"bindAddr": "127.0.0.1", "bindPort": bind, "vhostHTTPPort": vhost, "subDomainHost": sites,
		"auth": map[string]any{
			"method": "oidc", "additionalScopes": []string{"HeartBeats", "NewWorkConns"},
			"oidc": map[string]any{"issuer": s.mock.URL, "audience": mockidp.APIResource},
		},
		"transport": map[string]any{"heartbeatTimeout": 90},
		"webServer": map[string]any{"addr": "127.0.0.1", "port": dash, "user": dashUser, "password": dashPassword},
		"httpPlugins": []any{map[string]any{
			"name": "broker", "addr": b.URL, "path": "/plugin/" + secret, "ops": []string{"Login", "NewProxy", "CloseProxy"},
		}},
	})
	path := filepath.Join(t.TempDir(), "frps.json")
	if err := os.WriteFile(path, conf, 0o600); err != nil {
		t.Fatal(err)
	}
	frpsLog := &lockedBuffer{}
	cmd := exec.Command(frpsBin, "-c", path)
	cmd.Stdout, cmd.Stderr = frpsLog, frpsLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("frps:\n%s\nbroker:\n%s", frpsLog, brokerLog)
		}
	})
	eventually(t, 15*time.Second, "frps is up", func() bool {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", bind), time.Second)
		if err != nil {
			return false
		}
		c.Close()
		req, _ := http.NewRequest("GET", s.dash+"/healthz", nil)
		req.SetBasicAuth(dashUser, dashPassword)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	return s
}

// run is one tunnel.Run, as `tunnel up` starts it.
type run struct {
	status  chan tunnel.Status
	stopped chan struct{}
	err     error // set once stopped is closed
}

// up publishes the backend as handle's tunnel name with token in the token file.
func (s *stack) up(t *testing.T, token, handle, name string) *run {
	t.Helper()
	file := filepath.Join(t.TempDir(), "access-token")
	if err := os.WriteFile(file, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	return s.upWithFile(t, file, handle, name)
}

func (s *stack) upWithFile(t *testing.T, tokenFile, handle, name string) *run {
	t.Helper()
	r := &run{status: make(chan tunnel.Status, 64), stopped: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		r.err = tunnel.Run(ctx, tunnel.Options{
			ServerHost: "127.0.0.1", ServerPort: s.bind, Protocol: "tcp",
			Handle: handle, Name: name, LocalPort: s.backend, TokenFile: tokenFile, HeartbeatInterval: 1, Version: "0.0.0-e2e",
		}, func(st tunnel.Status) {
			select {
			case r.status <- st:
			default:
			}
		})
		close(r.stopped)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.stopped:
		case <-time.After(10 * time.Second):
			t.Error("a tunnel did not stop")
		}
	})
	return r
}

func (r *run) waitPhase(t *testing.T, phase string) tunnel.Status {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case st := <-r.status:
			if st.Phase == phase {
				return st
			}
		case <-r.stopped:
			t.Fatalf("the tunnel stopped (%v) before %q", r.err, phase)
		case <-deadline:
			t.Fatalf("no %q within 20 s", phase)
		}
	}
}

// wait returns Run's error; a refused first login ends it.
func (r *run) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-r.stopped:
		return r.err
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

func (s *stack) get(t *testing.T, host string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+s.vhost+"/", nil)
	req.Host = host
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func (s *stack) token(sub string) string { return s.mock.Issue(sub, mockidp.IssueOpts{}) }

// runID is the run ID of user's client that is online, read from the dashboard.
func (s *stack) runID(t *testing.T, user string) string {
	t.Helper()
	req, _ := http.NewRequest("GET", s.dash+"/api/v2/clients?status=online&user="+user, nil)
	req.SetBasicAuth(dashUser, dashPassword)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var page struct {
		Data struct {
			Items []struct {
				RunID string `json:"runID"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil || len(page.Data.Items) != 1 || page.Data.Items[0].RunID == "" {
		t.Fatalf("online clients of %s: %+v, %v", user, page, err)
	}
	return page.Data.Items[0].RunID
}

func TestOwnerTunnelServesTraffic(t *testing.T) {
	s := newStack(t, 5)
	s.up(t, s.token("sub-alice"), "alice", "").waitPhase(t, "running")

	if code, body := s.get(t, "alice."+sites); code != 200 || body != "hello" {
		t.Errorf("alice's site = %d %q, want 200 hello", code, body)
	}
	s.mu.Lock()
	proto := s.proto
	s.mu.Unlock()
	if proto != "https" {
		t.Errorf("the app saw X-Forwarded-Proto %q, want https (frps rewrites it to http otherwise)", proto)
	}
	// The CLI's version travels through frps in the login and lands in the broker's log.
	if !strings.Contains(s.brokerLog.String(), `"cli_version":"0.0.0-e2e"`) {
		t.Errorf("the broker did not log the CLI's version:\n%s", s.brokerLog)
	}
	if code, _ := s.get(t, "bob."+sites); code != 404 {
		t.Errorf("a site nobody publishes = %d, want 404", code)
	}

	r := s.up(t, s.token("sub-alice"), "alice", "blog")
	r.waitPhase(t, "running")
	if code, body := s.get(t, "alice-blog."+sites); code != 200 || body != "hello" {
		t.Errorf("alice's named tunnel = %d %q", code, body)
	}
}

// A client changed to claim alice's name logs in as bob, and his proxy for alice's name is refused.
func TestCannotTakeAnotherUsersName(t *testing.T) {
	s := newStack(t, 5)
	s.up(t, s.token("sub-alice"), "alice", "").waitPhase(t, "running")

	st := s.up(t, s.token("sub-bob"), "alice", "").waitPhase(t, "start error")
	if !strings.Contains(st.Err, "not yours") {
		t.Errorf("start error = %q, want the broker's refusal", st.Err)
	}
	if code, body := s.get(t, "alice."+sites); code != 200 || body != "hello" {
		t.Errorf("alice's site after bob's attempt = %d %q", code, body)
	}
}

func TestRefusedLogins(t *testing.T) {
	s := newStack(t, 5)
	tests := []struct {
		name, token, want string
	}{
		{"token for another API", s.mock.Issue("sub-alice", mockidp.IssueOpts{Audience: []string{s.mock.URL}}), "tunnel login"},
		{"expired token", s.mock.Issue("sub-alice", mockidp.IssueOpts{TTL: -time.Minute}), "tunnel login"},
		{"garbage token", "garbage", "tunnel login"},
		{"not a creator", s.token("sub-carol"), "tunnels-creators"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.up(t, tt.token, "alice", "").wait(t)
			if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.HasPrefix(err.Error(), "login to the server failed: ") {
				t.Errorf("Run = %v, want the login refused with a reason containing %q", err, tt.want)
			}
			if err != nil && strings.Contains(err.Error(), "loginFailExit") {
				t.Errorf("frp's advice was not trimmed: %v", err)
			}
		})
	}
}

// pluginLogin posts a Login to the broker as frps would.
func (s *stack) pluginLogin(t *testing.T, token, runID string) (reject bool, reason, user string) {
	t.Helper()
	body, _ := json.Marshal(plugin.Request{Version: plugin.APIVersion, Op: plugin.OpLogin, Content: plugin.LoginContent{
		Login: msg.Login{Version: "0.71.0", User: "x", PrivilegeKey: token, RunID: runID},
	}})
	resp, err := http.Post(s.plugin+"?version=0.1.0&op=Login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rep struct {
		Reject       bool   `json:"reject"`
		RejectReason string `json:"reject_reason"`
		Content      struct {
			User string `json:"user"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil || resp.StatusCode != 200 {
		t.Fatalf("plugin answered %d: %v", resp.StatusCode, err)
	}
	return rep.Reject, rep.RejectReason, rep.Content.User
}

func TestRunIDTakeover(t *testing.T) {
	s := newStack(t, 5)
	s.up(t, s.token("sub-alice"), "alice", "").waitPhase(t, "running")
	run := s.runID(t, "alice")

	if user, online, err := s.frps.OnlineRunIDUser(t.Context(), run); err != nil || !online || user != "alice" {
		t.Fatalf("OnlineRunIDUser(%s) = %q, %v, %v; want alice online", run, user, online, err)
	}
	if reject, reason, _ := s.pluginLogin(t, s.token("sub-bob"), run); !reject || reason != "run id belongs to another session" {
		t.Errorf("bob with alice's run ID: reject=%v %q", reject, reason)
	}
	if reject, reason, user := s.pluginLogin(t, s.token("sub-alice"), run); reject || user != "alice" {
		t.Errorf("alice reconnecting with her own run ID: reject=%v %q user=%q", reject, reason, user)
	}
}

// A run ID is not a credential: a work connection without a token is refused (the NewWorkConns
// scope), so nobody who learns one can be handed the owner's visitors.
func TestWorkConnNeedsAToken(t *testing.T) {
	s := newStack(t, 5)
	s.up(t, s.token("sub-alice"), "alice", "").waitPhase(t, "running")
	run := s.runID(t, "alice")

	// frps multiplexes every connection with yamux (tcpMux, on by default), as any client can.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", s.bind), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	session, err := yamux.Client(conn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	rw := msg.NewV1ReadWriter(stream)
	if err := rw.WriteMsg(&msg.NewWorkConn{RunID: run}); err != nil {
		t.Fatal(err)
	}
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	m, err := rw.ReadMsg()
	if sw, ok := m.(*msg.StartWorkConn); err != nil || !ok || sw.Error == "" {
		t.Fatalf("frps answered a work connection without a token with %T %+v, %v; want a refusal", m, m, err)
	}
	for i := 0; i < 4; i++ {
		if code, body := s.get(t, "alice."+sites); code != 200 || body != "hello" {
			t.Errorf("request %d to alice's site = %d %q", i, code, body)
		}
	}
}

// Tokens live 6 s here, frps checks one with every ping (every second), and KeepFresh replaces it
// every 2 s: the tunnel must stay up throughout. Without the refresh it falls over within seconds.
func TestTokenRefreshKeepsTunnelAlive(t *testing.T) {
	s := newStack(t, 5)
	s.mock.SetTTL(6 * time.Second)
	st := auth.Store{Dir: t.TempDir()}
	if err := st.Save(auth.Tokens{AccessToken: s.token("sub-alice"), RefreshToken: s.mock.IssueRefreshToken("sub-alice"), Handle: "alice", Server: "http://unused"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var refreshErrs []error
	refresher := make(chan struct{})
	go func() {
		defer close(refresher)
		auth.KeepFresh(ctx, st, auth.OIDC{Issuer: s.mock.URL, ClientID: mockidp.ClientID, Resource: mockidp.APIResource, HTTP: httpx.Client(ua, 10*time.Second)},
			2*time.Second, func(err error) { mu.Lock(); refreshErrs = append(refreshErrs, err); mu.Unlock() })
	}()
	defer func() { cancel(); <-refresher }()

	r := s.upWithFile(t, st.AccessTokenPath(), "alice", "")
	r.waitPhase(t, "running")
	deadline := time.After(15 * time.Second)
watch:
	for {
		select {
		case got := <-r.status:
			if got.Phase != "running" {
				t.Fatalf("status left running: %+v", got)
			}
		case <-r.stopped:
			t.Fatalf("the tunnel stopped: %v", r.err)
		case <-deadline:
			break watch
		}
	}
	if code, body := s.get(t, "alice."+sites); code != 200 || body != "hello" {
		t.Errorf("alice's site after 15 s = %d %q", code, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(refreshErrs) != 0 {
		t.Errorf("refresh failed: %v", refreshErrs)
	}
}

func TestTunnelLimit(t *testing.T) {
	s := newStack(t, 2)
	s.up(t, s.token("sub-alice"), "alice", "one").waitPhase(t, "running")
	s.up(t, s.token("sub-alice"), "alice", "two").waitPhase(t, "running")
	st := s.up(t, s.token("sub-alice"), "alice", "three").waitPhase(t, "start error")
	if !strings.Contains(st.Err, "limit") {
		t.Errorf("start error = %q, want the tunnel limit", st.Err)
	}
	// bob has a limit of his own
	s.up(t, s.token("sub-bob"), "bob", "").waitPhase(t, "running")
}
