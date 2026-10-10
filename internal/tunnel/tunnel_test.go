package tunnel

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatedier/frp/client/proxy"
	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func opts() Options {
	return Options{
		ServerHost: "tunnels.layertwo.dev", ServerPort: 443, Protocol: "wss",
		Handle: "alice", Name: "blog", LocalPort: 3000,
		TokenFile: "/home/alice/.config/tunnels/access-token", CAFile: "/home/alice/.config/tunnels/cacert.pem",
		Version: "1.2.3",
	}
}

func build(t *testing.T, o Options) (*v1.ClientCommonConfig, *v1.HTTPProxyConfig) {
	t.Helper()
	common, proxies, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 {
		t.Fatalf("%d proxies, want 1", len(proxies))
	}
	p, ok := proxies[0].(*v1.HTTPProxyConfig)
	if !ok {
		t.Fatalf("proxy is a %T, want *v1.HTTPProxyConfig", proxies[0])
	}
	return common, p
}

func TestBuildFields(t *testing.T) {
	o := opts()
	c, p := build(t, o)

	if c.ServerAddr != o.ServerHost || c.ServerPort != 443 || c.User != "alice" {
		t.Errorf("server %s:%d, user %q", c.ServerAddr, c.ServerPort, c.User)
	}
	if c.Transport.Protocol != "wss" || c.Transport.HeartbeatInterval != 30 {
		t.Errorf("protocol %q, heartbeat %d; want wss and 30 (with tcpMux frp sends none unless told)", c.Transport.Protocol, c.Transport.HeartbeatInterval)
	}
	if c.Transport.TLS.TrustedCaFile != o.CAFile {
		t.Errorf("trustedCaFile = %q, want %q (without it frp does not verify the server)", c.Transport.TLS.TrustedCaFile, o.CAFile)
	}
	if c.Auth.Method != v1.AuthMethodOIDC || !reflect.DeepEqual(c.Auth.AdditionalScopes, []v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}) {
		t.Errorf("auth method %q, scopes %v", c.Auth.Method, c.Auth.AdditionalScopes)
	}
	if ts := c.Auth.OIDC.TokenSource; ts == nil || ts.Type != "file" || ts.File == nil || ts.File.Path != o.TokenFile {
		t.Errorf("oidc token source = %+v, want the file %s", ts, o.TokenFile)
	}
	if c.LoginFailExit == nil || !*c.LoginFailExit {
		t.Error("loginFailExit is off: a refused first login would retry for ever instead of saying why")
	}
	if c.Metadatas["tunnel_version"] != "1.2.3" {
		t.Errorf("metadatas = %v, want tunnel_version 1.2.3: the broker logs it with every login", c.Metadatas)
	}
	if c.WebServer.Port != 0 {
		t.Errorf("the admin web server is on (port %d)", c.WebServer.Port)
	}

	if p.Name != "blog" || p.Type != "http" || p.LocalIP != "127.0.0.1" || p.LocalPort != 3000 {
		t.Errorf("proxy %q type %q to %s:%d", p.Name, p.Type, p.LocalIP, p.LocalPort)
	}
	if p.SubDomain != "alice-blog" || len(p.CustomDomains) != 0 || len(p.Locations) != 0 {
		t.Errorf("subdomain %q, custom domains %v, locations %v", p.SubDomain, p.CustomDomains, p.Locations)
	}
	if !reflect.DeepEqual(p.RequestHeaders.Set, map[string]string{"x-forwarded-proto": "https"}) {
		t.Errorf("request headers set = %v; frps rewrites x-forwarded-proto to http without it", p.RequestHeaders.Set)
	}
}

func TestBuildDefaultTunnel(t *testing.T) {
	o := opts()
	o.Name = ""
	_, p := build(t, o)
	if p.Name != "default" || p.SubDomain != "alice" {
		t.Errorf("proxy %q with subdomain %q, want default and alice", p.Name, p.SubDomain)
	}
}

func TestBuildHeartbeat(t *testing.T) {
	o := opts()
	o.HeartbeatInterval = 1
	if c, _ := build(t, o); c.Transport.HeartbeatInterval != 1 {
		t.Errorf("heartbeat = %d, want 1", c.Transport.HeartbeatInterval)
	}
}

func TestBuildWindowsPaths(t *testing.T) {
	o := opts()
	o.CAFile = `C:\Users\a b\AppData\Roaming\tunnels\cacert.pem`
	o.TokenFile = `C:\Users\a b\AppData\Roaming\tunnels\access-token`
	c, _ := build(t, o)
	if c.Transport.TLS.TrustedCaFile != o.CAFile || c.Auth.OIDC.TokenSource.File.Path != o.TokenFile {
		t.Errorf("paths = %q and %q", c.Transport.TLS.TrustedCaFile, c.Auth.OIDC.TokenSource.File.Path)
	}
}

// Tests talk to a local frps over plain tcp and need no CA file.
func TestBuildTCPWithoutCAFile(t *testing.T) {
	o := opts()
	o.Protocol, o.CAFile = "tcp", ""
	if c, _ := build(t, o); c.Transport.Protocol != "tcp" {
		t.Errorf("protocol %q", c.Transport.Protocol)
	}
}

func TestBuildRefuses(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*Options)
		want string // part of the error
	}{
		{"wss without a CA file", func(o *Options) { o.CAFile = "" }, "certificate"},
		{"the reserved name", func(o *Options) { o.Name = "default" }, "default"},
		{"a capital in the name", func(o *Options) { o.Name = "Blog" }, "Blog"},
		{"an underscore in the name", func(o *Options) { o.Name = "a_b" }, "a_b"},
		{"a dash at the start", func(o *Options) { o.Name = "-x" }, "-x"},
		{"a name that is too long", func(o *Options) { o.Name = strings.Repeat("a", 43) }, "aaaa"},
		{"port 0", func(o *Options) { o.LocalPort = 0 }, "port"},
		{"port -1", func(o *Options) { o.LocalPort = -1 }, "port"},
		{"port 65536", func(o *Options) { o.LocalPort = 65536 }, "port"},
		{"no handle", func(o *Options) { o.Handle = "" }, "tunnel login"},
		{"a handle with a capital", func(o *Options) { o.Handle = "Alice" }, "tunnel login"},
		{"a handle with a dash", func(o *Options) { o.Handle = "a-b" }, "tunnel login"},
		{"no token file", func(o *Options) { o.TokenFile = "" }, "token"},
		// frp's own validation runs too: a value only it knows to refuse is refused here, not at connect.
		{"a protocol frp does not speak", func(o *Options) { o.Protocol = "carrier-pigeon" }, "protocol"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := opts()
			tt.mod(&o)
			c, p, err := Build(o)
			if err == nil || !strings.Contains(err.Error(), tt.want) || c != nil || p != nil {
				t.Errorf("Build = %v, %v, %v; want only an error containing %q", c, p, err, tt.want)
			}
		})
	}
}

func certs(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			t.Fatalf("PEM block of type %q", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	if len(strings.TrimSpace(string(raw))) != 0 {
		t.Fatalf("%d bytes after the last PEM block", len(raw))
	}
	return out
}

func TestWriteCABundle(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteCABundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "cacert.pem") {
		t.Errorf("path = %q", path)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %o, want 600", fi.Mode().Perm())
		}
	}
	list := certs(t, path)
	if len(list) < 100 {
		t.Errorf("%d certificates, want the whole Mozilla set (100 or more)", len(list))
	}
	var isrg, izenpe bool
	for _, c := range list {
		isrg = isrg || strings.Contains(c.Subject.String(), "ISRG Root X1")
		izenpe = izenpe || strings.Contains(c.Subject.String(), "Izenpe.com")
	}
	if !isrg {
		t.Error("ISRG Root X1 (Let's Encrypt) is missing")
	}
	// A root that Mozilla distrusts after a date cannot carry that date in a PEM file, so it is left out.
	if izenpe {
		t.Error("a root with a distrust-after constraint was written without its constraint")
	}

	// The same bundle again: the file is left alone.
	before, _ := os.Stat(path)
	time.Sleep(20 * time.Millisecond)
	if again, err := WriteCABundle(dir); err != nil || again != path {
		t.Fatalf("second call = %q, %v", again, err)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
		t.Error("the second call rewrote an identical file")
	}

	// A damaged file is replaced.
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteCABundle(dir); err != nil {
		t.Fatal(err)
	}
	if n := len(certs(t, path)); n != len(list) {
		t.Errorf("after repair %d certificates, want %d", n, len(list))
	}
}

// A directory that does not exist cannot take the bundle, and the failure is reported, not ignored.
func TestWriteCABundleUnwritableDir(t *testing.T) {
	path, err := WriteCABundle(filepath.Join(t.TempDir(), "missing"))
	if path != "" || err == nil || !strings.Contains(err.Error(), "write the CA bundle") {
		t.Errorf("WriteCABundle = %q, %v; want the write error", path, err)
	}
}

// fakeStatus is a client.StatusExporter the test drives by hand.
type fakeStatus struct {
	mu     sync.Mutex
	polled string
	status *proxy.WorkingStatus
	ok     bool
}

func (f *fakeStatus) GetProxyStatus(name string) (*proxy.WorkingStatus, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polled = name
	return f.status, f.ok
}

func (f *fakeStatus) set(phase, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.ok = &proxy.WorkingStatus{Phase: phase, Err: reason}, true
}

func (f *fakeStatus) lastPolled() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.polled
}

// watch polls the proxy's name and reports each change of its status once, until stopped.
func TestWatchReportsChangesUntilStopped(t *testing.T) {
	f := &fakeStatus{}
	statuses := make(chan Status, 8)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		watch(f, "blog", func(s Status) { statuses <- s }, stop)
	}()

	// Until the proxy has a status, watch keeps polling and reports nothing.
	deadline := time.After(5 * time.Second)
	for f.lastPolled() == "" {
		select {
		case s := <-statuses:
			t.Fatalf("reported %+v before the proxy had a status", s)
		case <-deadline:
			t.Fatal("watch never asked for the proxy status")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if name := f.lastPolled(); name != "blog" {
		t.Errorf("polled proxy %q, want blog", name)
	}

	f.set("wait start", "")
	if got := nextStatus(t, statuses); got != (Status{Phase: "wait start"}) {
		t.Errorf("reported %+v, want wait start", got)
	}
	// The same status again is not repeated.
	select {
	case s := <-statuses:
		t.Fatalf("reported the unchanged status %+v again", s)
	case <-time.After(250 * time.Millisecond):
	}

	f.set("start error", "the service refused the tunnel")
	if got := nextStatus(t, statuses); got != (Status{Phase: "start error", Err: "the service refused the tunnel"}) {
		t.Errorf("reported %+v, want the changed status with its reason", got)
	}

	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not stop when told")
	}
}

func nextStatus(t *testing.T, ch <-chan Status) Status {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("watch reported no status")
		return Status{}
	}
}

func TestRunRefusesBadOptions(t *testing.T) {
	o := opts()
	o.Handle = ""
	if err := Run(t.Context(), o, nil); err == nil || !strings.Contains(err.Error(), "tunnel login") {
		t.Errorf("Run = %v, want Build's error", err)
	}
}

// A first login that fails ends Run with the reason, without frp's advice about loginFailExit.
func TestRunFirstLoginFails(t *testing.T) {
	o := opts()
	o.ServerHost, o.ServerPort, o.Protocol, o.CAFile = "127.0.0.1", 1, "tcp", ""
	o.TokenFile = filepath.Join(t.TempDir(), "access-token")
	if err := os.WriteFile(o.TokenFile, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	reported := make(chan Status, 8) // a failed first login never reaches a proxy status
	go func() { done <- Run(t.Context(), o, func(s Status) { reported <- s }) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "loginFailExit") {
			t.Errorf("Run = %v, want the connection error alone", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after a failed first login")
	}
	select {
	case s := <-reported:
		t.Errorf("reported %+v for a login that never reached the proxy", s)
	default:
	}
}

func TestRunStopsWithItsContext(t *testing.T) {
	o := opts()
	o.ServerHost, o.ServerPort, o.Protocol, o.CAFile = "127.0.0.1", 1, "tcp", ""
	o.TokenFile = filepath.Join(t.TempDir(), "access-token")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	start := time.Now()
	if err := Run(ctx, o, nil); err != nil {
		t.Errorf("Run with an ended context = %v, want nil: stopping is not a failure", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("took %v", took)
	}
}

// Several tunnels in one process (the end-to-end test runs many) share frp's global logger, which
// must be set up once, not by every Run while another is logging. Run with -race.
func TestRunConcurrently(t *testing.T) {
	o := opts()
	o.ServerHost, o.ServerPort, o.Protocol, o.CAFile = "127.0.0.1", 1, "tcp", ""
	o.TokenFile = filepath.Join(t.TempDir(), "access-token")
	if err := os.WriteFile(o.TokenFile, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Run(t.Context(), o, nil); err == nil {
				t.Error("Run against a closed port succeeded")
			}
		}()
	}
	wg.Wait()
}
