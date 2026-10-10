package frpsapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const userAgent = "tunnels-test/1"

// Bodies as frps v0.71.0 sends them (api/v2, wrapped in code, msg and data).
const (
	clientsOnline = `{"code":200,"msg":"success","data":{"total":1,"page":1,"pageSize":1,"items":[{"key":"alice.930a3a060e21c161","user":"alice","clientID":"930a3a060e21c161","runID":"930a3a060e21c161","version":"0.71.0","wireProtocol":"v1","hostname":"7cf34de847ea","clientIP":"127.0.0.1","firstConnectedAt":1791565403,"lastConnectedAt":1791565403,"online":true}]}}`
	clientsNone   = `{"code":200,"msg":"success","data":{"total":0,"page":1,"pageSize":1,"items":[]}}`
	proxiesThree  = `{"code":200,"msg":"success","data":{"total":3,"page":1,"pageSize":1,"items":[{"name":"alice.default","user":"alice","clientID":"930a3a060e21c161","spec":{"type":"http","http":{"transport":{"useEncryption":false,"useCompression":false,"bandwidthLimit":"10MB","bandwidthLimitMode":"server"},"loadBalancer":{"group":""},"subdomain":"alice"}},"status":{"phase":"online","todayTrafficIn":184,"todayTrafficOut":209,"curConns":0,"lastStartAt":1791565403,"lastCloseAt":1791565393}}]}}`
	proxiesNone   = `{"code":200,"msg":"success","data":{"total":0,"page":1,"pageSize":1,"items":[]}}`
)

// request is what the dashboard saw of the last call.
type request struct {
	path, userAgent, user, password string
	query                           url.Values
	hasAuth                         bool
}

// dashboard answers every request with status and body and records the last one.
type dashboard struct {
	mu    sync.Mutex
	last  request
	calls int
}

func (d *dashboard) saw() (request, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.last, d.calls
}

// serve starts a dashboard and returns a client for it (basic auth broker:pw).
func serve(t *testing.T, status int, body string) (*Client, *dashboard) {
	t.Helper()
	d := &dashboard{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		d.mu.Lock()
		d.calls++
		d.last = request{path: r.URL.Path, query: r.URL.Query(), userAgent: r.UserAgent(), user: user, password: pass, hasAuth: ok}
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, "broker", "pw", userAgent), d
}

func wantQuery(t *testing.T, got request, path string, want map[string]string) {
	t.Helper()
	if got.path != path {
		t.Errorf("path = %q, want %q", got.path, path)
	}
	if len(got.query) != len(want) {
		t.Errorf("query = %v, want exactly %v", got.query, want)
	}
	for k, v := range want {
		if got.query.Get(k) != v {
			t.Errorf("query %s = %q, want %q", k, got.query.Get(k), v)
		}
	}
	if !got.hasAuth || got.user != "broker" || got.password != "pw" {
		t.Errorf("basic auth = %q:%q (present %v), want broker:pw", got.user, got.password, got.hasAuth)
	}
	if got.userAgent != userAgent {
		t.Errorf("User-Agent = %q, want %q", got.userAgent, userAgent)
	}
}

func TestOnlineRunIDUser(t *testing.T) {
	c, d := serve(t, 200, clientsOnline)
	user, online, err := c.OnlineRunIDUser(t.Context(), "930a3a060e21c161")
	if err != nil || !online || user != "alice" {
		t.Fatalf("OnlineRunIDUser = %q, %v, %v, want alice, true, nil", user, online, err)
	}
	got, _ := d.saw()
	wantQuery(t, got, "/api/v2/clients", map[string]string{"runID": "930a3a060e21c161", "status": "online", "pageSize": "1"})
}

func TestOnlineRunIDUserOffline(t *testing.T) {
	c, _ := serve(t, 200, clientsNone)
	user, online, err := c.OnlineRunIDUser(t.Context(), "unknown")
	if err != nil || online || user != "" {
		t.Errorf("OnlineRunIDUser = %q, %v, %v, want empty, false, nil", user, online, err)
	}
}

// An empty runID filter would list every client, so it must not reach the dashboard.
func TestOnlineRunIDUserEmptyMakesNoRequest(t *testing.T) {
	c, d := serve(t, 200, clientsOnline)
	user, online, err := c.OnlineRunIDUser(t.Context(), "")
	if err != nil || online || user != "" {
		t.Errorf("OnlineRunIDUser = %q, %v, %v, want empty, false, nil", user, online, err)
	}
	if _, calls := d.saw(); calls != 0 {
		t.Errorf("%d requests for an empty run ID, want 0", calls)
	}
}

// If the dashboard ignored the filter, the first client it lists is somebody else's.
func TestOnlineRunIDUserChecksTheRunIDItGot(t *testing.T) {
	c, _ := serve(t, 200, clientsOnline)
	user, online, err := c.OnlineRunIDUser(t.Context(), "someone-elses-run-id")
	if err == nil || online || user != "" {
		t.Errorf("OnlineRunIDUser = %q, %v, %v, want an error and no user", user, online, err)
	}
}

// A record this client does not fully understand is not an owner and not "nobody": it is an error.
func TestOnlineRunIDUserInconsistentAnswers(t *testing.T) {
	item := `{"user":"alice","clientID":"r1","runID":"r1","online":true}`
	for name, body := range map[string]string{
		"total without items": `{"code":200,"msg":"success","data":{"total":1,"page":1,"pageSize":1,"items":[]}}`,
		"items without total": `{"code":200,"msg":"success","data":{"total":0,"page":1,"pageSize":1,"items":[` + item + `]}}`,
		"two online":          `{"code":200,"msg":"success","data":{"total":2,"page":1,"pageSize":1,"items":[` + item + `]}}`,
		"two items":           `{"code":200,"msg":"success","data":{"total":1,"page":1,"pageSize":1,"items":[` + item + `,` + item + `]}}`,
		"not online":          `{"code":200,"msg":"success","data":{"total":1,"page":1,"pageSize":1,"items":[{"user":"alice","clientID":"r1","runID":"r1","online":false}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := serve(t, 200, body)
			if user, online, err := c.OnlineRunIDUser(t.Context(), "r1"); err == nil || online || user != "" {
				t.Errorf("OnlineRunIDUser = %q, %v, %v, want an error and no user", user, online, err)
			}
		})
	}
}

func TestClientHasADeadline(t *testing.T) {
	if got := New("http://x", "u", "p", userAgent).http.Timeout; got != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", got)
	}
}

func TestOnlineProxyCount(t *testing.T) {
	c, d := serve(t, 200, proxiesThree)
	n, err := c.OnlineProxyCount(t.Context(), "alice")
	if err != nil || n != 3 {
		t.Fatalf("OnlineProxyCount = %d, %v, want 3, nil", n, err)
	}
	got, _ := d.saw()
	wantQuery(t, got, "/api/v2/proxies", map[string]string{"type": "http", "user": "alice", "status": "online", "pageSize": "1"})

	c, _ = serve(t, 200, proxiesNone)
	if n, err := c.OnlineProxyCount(t.Context(), "alice"); err != nil || n != 0 {
		t.Errorf("OnlineProxyCount = %d, %v, want 0, nil", n, err)
	}
}

func TestOnlineProxyCountEncodesTheUser(t *testing.T) {
	c, d := serve(t, 200, proxiesNone)
	const odd = "a&status=offline user=b%20#c"
	if _, err := c.OnlineProxyCount(t.Context(), odd); err != nil {
		t.Fatal(err)
	}
	got, _ := d.saw()
	wantQuery(t, got, "/api/v2/proxies", map[string]string{"type": "http", "user": odd, "status": "online", "pageSize": "1"})
}

func TestOnlineProxyCountEmptyUserMakesNoRequest(t *testing.T) {
	c, d := serve(t, 200, proxiesThree)
	if n, err := c.OnlineProxyCount(t.Context(), ""); err == nil || n != 0 {
		t.Errorf("OnlineProxyCount = %d, %v, want 0 and an error", n, err)
	}
	if _, calls := d.saw(); calls != 0 {
		t.Errorf("%d requests for an empty user, want 0", calls)
	}
}

func TestBaseURLTrailingSlash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/clients" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(clientsNone))
	}))
	defer srv.Close()
	if _, _, err := New(srv.URL+"/", "u", "p", userAgent).OnlineRunIDUser(t.Context(), "r1"); err != nil {
		t.Error(err)
	}
}

// Whatever goes wrong, the answer is an error, never a value that reads as "nobody is online".
func TestErrors(t *testing.T) {
	bodies := []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized", 401, `{"code":401,"msg":"unauthorized"}`},
		{"server error", 500, ``},
		{"code in the body", 200, `{"code":500,"msg":"boom","data":null}`},
		{"truncated json", 200, `{"code":200,"msg":"success","data":{"total":1,"items":[{"user":"al`},
		{"empty body", 200, ``},
		{"not json", 200, `<html>`},
		{"data of the wrong type", 200, `{"code":200,"msg":"success","data":"x"}`},
		{"code 500 with data", 200, `{"code":500,"msg":"boom","data":{"total":0,"page":1,"pageSize":1,"items":[]}}`},
		{"status 500 with a success body", 500, clientsNone},
		{"status 404 with a success body", 404, clientsNone},
		{"body over 1 MiB", 200, `{"code":200,"msg":"` + strings.Repeat("a", 2<<20) + `","data":{"total":0,"page":1,"pageSize":1,"items":[]}}`},
		{"data missing", 200, `{"code":200,"msg":"success"}`},
		{"data null", 200, `{"code":200,"msg":"success","data":null}`},
		{"no envelope", 200, `{"total":0,"items":[]}`},
	}
	calls := map[string]func(*Client) (bool, error){
		"OnlineRunIDUser": func(c *Client) (bool, error) {
			user, online, err := c.OnlineRunIDUser(t.Context(), "930a3a060e21c161")
			return online || user != "", err
		},
		"OnlineProxyCount": func(c *Client) (bool, error) {
			n, err := c.OnlineProxyCount(t.Context(), "alice")
			return n != 0, err
		},
	}
	for name, call := range calls {
		for _, b := range bodies {
			t.Run(name+"/"+b.name, func(t *testing.T) {
				c, _ := serve(t, b.status, b.body)
				if value, err := call(c); err == nil || value {
					t.Errorf("err = %v, non-zero value = %v, want an error and a zero value", err, value)
				}
			})
		}
		t.Run(name+"/connection refused", func(t *testing.T) {
			if value, err := call(New("http://127.0.0.1:1", "broker", "pw", userAgent)); err == nil || value {
				t.Errorf("err = %v, non-zero value = %v, want an error and a zero value", err, value)
			}
		})
	}
}

func TestCallerDeadlineIsHonoured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, online, err := New(srv.URL, "broker", "pw", userAgent).OnlineRunIDUser(ctx, "r1")
	if err == nil || online {
		t.Errorf("online = %v, err = %v, want an error", online, err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("took %v for a 100 ms deadline", took)
	}
}

// The dashboard is asked about run IDs and handles, and its errors end up in the broker's log: the
// query must not be part of what an error says.
func TestErrorsDoNotCarryTheQuery(t *testing.T) {
	c := New("http://127.0.0.1:1", "broker", "pw-secret", userAgent)
	_, _, err := c.OnlineRunIDUser(t.Context(), "930a3a060e21c161")
	if err == nil || strings.Contains(err.Error(), "930a3a060e21c161") || strings.Contains(err.Error(), "pw-secret") {
		t.Errorf("OnlineRunIDUser error = %v, want one without the run id", err)
	}
	_, err = c.OnlineProxyCount(t.Context(), "alice")
	if err == nil || strings.Contains(err.Error(), "alice") || strings.Contains(err.Error(), "?") {
		t.Errorf("OnlineProxyCount error = %v, want one without the handle", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %v, want the cause kept", err)
	}
}
