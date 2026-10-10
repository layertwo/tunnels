package httpx

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestClientSetsUserAgent(t *testing.T) {
	seen := make(chan []string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Values("User-Agent")
	}))
	t.Cleanup(srv.Close)
	c := Client("tunnels-test/1", 5*time.Second)

	tests := []struct{ name, callerUA string }{
		{"request without a user agent", ""},
		{"request with a user agent of its own", "caller/1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Test", "1")
			if tt.callerUA != "" {
				req.Header.Set("User-Agent", tt.callerUA)
			}
			before := req.Header.Clone()

			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			if got, want := <-seen, []string{"tunnels-test/1"}; !slices.Equal(got, want) {
				t.Errorf("the server saw User-Agent %q, want %q", got, want)
			}
			if !reflect.DeepEqual(req.Header, before) {
				t.Errorf("the caller's request headers changed from %v to %v", before, req.Header)
			}
		})
	}
}

func TestClientTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select { // outlasts the client timeout; the client hanging up ends it early
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Client("tunnels-test/1", 50*time.Millisecond).Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("got status %d, want a timeout error", resp.StatusCode)
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Errorf("err = %v, want a timeout error", err)
	}
}

// A redirect is never followed. Go would forward the Authorization header to the same host on
// another scheme or port (https to http included) and re-send a POST body (a refresh token, a
// device code) to any host on a 307; nothing the broker or the CLI calls needs a redirect.
func TestClientFollowsNoRedirect(t *testing.T) {
	var mu sync.Mutex
	var leaked []string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		leaked = append(leaked, r.Method+" "+r.Header.Get("Authorization")+" "+string(body))
		mu.Unlock()
	}))
	t.Cleanup(elsewhere.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := http.StatusFound
		if r.Method == http.MethodPost {
			code = http.StatusTemporaryRedirect // keeps the method and the body
		}
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, code)
	}))
	t.Cleanup(redirector.Close)
	c := Client("tunnels-test/1", 5*time.Second)

	req, _ := http.NewRequest(http.MethodGet, redirector.URL+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer secret-access-token")
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Errorf("GET = %v, %v; want the 302 itself", resp, err)
	}
	resp, err = c.PostForm(redirector.URL+"/token", url.Values{"refresh_token": {"secret-refresh-token"}})
	if err != nil || resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("POST = %v, %v; want the 307 itself", resp, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(leaked) != 0 {
		t.Errorf("the redirect was followed: %q", leaked)
	}
}
