package httpx

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
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
