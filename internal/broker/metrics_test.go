package broker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRouteOf(t *testing.T) {
	tests := []struct{ path, want string }{
		{"/plugin/abc", "/plugin/"},
		{"/plugin/" + pluginSecret, "/plugin/"},
		{"/plugin/", "/plugin/"},
		{"/authz", "/authz"},
		{"/api/me", "/api/me"},
		{"/api/shares", "/api/shares"},
		{"/.well-known/tunnels.json", "/.well-known/tunnels.json"},
		{"/healthz", "/healthz"},
		{"/metrics", "/metrics"},
		{"/nope", "other"},
		{"/", "other"},
		{"/plugin", "other"},
	}
	for _, tt := range tests {
		if got := routeOf(tt.path); got != tt.want {
			t.Errorf("routeOf(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
	// The plugin secret is a path element: no label may ever carry it.
	if got := routeOf("/plugin/" + pluginSecret); strings.Contains(got, pluginSecret) {
		t.Errorf("routeOf leaked the plugin secret into the label %q", got)
	}
}

func TestMethodOf(t *testing.T) {
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"} {
		if got := methodOf(m); got != m {
			t.Errorf("methodOf(%q) = %q, want it kept", m, got)
		}
	}
	if got := methodOf("BREW"); got != "other" {
		t.Errorf("methodOf(%q) = %q, want other", "BREW", got)
	}
}

func TestMiddlewareRecords(t *testing.T) {
	m := NewMetrics()
	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hello"))
	}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusTeapot || w.Body.String() != "hello" {
		t.Fatalf("wrapped response = %d %q, want 418 hello", w.Code, w.Body)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("/healthz", "GET", "418")); got != 1 {
		t.Errorf("requests_total = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.inFlight); got != 0 {
		t.Errorf("in_flight = %v after the request, want 0", got)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	m := NewMetrics()
	// A counter with no series is not exposed, so make one request first.
	m.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if body := w.Body.String(); !strings.Contains(body, "tunnels_http_requests_total") {
		t.Errorf("the metrics body does not mention tunnels_http_requests_total:\n%s", body)
	}
}
