package broker

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics is the broker's Prometheus instrumentation: every HTTP request and both store lookups the
// /authz decision makes. Labels are bounded and secret-free: route is a fixed classifier, method and
// status come from a small bounded set, and phase is one of two literals. The plugin's secret path
// element therefore never reaches a label. It is safe for concurrent use.
type Metrics struct {
	reg      *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight prometheus.Gauge
	lookup   *prometheus.HistogramVec
}

// NewMetrics builds the collectors on a private registry, so a second call (as tests make) never
// collides with the first the way the default registry would.
func NewMetrics() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunnels_http_requests_total", Help: "HTTP requests the broker answered, by route, method and status.",
		}, []string{"route", "method", "status"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tunnels_http_request_duration_seconds", Help: "How long the broker took to answer a request.",
		}, []string{"route", "method", "status"}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tunnels_http_in_flight", Help: "Requests being served right now.",
		}),
		lookup: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tunnels_authz_lookup_duration_seconds", Help: "How long a store lookup in the /authz decision took.",
		}, []string{"phase"}),
	}
	m.reg.MustRegister(m.requests, m.duration, m.inFlight, m.lookup)
	return m
}

// Middleware measures every request that reaches next and counts it once its status is known. It
// passes the response through unchanged.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, method := routeOf(r.URL.Path), methodOf(r.Method)
		m.inFlight.Inc()
		defer m.inFlight.Dec()

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sw, r)
		status := strconv.Itoa(sw.status)
		m.requests.WithLabelValues(route, method, status).Inc()
		m.duration.WithLabelValues(route, method, status).Observe(time.Since(start).Seconds())
	})
}

// Handler serves the registry in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// ObserveLookup records how long one store lookup in the /authz path took; phase is "owner" or
// "shares".
func (m *Metrics) ObserveLookup(phase string, d time.Duration) {
	m.lookup.WithLabelValues(phase).Observe(d.Seconds())
}

// routeOf maps a request path to a fixed route label. Only known routes are named and everything
// else is "other", so no unbounded or secret path element can ever become a label.
func routeOf(path string) string {
	switch {
	case strings.HasPrefix(path, "/plugin/"):
		return "/plugin/"
	case path == "/authz":
		return "/authz"
	case path == "/api/me":
		return "/api/me"
	case path == "/api/shares":
		return "/api/shares"
	case path == "/.well-known/tunnels.json":
		return "/.well-known/tunnels.json"
	case path == "/healthz":
		return "/healthz"
	case path == "/metrics":
		return "/metrics"
	}
	return "other"
}

// methodOf keeps the method label to the standard methods and "other", so a client cannot mint a
// new series with an arbitrary method token.
func methodOf(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return method
	}
	return "other"
}

// statusWriter remembers the status the wrapped handler wrote, so the middleware can label it.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}
