// Package httpx builds the HTTP client every outbound request of the broker and the CLI goes through.
package httpx

import (
	"net/http"
	"time"
)

// Client returns an HTTP client with an overall deadline of timeout and the given User-Agent on every request.
func Client(userAgent string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: uaTransport{base: http.DefaultTransport.(*http.Transport).Clone(), userAgent: userAgent},
	}
}

// uaTransport sets the User-Agent header on a copy of each request.
type uaTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (t uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context()) // a RoundTripper must not modify the caller's request
	req.Header.Set("User-Agent", t.userAgent)
	return t.base.RoundTrip(req)
}
