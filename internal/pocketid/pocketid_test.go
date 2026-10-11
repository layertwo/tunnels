package pocketid

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// call is one request a fake Pocket ID saw.
type call struct {
	method, path, apiKey, contentType string
	body                              []byte
}

// recorder remembers every request in order.
type recorder struct {
	mu    sync.Mutex
	calls []call
}

func (rc *recorder) record(r *http.Request) call {
	body, _ := io.ReadAll(r.Body)
	c := call{method: r.Method, path: r.URL.Path, apiKey: r.Header.Get("X-API-KEY"), contentType: r.Header.Get("Content-Type"), body: body}
	rc.mu.Lock()
	rc.calls = append(rc.calls, c)
	rc.mu.Unlock()
	return c
}

func (rc *recorder) all() []call {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.calls
}

// TestCreateClient proves the whole mint: the client body, the API key header, and the follow-up grant.
func TestCreateClient(t *testing.T) {
	rc := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.record(r)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/oidc/clients":
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"id":"client-123"}`)
		case r.Method == http.MethodPut && r.URL.Path == "/api/apis/api-1/clients/client-123":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	jwk := json.RawMessage(`{"kty":"EC","crv":"P-256","x":"abc","y":"def"}`)
	id, err := New(srv.URL, "secret-key", srv.Client()).CreateClient(t.Context(), "machine-nas", "https://idp.example", "https://api.example", jwk, "api-1")
	if err != nil || id != "client-123" {
		t.Fatalf("CreateClient = %q, %v; want client-123, nil", id, err)
	}
	calls := rc.all()
	if len(calls) != 2 {
		t.Fatalf("requests = %d, want the create and the grant", len(calls))
	}

	post := calls[0]
	if post.method != http.MethodPost || post.path != "/api/oidc/clients" || post.apiKey != "secret-key" || post.contentType != "application/json" {
		t.Errorf("create request = %+v", post)
	}
	var body struct {
		Name        string `json:"name"`
		IsPublic    bool   `json:"isPublic"`
		Credentials struct {
			FederatedIdentities []struct {
				Issuer           string            `json:"issuer"`
				Audience         string            `json:"audience"`
				PublicKeys       []json.RawMessage `json:"publicKeys"`
				ReplayProtection bool              `json:"replayProtection"`
			} `json:"federatedIdentities"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(post.body, &body); err != nil {
		t.Fatalf("create body %s: %v", post.body, err)
	}
	if body.Name != "machine-nas" || body.IsPublic {
		t.Errorf("create body = %s, want a private client named machine-nas", post.body)
	}
	fi := body.Credentials.FederatedIdentities
	if len(fi) != 1 || fi[0].Issuer != "https://idp.example" || fi[0].Audience != "https://api.example" || !fi[0].ReplayProtection {
		t.Errorf("federated identity = %s", post.body)
	}
	if len(fi[0].PublicKeys) != 1 || !bytes.Equal(fi[0].PublicKeys[0], jwk) {
		t.Errorf("publicKeys = %s, want the JWK verbatim", post.body)
	}
	if bytes.Contains(post.body, []byte("private")) {
		t.Errorf("the body names a private key: %s", post.body)
	}

	put := calls[1]
	if put.method != http.MethodPut || put.path != "/api/apis/api-1/clients/client-123" || put.apiKey != "secret-key" || put.contentType != "application/json" {
		t.Errorf("grant request = %+v", put)
	}
	if !strings.Contains(string(put.body), `"clientAccess":true`) {
		t.Errorf("grant body = %s, want client access", put.body)
	}
}

// A non-2xx is an error, never a panic, and the error carries neither the key nor the echoed body.
func TestCreateClientRefusesNon2xx(t *testing.T) {
	rc := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.record(r)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"the api key secret-key is bad"}`)
	}))
	t.Cleanup(srv.Close)

	_, err := New(srv.URL, "secret-key", srv.Client()).CreateClient(t.Context(), "machine-nas", "i", "a", json.RawMessage(`{"kty":"EC"}`), "api-1")
	if err == nil {
		t.Fatal("a 500 was not an error")
	}
	if strings.Contains(err.Error(), "secret-key") {
		t.Errorf("the error repeats the API key: %v", err)
	}
	if calls := rc.all(); len(calls) != 1 {
		t.Errorf("requests = %d, want no grant after a failed create", len(calls))
	}
}

// An answer without an id cannot become a machine: it is an error, not an empty client id.
func TestCreateClientWithoutID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(srv.Close)

	if id, err := New(srv.URL, "k", srv.Client()).CreateClient(t.Context(), "n", "i", "a", json.RawMessage(`{"kty":"EC"}`), "api-1"); err == nil || id != "" {
		t.Errorf("CreateClient = %q, %v; want an error and no id", id, err)
	}
}

// A create whose answer cannot be decoded is an error.
func TestCreateClientUndecodableAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `not json`)
	}))
	t.Cleanup(srv.Close)

	if _, err := New(srv.URL, "k", srv.Client()).CreateClient(t.Context(), "n", "i", "a", json.RawMessage(`{"kty":"EC"}`), "api-1"); err == nil {
		t.Error("an undecodable create answer was not an error")
	}
}

// A create body that cannot be built is an error before any request goes out.
func TestCreateClientRejectsAnInvalidJWK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	if _, err := New(srv.URL, "k", srv.Client()).CreateClient(t.Context(), "n", "i", "a", json.RawMessage(`{`), "api-1"); err == nil {
		t.Error("an invalid JWK was not an error")
	}
}

// If the grant fails the just-created client is deleted, so the caller has no half-minted client.
func TestCreateClientRollsBackWhenTheGrantFails(t *testing.T) {
	rc := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.record(r)
		switch {
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"id":"client-9"}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/oidc/clients/client-9":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	id, err := New(srv.URL, "k", srv.Client()).CreateClient(t.Context(), "n", "i", "a", json.RawMessage(`{"kty":"EC"}`), "api-1")
	if err == nil || id != "" {
		t.Fatalf("CreateClient = %q, %v; want an error and no id", id, err)
	}
	var methods []string
	for _, c := range rc.all() {
		methods = append(methods, c.method)
	}
	if want := []string{http.MethodPost, http.MethodPut, http.MethodDelete}; !equal(methods, want) {
		t.Errorf("methods = %v, want create, grant, delete", methods)
	}
}

// A transport failure hides the whole URL (and anything in it) behind the cause.
func TestCreateClientHidesTheURLOnATransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	_, err := New(url, "k", srv.Client()).CreateClient(t.Context(), "n", "i", "a", json.RawMessage(`{"kty":"EC"}`), "api-1")
	if err == nil {
		t.Fatal("a refused connection was not an error")
	}
	if strings.Contains(err.Error(), url) {
		t.Errorf("the error repeats the base URL: %v", err)
	}
}

// A bad base URL fails when the request is built, not with a panic.
func TestCreateClientBuildError(t *testing.T) {
	if _, err := New("http://exa mple.com", "k", http.DefaultClient).CreateClient(t.Context(), "n", "i", "a", json.RawMessage(`{"kty":"EC"}`), "api-1"); err == nil {
		t.Error("a URL with a space in the host was not an error")
	}
}

func TestDeleteClient(t *testing.T) {
	rc := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.record(r)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	if err := New(srv.URL, "secret-key", srv.Client()).DeleteClient(t.Context(), "abc"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	calls := rc.all()
	if len(calls) != 1 {
		t.Fatalf("requests = %d, want one", len(calls))
	}
	if c := calls[0]; c.method != http.MethodDelete || c.path != "/api/oidc/clients/abc" || c.apiKey != "secret-key" || c.contentType != "" {
		t.Errorf("delete request = %+v", c)
	}
}

func TestDeleteClientRefusesNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	if err := New(srv.URL, "k", srv.Client()).DeleteClient(t.Context(), "abc"); err == nil {
		t.Error("a 404 was not an error")
	}
}

// The base URL a caller gives may end in a slash; the path must not double it.
func TestNewTrimsTheTrailingSlash(t *testing.T) {
	rc := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.record(r)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	if err := New(srv.URL+"/", "k", srv.Client()).DeleteClient(t.Context(), "abc"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if c := rc.all()[0]; c.path != "/api/oidc/clients/abc" {
		t.Errorf("path = %q, want no doubled slash", c.path)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
