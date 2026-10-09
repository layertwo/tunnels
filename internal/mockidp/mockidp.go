// Package mockidp is an in-process stand-in for Pocket ID v2.18.0, for tests. It serves the OIDC
// discovery document, the JWKS and the userinfo endpoint, and signs the access tokens it issues
// with an RSA key it generates itself.
package mockidp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	// APIResource is the audience of the access tokens meant for the broker.
	APIResource = "https://tunnels.layertwo.dev"
	// ClientID is the OIDC client the CLI logs in with.
	ClientID = "tunnels-cli-test"

	kid = "k1" // id of the one signing key
)

// User is an account of the mock; Sub identifies it.
type User struct {
	Sub, Username string
	Groups        []string
}

// IssueOpts overrides the defaults of Issue. A nil Audience, an empty Scope and a zero TTL keep the default.
type IssueOpts struct {
	Audience []string
	Scope    string
	TTL      time.Duration // negative: the token is already expired
}

// Server is a running mock identity provider; URL is its issuer.
type Server struct {
	URL string

	key *rsa.PrivateKey // immutable

	mu             sync.Mutex // guards the fields below
	users          map[string]User
	revoked        map[string]bool
	ttl            time.Duration
	deviceTTL      time.Duration
	refreshGrace   time.Duration
	userAgents     []string
	deviceRequests []url.Values
	deviceCodes    map[string]*deviceGrant
	refreshTokens  map[string]*refreshGrant
}

// deviceGrant is one device authorization request.
type deviceGrant struct {
	userCode, clientID, scope, resource string
	expires                             time.Time
	sub                                 string // set when approved
	denied                              bool
}

// refreshGrant is one refresh token.
type refreshGrant struct {
	sub, scope string
	aud        []string
	rotatedAt  time.Time // zero while it is the current token
}

// New starts a mock identity provider that is shut down when t ends.
func New(t testing.TB) *Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("mockidp: generate key: %v", err)
	}
	s := &Server{
		key:           key,
		users:         map[string]User{},
		revoked:       map[string]bool{},
		ttl:           time.Hour,
		deviceTTL:     10 * time.Minute,
		refreshGrace:  60 * time.Second,
		deviceCodes:   map[string]*deviceGrant{},
		refreshTokens: map[string]*refreshGrant{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /jwks", s.jwks)
	mux.HandleFunc("GET /userinfo", s.userinfo)
	// the device flow and the refresh grant are not implemented yet
	mux.HandleFunc("POST /device/authorize", notImplemented)
	mux.HandleFunc("POST /token", notImplemented)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.userAgents = append(s.userAgents, r.UserAgent())
		s.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	s.URL = "http://" + srv.Listener.Addr().String() // set before the first request can arrive
	srv.Start()
	t.Cleanup(srv.Close)
	return s
}

// AddUser registers u, replacing any user with the same Sub.
func (s *Server) AddUser(u User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.Sub] = u
}

// SetTTL sets the lifetime (default 1h) of every access token issued from now on, refreshed ones included.
func (s *Server) SetTTL(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttl = d
}

// SetDeviceTTL sets how long a device code is valid (default 10 minutes).
func (s *Server) SetDeviceTTL(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceTTL = d
}

// SetRefreshGrace sets how long a rotated refresh token is still accepted (default 60 seconds).
func (s *Server) SetRefreshGrace(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshGrace = d
}

// RevokeUser marks sub as revoked: the refresh_token grant refuses its refresh tokens.
func (s *Server) RevokeUser(sub string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[sub] = true
}

// UserAgents returns the User-Agent of every request received so far, in order.
func (s *Server) UserAgents() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.userAgents)
}

// DeviceRequests returns the form of every device authorization request received so far, in order.
func (s *Server) DeviceRequests() []url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.deviceRequests)
}

// Issue returns an access token for sub. The defaults are the audience [APIResource, ClientID, URL],
// the scope "openid profile groups" and the TTL of the server.
func (s *Server) Issue(sub string, o IssueOpts) string {
	s.mu.Lock()
	ttl := s.ttl
	s.mu.Unlock()
	if o.TTL != 0 {
		ttl = o.TTL
	}
	if o.Audience == nil {
		o.Audience = []string{APIResource, ClientID, s.URL}
	}
	if o.Scope == "" {
		o.Scope = "openid profile groups"
	}
	return s.sign(sub, o.Audience, o.Scope, ttl)
}

// sign builds the JWT. It does not touch the mutex, so the handlers can call it while holding it.
func (s *Server) sign(sub string, aud []string, scope string, ttl time.Duration) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		panic(err) // cannot happen: RS256 with an RSA key
	}
	now := time.Now()
	raw, err := jwt.Signed(signer).Claims(map[string]any{
		"iss":   s.URL,
		"sub":   sub,
		"aud":   aud,
		"scope": scope,
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
		"jti":   randHex(16), // two tokens issued in the same second still differ
	}).Serialize()
	if err != nil {
		panic(err) // cannot happen: the claims are plain JSON values
	}
	return raw
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.URL,
		"authorization_endpoint":                s.URL + "/authorize",
		"token_endpoint":                        s.URL + "/token",
		"userinfo_endpoint":                     s.URL + "/userinfo",
		"jwks_uri":                              s.URL + "/jwks",
		"device_authorization_endpoint":         s.URL + "/device/authorize",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &s.key.PublicKey, KeyID: kid, Use: "sig", Algorithm: string(jose.RS256)},
	}})
}

// userinfo answers like Pocket ID: the claims follow the scopes of the access token, which must
// carry openid and name this issuer in its audience.
func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	raw, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	var c struct {
		jwt.Claims
		Scope string `json:"scope"`
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err == nil {
		err = tok.Claims(&s.key.PublicKey, &c)
	}
	if err == nil {
		err = c.ValidateWithLeeway(jwt.Expected{Time: time.Now()}, 0)
	}
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	if !slices.Contains(c.Audience, s.URL) {
		writeError(w, http.StatusForbidden, "invalid_audience")
		return
	}
	scopes := strings.Fields(c.Scope)
	if !slices.Contains(scopes, "openid") {
		writeError(w, http.StatusForbidden, "insufficient_scope")
		return
	}
	s.mu.Lock()
	u, ok := s.users[c.Subject]
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	body := map[string]any{"sub": u.Sub}
	if slices.Contains(scopes, "profile") {
		body["preferred_username"] = u.Username
	}
	if slices.Contains(scopes, "groups") {
		body["groups"] = append([]string{}, u.Groups...) // [] rather than null
	}
	writeJSON(w, http.StatusOK, body)
}

func notImplemented(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// randHex returns n random bytes as hex.
func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b) // never fails
	return hex.EncodeToString(b)
}
