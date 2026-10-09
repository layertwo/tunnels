// Package mockidp is an in-process stand-in for Pocket ID v2.18.0, for tests. It serves the OIDC
// discovery document, the JWKS, the userinfo endpoint, the device authorization endpoint and a
// token endpoint (device_code and refresh_token grants), and signs the access tokens it issues
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

	kid             = "k1" // id of the one signing key
	deviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code"
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
	t   testing.TB      // immutable; Approve and Deny report an unknown user code through it

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
		t:             t,
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
	mux.HandleFunc("POST /device/authorize", s.deviceAuthorize)
	mux.HandleFunc("POST /token", s.token)

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

// Approve completes the device authorization that handed out userCode, as the user sub.
// A code the mock never handed out (or one already exchanged) fails the test.
func (s *Server) Approve(userCode, sub string) {
	s.t.Helper()
	s.decide(userCode, func(g *deviceGrant) { g.sub = sub })
}

// Deny rejects the device authorization that handed out userCode; it wins over an Approve.
func (s *Server) Deny(userCode string) {
	s.t.Helper()
	s.decide(userCode, func(g *deviceGrant) { g.denied = true })
}

// decide applies f to the device grant with the given user code.
func (s *Server) decide(userCode string, f func(*deviceGrant)) {
	s.t.Helper()
	s.mu.Lock()
	found := false
	for _, g := range s.deviceCodes {
		if g.userCode == userCode {
			f(g)
			found = true
		}
	}
	s.mu.Unlock()
	if !found {
		s.t.Errorf("mockidp: no device authorization with user code %q", userCode)
	}
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
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok { // no scheme, no token, as with fosite.AccessTokenFromRequest
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
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

// deviceAuthorize starts a device authorization for a public client; Approve or Deny settles it.
func (s *Server) deviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.ParseForm() != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	form := make(url.Values, len(r.Form))
	for k, v := range r.Form {
		form[k] = slices.Clone(v)
	}
	deviceCode, userCode := randHex(16), randUserCode()

	s.mu.Lock()
	ttl := s.deviceTTL
	s.deviceRequests = append(s.deviceRequests, form)
	s.deviceCodes[deviceCode] = &deviceGrant{
		userCode: userCode,
		clientID: form.Get("client_id"),
		scope:    form.Get("scope"),
		resource: form.Get("resource"),
		expires:  time.Now().Add(ttl),
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          s.URL + "/device",
		"verification_uri_complete": s.URL + "/device?user_code=" + userCode,
		"expires_in":                int(ttl / time.Second),
		"interval":                  1,
	})
}

// token serves the device_code and the refresh_token grants.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.ParseForm() != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var resp map[string]any
	var errCode string // empty on success
	switch r.Form.Get("grant_type") {
	case deviceCodeGrant:
		resp, errCode = s.exchangeDeviceCode(r.Form.Get("device_code"))
	case "refresh_token":
		resp, errCode = s.exchangeRefreshToken(r.Form.Get("refresh_token"))
	default:
		errCode = "unsupported_grant_type"
	}
	if errCode != "" {
		writeError(w, http.StatusBadRequest, errCode)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// exchangeDeviceCode answers one poll of a device authorization; an approved one is used up by it.
func (s *Server) exchangeDeviceCode(deviceCode string) (resp map[string]any, errCode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.deviceCodes[deviceCode]
	switch {
	case !ok:
		return nil, "invalid_grant"
	case !time.Now().Before(g.expires):
		return nil, "expired_token"
	case g.denied:
		return nil, "access_denied"
	case g.sub == "":
		return nil, "authorization_pending"
	}
	delete(s.deviceCodes, deviceCode)
	aud := []string{g.clientID, s.URL}
	if g.resource != "" {
		aud = slices.Insert(aud, 0, g.resource)
	}
	return s.tokenResponse(g.sub, aud, g.scope), ""
}

// exchangeRefreshToken rotates a refresh token. The first use marks it rotated; from then on it is
// accepted only for the refresh grace period, which covers two clients refreshing at once.
func (s *Server) exchangeRefreshToken(token string) (resp map[string]any, errCode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.refreshTokens[token]
	if !ok || s.revoked[g.sub] {
		return nil, "invalid_grant"
	}
	now := time.Now()
	if g.rotatedAt.IsZero() {
		g.rotatedAt = now
	} else if !now.Before(g.rotatedAt.Add(s.refreshGrace)) {
		return nil, "invalid_grant"
	}
	return s.tokenResponse(g.sub, g.aud, g.scope), ""
}

// tokenResponse builds the success answer of the token endpoint: an access token with the server
// TTL and, when scope has offline_access, a new refresh token. The caller holds s.mu.
func (s *Server) tokenResponse(sub string, aud []string, scope string) map[string]any {
	resp := map[string]any{
		"access_token": s.sign(sub, aud, scope, s.ttl),
		"token_type":   "Bearer",
		"expires_in":   int(s.ttl / time.Second),
		"scope":        scope,
	}
	if slices.Contains(strings.Fields(scope), "offline_access") {
		token := randHex(16)
		s.refreshTokens[token] = &refreshGrant{sub: sub, scope: scope, aud: aud}
		resp["refresh_token"] = token
	}
	return resp
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

// randUserCode returns a user code like ABCD-EFGH.
func randUserCode() string {
	b := make([]byte, 8)
	rand.Read(b) // never fails
	for i := range b {
		b[i] = 'A' + b[i]%26
	}
	return string(b[:4]) + "-" + string(b[4:])
}
