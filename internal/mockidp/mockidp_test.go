package mockidp

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// urnDeviceCode is the grant_type of a device code exchange; spelled out here to check the mock's constant.
const urnDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

// claims are the claims of an access token that the tests look at.
type claims struct {
	jwt.Claims
	Scope string `json:"scope"`
}

// get issues a GET with the extra request headers h and returns the status and the trimmed body.
func get(t *testing.T, url string, h http.Header) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	maps.Copy(req.Header, h)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, strings.TrimSpace(string(body))
}

// verify checks raw against the key s publishes at /jwks, as a resource server would, and returns its claims.
func verify(t *testing.T, s *Server, raw string) claims {
	t.Helper()
	status, body := get(t, s.URL+"/jwks", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /jwks = %d: %s", status, body)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(body), &set); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	kid := tok.Headers[0].KeyID
	keys := set.Key(kid)
	if len(keys) != 1 {
		t.Fatalf("jwks has %d keys for kid %q, want 1", len(keys), kid)
	}
	var c claims
	if err := tok.Claims(keys[0].Key, &c); err != nil {
		t.Fatalf("token does not verify against the jwks: %v", err)
	}
	return c
}

// checkExpiry fails unless exp is ttl after the moment of issue, which lay between before and after.
func checkExpiry(t *testing.T, exp *jwt.NumericDate, ttl time.Duration, before, after time.Time) {
	t.Helper()
	// exp has a resolution of one second: it is the issue time plus ttl, rounded down
	if got := exp.Time(); got.Before(before.Add(ttl).Truncate(time.Second)) || got.After(after.Add(ttl)) {
		t.Errorf("exp = %v, want %v after the issue time (between %v and %v)", got, ttl, before, after)
	}
}

func TestIssueVerifiesAgainstJWKS(t *testing.T) {
	s := New(t)

	before := time.Now()
	a := s.Issue("alice-sub", IssueOpts{})
	after := time.Now()
	b := s.Issue("alice-sub", IssueOpts{})

	ca := verify(t, s, a)
	if ca.Issuer != s.URL {
		t.Errorf("iss = %q, want %q", ca.Issuer, s.URL)
	}
	if ca.Subject != "alice-sub" {
		t.Errorf("sub = %q, want alice-sub", ca.Subject)
	}
	if want := []string{APIResource, ClientID, s.URL}; !slices.Equal(ca.Audience, want) {
		t.Errorf("aud = %v, want %v", ca.Audience, want)
	}
	if want := "openid profile groups"; ca.Scope != want {
		t.Errorf("scope = %q, want %q", ca.Scope, want)
	}
	checkExpiry(t, ca.Expiry, time.Hour, before, after)

	// the same claims within the same second: only the jti tells the tokens apart
	cb := verify(t, s, b)
	if a == b || ca.ID == "" || ca.ID == cb.ID {
		t.Errorf("two tokens do not differ: jti %q and %q", ca.ID, cb.ID)
	}
}

func TestIssueOptions(t *testing.T) {
	s := New(t)

	before := time.Now()
	raw := s.Issue("bob-sub", IssueOpts{Audience: []string{"a", "b"}, Scope: "openid email", TTL: 5 * time.Minute})
	after := time.Now()
	c := verify(t, s, raw)
	if want := []string{"a", "b"}; !slices.Equal(c.Audience, want) {
		t.Errorf("aud = %v, want %v", c.Audience, want)
	}
	if want := "openid email"; c.Scope != want {
		t.Errorf("scope = %q, want %q", c.Scope, want)
	}
	checkExpiry(t, c.Expiry, 5*time.Minute, before, after)

	before = time.Now()
	raw = s.Issue("bob-sub", IssueOpts{TTL: -time.Minute})
	after = time.Now()
	c = verify(t, s, raw)
	checkExpiry(t, c.Expiry, -time.Minute, before, after)
	if !c.Expiry.Time().Before(time.Now()) {
		t.Error("a negative TTL did not give an expired token")
	}

	// SetTTL is the default for the tokens issued afterwards
	s.SetTTL(2 * time.Minute)
	before = time.Now()
	raw = s.Issue("bob-sub", IssueOpts{})
	after = time.Now()
	checkExpiry(t, verify(t, s, raw).Expiry, 2*time.Minute, before, after)
}

// Pocket ID reads the token with fosite.AccessTokenFromRequest: without the Bearer scheme there is
// no token, so the answer is 401 even when the rest of the header is a good access token.
func TestUserInfoRequiresBearerScheme(t *testing.T) {
	s := New(t)
	s.AddUser(User{Sub: "alice-sub", Username: "alice"})
	token := s.Issue("alice-sub", IssueOpts{})

	for name, header := range map[string]string{
		"bare token":   token,
		"basic scheme": "Basic " + token,
		"empty scheme": " " + token,
	} {
		t.Run(name, func(t *testing.T) {
			status, body := get(t, s.URL+"/userinfo", http.Header{"Authorization": {header}})
			if status != 401 || body != `{"error":"invalid_token"}` {
				t.Errorf("status = %d, body = %s, want 401 invalid_token", status, body)
			}
		})
	}
}

func TestUserInfo(t *testing.T) {
	s := New(t)
	s.AddUser(User{Sub: "alice-sub", Username: "alice", Groups: []string{"admins", "dev"}})
	elsewhere := New(t) // another issuer, with a key of its own

	const invalid = `{"error":"invalid_token"}`
	tests := []struct {
		name   string
		token  string // empty: no Authorization header
		status int
		body   string // compared unless empty
	}{
		{"profile and groups", s.Issue("alice-sub", IssueOpts{}), 200,
			`{"groups":["admins","dev"],"preferred_username":"alice","sub":"alice-sub"}`},
		{"openid only", s.Issue("alice-sub", IssueOpts{Scope: "openid"}), 200, `{"sub":"alice-sub"}`},
		{"audience lacks the issuer", s.Issue("alice-sub", IssueOpts{Audience: []string{APIResource, ClientID}}), 403, ""},
		{"scope lacks openid", s.Issue("alice-sub", IssueOpts{Scope: "profile groups"}), 403, ""},
		{"expired", s.Issue("alice-sub", IssueOpts{TTL: -time.Minute}), 401, invalid},
		{"garbage", "not-a-jwt", 401, invalid},
		{"bad signature", elsewhere.Issue("alice-sub", IssueOpts{Audience: []string{s.URL}}), 401, invalid},
		{"unknown sub", s.Issue("nobody", IssueOpts{}), 401, invalid},
		{"no token", "", 401, invalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.token != "" {
				h.Set("Authorization", "Bearer "+tt.token)
			}
			status, body := get(t, s.URL+"/userinfo", h)
			if status != tt.status {
				t.Errorf("status = %d, want %d (body %s)", status, tt.status, body)
			}
			if tt.body != "" && body != tt.body {
				t.Errorf("body = %s, want %s", body, tt.body)
			}
		})
	}
}

func TestRecordsUserAgents(t *testing.T) {
	s := New(t)

	want := []string{"agent/1", "agent/2", "agent/3"}
	for i, path := range []string{"/jwks", "/.well-known/openid-configuration", "/no-such-route"} {
		get(t, s.URL+path, http.Header{"User-Agent": {want[i]}})
	}
	got := s.UserAgents()
	if !slices.Equal(got, want) {
		t.Fatalf("UserAgents() = %v, want %v", got, want)
	}

	got[0] = "changed"
	if again := s.UserAgents(); !slices.Equal(again, want) {
		t.Errorf("UserAgents() = %v after the caller changed its result, want %v", again, want)
	}
}

// reply is a decoded JSON answer of the mock.
type reply map[string]any

// str returns the string value of key, or "" when it is absent or not a string.
func (r reply) str(key string) string {
	s, _ := r[key].(string)
	return s
}

// post sends form to endpoint and returns the status and the JSON object of the answer.
func post(t *testing.T, endpoint string, form url.Values) (int, reply) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body reply
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("POST %s = %d: the answer is not a JSON object: %v", endpoint, resp.StatusCode, err)
	}
	return resp.StatusCode, body
}

// startLogin sends a device authorization request and returns the answer.
func startLogin(t *testing.T, s *Server, form url.Values) reply {
	t.Helper()
	status, auth := post(t, s.URL+"/device/authorize", form)
	if status != http.StatusOK {
		t.Fatalf("POST /device/authorize = %d: %v", status, auth)
	}
	return auth
}

// poll exchanges a device code at the token endpoint.
func poll(t *testing.T, s *Server, deviceCode string) (int, reply) {
	t.Helper()
	return post(t, s.URL+"/token", url.Values{"grant_type": {urnDeviceCode}, "device_code": {deviceCode}, "client_id": {ClientID}})
}

// refresh exchanges a refresh token at the token endpoint.
func refresh(t *testing.T, s *Server, refreshToken string) (int, reply) {
	t.Helper()
	return post(t, s.URL+"/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {ClientID}})
}

// login runs the device flow for sub, asking for the API resource and scope, and returns the token response.
func login(t *testing.T, s *Server, sub, scope string) reply {
	t.Helper()
	auth := startLogin(t, s, url.Values{"client_id": {ClientID}, "scope": {scope}, "resource": {APIResource}})
	s.Approve(auth.str("user_code"), sub)
	status, tok := poll(t, s, auth.str("device_code"))
	if status != http.StatusOK {
		t.Fatalf("POST /token = %d: %v", status, tok)
	}
	return tok
}

// wantError fails unless the answer is exactly {"error": code} with status 400.
func wantError(t *testing.T, status int, r reply, code string) {
	t.Helper()
	if status != http.StatusBadRequest || len(r) != 1 || r.str("error") != code {
		t.Errorf("got %d %v, want 400 {error: %q}", status, r, code)
	}
}

func TestDeviceFlow(t *testing.T) {
	s := New(t)
	const scope = "openid profile groups offline_access"

	auth := startLogin(t, s, url.Values{"client_id": {ClientID}, "scope": {scope}, "resource": {APIResource}})
	deviceCode, userCode := auth.str("device_code"), auth.str("user_code")
	if deviceCode == "" {
		t.Error("device_code is empty")
	}
	if !regexp.MustCompile(`^[A-Z]{4}-[A-Z]{4}$`).MatchString(userCode) {
		t.Errorf("user_code = %q, want a code like ABCD-EFGH", userCode)
	}
	if got, want := auth.str("verification_uri"), s.URL+"/device"; got != want {
		t.Errorf("verification_uri = %q, want %q", got, want)
	}
	if got, want := auth.str("verification_uri_complete"), s.URL+"/device?user_code="+userCode; got != want {
		t.Errorf("verification_uri_complete = %q, want %q", got, want)
	}
	if auth["expires_in"] != float64(600) || auth["interval"] != float64(1) {
		t.Errorf("expires_in = %v, interval = %v, want 600 and 1", auth["expires_in"], auth["interval"])
	}

	// the request as the mock recorded it
	reqs := s.DeviceRequests()
	if len(reqs) != 1 {
		t.Fatalf("DeviceRequests() has %d entries, want 1", len(reqs))
	}
	for key, want := range map[string]string{"client_id": ClientID, "scope": scope, "resource": APIResource} {
		if got := reqs[0].Get(key); got != want {
			t.Errorf("recorded %s = %q, want %q", key, got, want)
		}
	}
	if reqs[0].Has("client_secret") {
		t.Error("the device request carries a client_secret")
	}

	status, body := poll(t, s, deviceCode)
	wantError(t, status, body, "authorization_pending")

	s.Approve(userCode, "alice-sub")
	status, tok := poll(t, s, deviceCode)
	if status != http.StatusOK {
		t.Fatalf("POST /token after Approve = %d: %v", status, tok)
	}
	if tok.str("token_type") != "Bearer" || tok["expires_in"] != float64(3600) || tok.str("scope") != scope {
		t.Errorf("token_type = %v, expires_in = %v, scope = %v, want Bearer, 3600, %q",
			tok["token_type"], tok["expires_in"], tok["scope"], scope)
	}
	if tok.str("refresh_token") == "" {
		t.Error("refresh_token is empty although the scope has offline_access")
	}
	c := verify(t, s, tok.str("access_token"))
	if want := []string{APIResource, ClientID, s.URL}; !slices.Equal(c.Audience, want) {
		t.Errorf("aud = %v, want %v", c.Audience, want)
	}
	if c.Scope != scope || c.Subject != "alice-sub" {
		t.Errorf("scope = %q, sub = %q, want %q and alice-sub", c.Scope, c.Subject, scope)
	}

	// an approved device code is used up, and a code that never existed is no better
	status, body = poll(t, s, deviceCode)
	wantError(t, status, body, "invalid_grant")
	status, body = poll(t, s, "no-such-code")
	wantError(t, status, body, "invalid_grant")

	// without a resource indicator the audience names the client and the issuer only
	auth = startLogin(t, s, url.Values{"client_id": {ClientID}, "scope": {"openid"}})
	s.Approve(auth.str("user_code"), "bob-sub")
	status, tok = poll(t, s, auth.str("device_code"))
	if status != http.StatusOK {
		t.Fatalf("POST /token without a resource = %d: %v", status, tok)
	}
	if want, got := []string{ClientID, s.URL}, verify(t, s, tok.str("access_token")).Audience; !slices.Equal(got, want) {
		t.Errorf("aud = %v, want %v", got, want)
	}
}

func TestDeviceDeniedAndExpired(t *testing.T) {
	s := New(t)
	form := url.Values{"client_id": {ClientID}, "scope": {"openid"}}

	auth := startLogin(t, s, form)
	s.Deny(auth.str("user_code"))
	status, body := poll(t, s, auth.str("device_code"))
	wantError(t, status, body, "access_denied")

	s.SetDeviceTTL(20 * time.Millisecond)
	auth = startLogin(t, s, form)
	s.Approve(auth.str("user_code"), "alice-sub") // too late all the same
	time.Sleep(50 * time.Millisecond)
	status, body = poll(t, s, auth.str("device_code"))
	wantError(t, status, body, "expired_token")
}

func TestRefreshRotation(t *testing.T) {
	s := New(t)
	first := login(t, s, "alice-sub", "openid profile groups offline_access")
	old := first.str("refresh_token")

	s.SetTTL(5 * time.Minute) // a refreshed access token takes the TTL of the server
	before := time.Now()
	status, second := refresh(t, s, old)
	after := time.Now()
	if status != http.StatusOK {
		t.Fatalf("refresh = %d: %v", status, second)
	}
	current := second.str("refresh_token")
	if current == "" || current == old {
		t.Errorf("refresh_token = %q after rotating %q, want a new one", current, old)
	}
	if second.str("token_type") != "Bearer" || second["expires_in"] != float64(300) ||
		second.str("scope") != "openid profile groups offline_access" {
		t.Errorf("token_type = %v, expires_in = %v, scope = %v, want Bearer, 300 and the original scope",
			second["token_type"], second["expires_in"], second["scope"])
	}
	c := verify(t, s, second.str("access_token"))
	if want := []string{APIResource, ClientID, s.URL}; !slices.Equal(c.Audience, want) {
		t.Errorf("aud = %v, want %v", c.Audience, want)
	}
	if c.Scope != "openid profile groups offline_access" || c.Subject != "alice-sub" {
		t.Errorf("scope = %q, sub = %q, want the original scope and alice-sub", c.Scope, c.Subject)
	}
	checkExpiry(t, c.Expiry, 5*time.Minute, before, after)
	if second.str("access_token") == first.str("access_token") {
		t.Error("the refreshed access token equals the first one")
	}

	// the rotated token still works within the grace period, and rotates again
	status, third := refresh(t, s, old)
	if status != http.StatusOK {
		t.Fatalf("refresh with the rotated token within the grace period = %d: %v", status, third)
	}
	if rt := third.str("refresh_token"); rt == "" || rt == old || rt == current {
		t.Errorf("refresh_token = %q, want one that differs from %q and %q", rt, old, current)
	}

	// without grace it does not; the token that was never rotated is not affected
	s.SetRefreshGrace(0)
	status, body := refresh(t, s, old)
	wantError(t, status, body, "invalid_grant")
	if status, body := refresh(t, s, current); status != http.StatusOK {
		t.Errorf("refresh with the current token = %d: %v", status, body)
	}

	status, body = refresh(t, s, "no-such-token")
	wantError(t, status, body, "invalid_grant")
}

func TestRefreshAfterRevoke(t *testing.T) {
	s := New(t)
	alice := login(t, s, "alice-sub", "openid offline_access")
	bob := login(t, s, "bob-sub", "openid offline_access")

	s.RevokeUser("alice-sub")
	status, body := refresh(t, s, alice.str("refresh_token"))
	wantError(t, status, body, "invalid_grant")
	if status, body := refresh(t, s, bob.str("refresh_token")); status != http.StatusOK {
		t.Errorf("refresh for a user that was not revoked = %d: %v", status, body)
	}
}

func TestNoRefreshTokenWithoutOfflineAccess(t *testing.T) {
	s := New(t)
	tok := login(t, s, "alice-sub", "openid profile groups")
	if _, ok := tok["refresh_token"]; ok {
		t.Errorf("the token response has a refresh_token without offline_access: %v", tok)
	}
	if tok.str("access_token") == "" {
		t.Errorf("the token response has no access_token: %v", tok)
	}
}

func TestUnsupportedGrant(t *testing.T) {
	s := New(t)
	for _, grant := range []string{"authorization_code", "client_credentials", "password", ""} {
		t.Run(cmp.Or(grant, "none"), func(t *testing.T) {
			status, body := post(t, s.URL+"/token", url.Values{"grant_type": {grant}, "client_id": {ClientID}})
			wantError(t, status, body, "unsupported_grant_type")
		})
	}
}

// errorRecorder collects the Errorf calls instead of failing the test.
type errorRecorder struct {
	testing.TB
	errs []string
}

func (r *errorRecorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func TestDecisionOnUnknownUserCodeFailsTheTest(t *testing.T) {
	rec := &errorRecorder{TB: t}
	s := New(rec)
	s.Approve("ABCD-EFGH", "alice-sub")
	s.Deny("ABCD-EFGH")
	if len(rec.errs) != 2 {
		t.Errorf("Approve and Deny of an unknown user code reported %d errors, want 2: %q", len(rec.errs), rec.errs)
	}
}

func TestIssueRefreshToken(t *testing.T) {
	s := New(t)
	rt := s.IssueRefreshToken("alice-sub")
	status, got := refresh(t, s, rt)
	if status != http.StatusOK {
		t.Fatalf("refresh = %d: %v", status, got)
	}
	c := verify(t, s, got.str("access_token"))
	if want := []string{APIResource, ClientID, s.URL}; !slices.Equal(c.Audience, want) || c.Subject != "alice-sub" ||
		c.Scope != "openid profile groups offline_access" {
		t.Errorf("aud = %v, sub = %q, scope = %q, want the device flow's audience, alice-sub and its scope", c.Audience, c.Subject, c.Scope)
	}
	if next := got.str("refresh_token"); next == "" || next == rt {
		t.Errorf("refresh_token = %q, want a rotated one", next)
	}

	// It is as good as one from the device flow: revoking the user ends it.
	s.RevokeUser("alice-sub")
	status, body := refresh(t, s, s.IssueRefreshToken("alice-sub"))
	wantError(t, status, body, "invalid_grant")
}
