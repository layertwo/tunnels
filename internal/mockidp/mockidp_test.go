package mockidp

import (
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

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
