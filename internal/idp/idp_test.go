package idp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/layertwo/tunnels/internal/mockidp"
)

const userAgent = "tunnels-test/1"

// newMock starts a mock identity provider that knows the user alice.
func newMock(t *testing.T) *mockidp.Server {
	t.Helper()
	mock := mockidp.New(t)
	mock.AddUser(mockidp.User{Sub: "u-alice", Username: "alice", Groups: []string{"tunnels-creators"}})
	return mock
}

// newClient returns a client for the identity provider at issuer. The context it hands to New ends
// when this helper returns: the client must keep working without it.
func newClient(t *testing.T, issuer string, claims ...string) *Client {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	claims = append(claims, "", "")
	c, err := New(ctx, issuer, mockidp.APIResource, userAgent, claims[0], claims[1])
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// fakeIdP serves a discovery document of its own that takes its signing keys from mock and sends
// /userinfo to userinfo.
func fakeIdP(t *testing.T, mock *mockidp.Server, userinfo http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		self := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":            self,
			"jwks_uri":          mock.URL + "/jwks",
			"userinfo_endpoint": self + "/userinfo",
		})
	})
	mux.HandleFunc("GET /userinfo", userinfo)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// wantInvalidToken fails the test unless err says that the token is invalid.
func wantInvalidToken(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

// wantOtherError fails the test unless err is an error that does not say the token is invalid.
func wantOtherError(t *testing.T, err error) {
	t.Helper()
	if err == nil || errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v, want an error other than ErrInvalidToken", err)
	}
}

func TestUserInfo(t *testing.T) {
	mock := newMock(t)
	c := newClient(t, mock.URL)

	got, err := c.UserInfo(t.Context(), mock.Issue("u-alice", mockidp.IssueOpts{}))
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	want := Identity{Sub: "u-alice", Username: "alice", Groups: []string{"tunnels-creators"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("UserInfo = %+v, want %+v", got, want)
	}
}

func TestUserInfoRejectsTokenWithoutIssuerAudience(t *testing.T) {
	mock := newMock(t)
	c := newClient(t, mock.URL)
	token := mock.Issue("u-alice", mockidp.IssueOpts{Audience: []string{mockidp.APIResource, mockidp.ClientID}})

	_, err := c.UserInfo(t.Context(), token)
	wantInvalidToken(t, err)
}

func TestUserInfoRejectsTokenWithoutOpenidScope(t *testing.T) {
	mock := newMock(t)
	c := newClient(t, mock.URL)
	token := mock.Issue("u-alice", mockidp.IssueOpts{Scope: "profile groups"})

	_, err := c.UserInfo(t.Context(), token)
	wantInvalidToken(t, err)
}

func TestUserInfoRejectsExpiredAndGarbage(t *testing.T) {
	mock := newMock(t)
	c := newClient(t, mock.URL)

	for name, token := range map[string]string{
		"expired": mock.Issue("u-alice", mockidp.IssueOpts{TTL: -time.Minute}),
		"garbage": "not-a-jwt",
		"empty":   "",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.UserInfo(t.Context(), token)
			wantInvalidToken(t, err)
		})
	}
}

func TestUserInfoServerErrorIsNotInvalidToken(t *testing.T) {
	mock := newMock(t)
	idp := fakeIdP(t, mock, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	c := newClient(t, idp.URL)
	token := mock.Issue("u-alice", mockidp.IssueOpts{})

	// The IdP answers HTTP 500.
	_, err := c.UserInfo(t.Context(), token)
	wantOtherError(t, err)

	// The IdP is gone.
	idp.Close()
	_, err = c.UserInfo(t.Context(), token)
	wantOtherError(t, err)
}

func TestVerifyAccessToken(t *testing.T) {
	mock := newMock(t)
	c := newClient(t, mock.URL)

	sub, err := c.VerifyAccessToken(t.Context(), mock.Issue("u-alice", mockidp.IssueOpts{}))
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if sub != "u-alice" {
		t.Errorf("sub = %q, want %q", sub, "u-alice")
	}
}

func TestVerifyAccessTokenRefuses(t *testing.T) {
	mock := newMock(t)
	other := mockidp.New(t) // another issuer, with another key
	c := newClient(t, mock.URL)
	// An issuer of its own that takes its keys from mock: mock's tokens verify against these keys
	// but name the wrong issuer, so only the issuer check can refuse them.
	elsewhere := newClient(t, fakeIdP(t, mock, func(http.ResponseWriter, *http.Request) {}).URL)

	// mock's header and claims under another key's signature: only the signature check can refuse it.
	good := strings.Split(mock.Issue("u-alice", mockidp.IssueOpts{}), ".")
	foreign := strings.Split(other.Issue("u-alice", mockidp.IssueOpts{}), ".")
	forged := good[0] + "." + good[1] + "." + foreign[2]

	tests := []struct {
		name   string
		client *Client
		token  string
	}{
		{"audience lacks the API resource", c, mock.Issue("u-alice", mockidp.IssueOpts{Audience: []string{mockidp.ClientID, mock.URL}})},
		{"wrong issuer only", elsewhere, strings.Join(good, ".")},
		{"bad signature only", c, forged},
		{"wrong issuer and other key", c, other.Issue("u-alice", mockidp.IssueOpts{})},
		{"expired", c, mock.Issue("u-alice", mockidp.IssueOpts{TTL: -time.Minute})},
		{"garbage", c, "not-a-jwt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.client.VerifyAccessToken(t.Context(), tt.token)
			wantInvalidToken(t, err)
		})
	}
}

func TestSendsUserAgent(t *testing.T) {
	mock := newMock(t)
	c := newClient(t, mock.URL) // discovery

	token := mock.Issue("u-alice", mockidp.IssueOpts{})
	if _, err := c.UserInfo(t.Context(), token); err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if _, err := c.VerifyAccessToken(t.Context(), token); err != nil { // fetches the JWKS
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	agents := mock.UserAgents()
	if len(agents) < 3 {
		t.Fatalf("mock saw %d requests, want at least discovery, userinfo and JWKS", len(agents))
	}
	for _, got := range agents {
		if got != userAgent {
			t.Errorf("User-Agent = %q, want %q", got, userAgent)
		}
	}
}

func TestNewFailsWhenDiscoveryFails(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()

	if _, err := New(t.Context(), srv.URL, mockidp.APIResource, userAgent, "", ""); err == nil {
		t.Error("New succeeded against a server that is gone")
	}
}

func TestNewHonoursCallerDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select { // a slow IdP; give up as soon as the client hangs up
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := New(ctx, srv.URL, mockidp.APIResource, userAgent, "", ""); err == nil {
		t.Error("New succeeded against an IdP that never answers")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("New took %v with a 100ms deadline, want it to give up right after", elapsed)
	}
}

func TestCallerDeadlineIsHonoured(t *testing.T) {
	mock := newMock(t)
	idp := fakeIdP(t, mock, func(_ http.ResponseWriter, r *http.Request) {
		select { // a slow IdP; give up as soon as the client hangs up
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	})
	c := newClient(t, idp.URL)
	token := mock.Issue("u-alice", mockidp.IssueOpts{})

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.UserInfo(ctx, token)
	wantOtherError(t, err)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("UserInfo took %v with a 100ms deadline, want it to give up right after", elapsed)
	}
}

// userinfoJSON answers every userinfo request with body.
func userinfoJSON(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}
}

// Providers differ in what they call the username and the groups: New takes the claim names.
func TestUserInfoClaimNames(t *testing.T) {
	mock := newMock(t)
	alice := Identity{Sub: "u1", Username: "alice", Groups: []string{"tunnels-creators"}}
	tests := []struct {
		name   string
		body   string
		claims []string // username and groups claim names
		want   Identity // compared unless the call must fail
		fail   bool     // an error that is not ErrInvalidToken
	}{
		{"defaults", `{"sub":"u1","preferred_username":"alice","groups":["tunnels-creators"]}`, nil, alice, false},
		{"custom names", `{"sub":"u1","nickname":"alice","roles":["tunnels-creators"],"preferred_username":"x","groups":["x"]}`,
			[]string{"nickname", "roles"}, alice, false},
		{"empty names keep the defaults", `{"sub":"u1","preferred_username":"alice","groups":["tunnels-creators"]}`,
			[]string{"", ""}, alice, false},
		{"claims absent", `{"sub":"u1"}`, nil, Identity{Sub: "u1"}, false},
		{"groups null", `{"sub":"u1","preferred_username":"alice","groups":null}`, nil, Identity{Sub: "u1", Username: "alice"}, false},
		{"groups is a string", `{"sub":"u1","preferred_username":"alice","groups":"tunnels-creators"}`, nil, Identity{}, true},
		{"groups hold numbers", `{"sub":"u1","preferred_username":"alice","groups":[1,2]}`, nil, Identity{}, true},
		{"username is a number", `{"sub":"u1","preferred_username":7}`, nil, Identity{}, true},
		{"sub is a number", `{"sub":7}`, nil, Identity{}, true},
		{"custom group claim is the wrong type", `{"sub":"u1","roles":"x"}`, []string{"", "roles"}, Identity{}, true},
		{"body is not json", `<html>not json</html>`, nil, Identity{}, true},
		{"no sub", `{"preferred_username":"alice","groups":["tunnels-creators"]}`, nil, Identity{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t, fakeIdP(t, mock, userinfoJSON(tt.body)).URL, tt.claims...)
			got, err := c.UserInfo(t.Context(), "token")
			if tt.fail {
				wantOtherError(t, err)
				return
			}
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UserInfo = %+v, %v, want %+v", got, err, tt.want)
			}
		})
	}
}

// A userinfo endpoint the provider advertises but that cannot become a request (here: an unclosed
// IPv6 host) is a "could not ask" error, not an invalid token.
func TestUserInfoUnbuildableRequest(t *testing.T) {
	mock := newMock(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":            "http://" + r.Host,
			"jwks_uri":          mock.URL + "/jwks",
			"userinfo_endpoint": "http://[::1",
		})
	}))
	t.Cleanup(srv.Close)
	c := newClient(t, srv.URL)

	_, err := c.UserInfo(t.Context(), "token")
	wantOtherError(t, err)
}

// A provider without a userinfo endpoint cannot say who a token belongs to. Refuse it when the
// broker starts, rather than refusing every login later with "login unavailable".
func TestNewNeedsAUserinfoEndpoint(t *testing.T) {
	mock := newMock(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": "http://" + r.Host, "jwks_uri": mock.URL + "/jwks"})
	}))
	t.Cleanup(srv.Close)
	if _, err := New(t.Context(), srv.URL, mockidp.APIResource, userAgent, "", ""); err == nil || !strings.Contains(err.Error(), "userinfo") {
		t.Errorf("New = %v, want an error about the missing userinfo endpoint", err)
	}
}
