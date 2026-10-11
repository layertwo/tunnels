package auth

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/layertwo/tunnels/internal/mockidp"
)

// ---- the machine's key pair

func TestGenerateSaveLoadMachineKey(t *testing.T) {
	key, err := GenerateMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	if key.Algorithm != string(jose.ES256) {
		t.Errorf("Algorithm = %q, want ES256", key.Algorithm)
	}
	priv, ok := key.Key.(*ecdsa.PrivateKey)
	if !ok || priv.Curve.Params().Name != "P-256" {
		t.Fatalf("key = %T, want an ECDSA P-256 private key", key.Key)
	}

	path := filepath.Join(t.TempDir(), MachineKeyFile)
	if err := SaveMachineKey(path, key); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("%s: %v %v, want mode 0600", path, fi, err)
	}
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), `"d"`) {
		t.Error("the stored key has no private component")
	}

	got, err := LoadMachineKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key == nil || got.Key.(*ecdsa.PrivateKey).D.Cmp(priv.D) != 0 {
		t.Error("the loaded key is not the one saved")
	}
}

func TestSaveMachineKeyMarshalError(t *testing.T) {
	if err := SaveMachineKey(filepath.Join(t.TempDir(), MachineKeyFile), jose.JSONWebKey{Key: make(chan int)}); err == nil {
		t.Error("SaveMachineKey of an unmarshalable key succeeded")
	}
}

func TestSaveMachineKeyWriteError(t *testing.T) {
	key, _ := GenerateMachineKey()
	missing := filepath.Join(t.TempDir(), "no-such-dir", MachineKeyFile)
	if err := SaveMachineKey(missing, key); err == nil {
		t.Error("SaveMachineKey into a missing directory succeeded")
	}
}

func TestLoadMachineKeyErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadMachineKey(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("LoadMachineKey of a missing file succeeded")
	}
	damaged := filepath.Join(dir, "damaged.json")
	if err := os.WriteFile(damaged, []byte("<html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMachineKey(damaged); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("LoadMachineKey of a damaged file = %v, want a damaged-file error", err)
	}
}

// ---- the signed assertion

func TestClientAssertion(t *testing.T) {
	key, err := GenerateMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	raw, err := ClientAssertion(key, "machine-1", "https://idp.example", "https://api.example", now)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("the assertion is not an ES256 JWS: %v", err)
	}
	if tok.Headers[0].Algorithm != string(jose.ES256) {
		t.Errorf("alg = %q, want ES256", tok.Headers[0].Algorithm)
	}
	var c jwt.Claims
	if err := tok.Claims(key.Public().Key, &c); err != nil {
		t.Fatalf("the assertion does not verify against the key: %v", err)
	}
	if c.Issuer != "https://idp.example" {
		t.Errorf("iss = %q", c.Issuer)
	}
	if c.Subject != "machine-1" {
		t.Errorf("sub = %q, want the client id", c.Subject)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "https://api.example" {
		t.Errorf("aud = %v", c.Audience)
	}
	if c.IssuedAt == nil || !c.IssuedAt.Time().Equal(now) {
		t.Errorf("iat = %v, want %v", c.IssuedAt, now)
	}
	if c.Expiry == nil || !c.Expiry.Time().Equal(now.Add(assertionLifetime)) {
		t.Errorf("exp = %v, want %v", c.Expiry, now.Add(assertionLifetime))
	}
	if c.ID == "" {
		t.Error("jti is empty")
	}

	again, err := ClientAssertion(key, "machine-1", "https://idp.example", "https://api.example", now)
	if err != nil {
		t.Fatal(err)
	}
	if again == raw {
		t.Error("two assertions are identical; the jti is reused")
	}
}

func TestClientAssertionSignerError(t *testing.T) {
	_, err := ClientAssertion(jose.JSONWebKey{Key: make(chan int)}, "machine-1", "i", "a", time.Now())
	if err == nil || !strings.Contains(err.Error(), "auth:") {
		t.Errorf("ClientAssertion of an unusable key = %v, want an auth error", err)
	}
}

// ---- the exchange at the token endpoint

func TestExchangeAssertion(t *testing.T) {
	o, m := newOIDC(t)
	key, err := GenerateMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	m.AddMachineKey("machine-1", key.Public())

	rec := &recorder{}
	o.HTTP = &http.Client{Transport: rec, Timeout: 10 * time.Second}
	assertion, err := ClientAssertion(key, "machine-1", o.Issuer, o.Resource, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got, err := o.ExchangeAssertion(t.Context(), "machine-1", assertion)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken == "" {
		t.Error("no access token")
	}
	if got.ClientID != "machine-1" || got.RefreshToken != "" {
		t.Errorf("ExchangeAssertion = %+v, want the client id and no refresh token", got)
	}
	if sub := verifies(t, m, got.AccessToken); sub != "client-machine-1" {
		t.Errorf("access token is for %q, want client-machine-1", sub)
	}

	if len(rec.forms) != 1 {
		t.Fatalf("%d token requests, want 1", len(rec.forms))
	}
	form := rec.forms[0]
	for k, want := range map[string]string{
		"grant_type": "client_credentials", "client_id": "machine-1",
		"client_assertion_type": assertionType, "client_assertion": assertion, "resource": mockidp.APIResource,
	} {
		if value := form.Get(k); value != want {
			t.Errorf("token request %s = %q, want %q", k, value, want)
		}
	}
}

// The assertion is single use: the same one cannot be exchanged twice.
func TestExchangeAssertionReplayRefused(t *testing.T) {
	o, m := newOIDC(t)
	key, _ := GenerateMachineKey()
	m.AddMachineKey("machine-1", key.Public())
	assertion, _ := ClientAssertion(key, "machine-1", o.Issuer, o.Resource, time.Now())

	if _, err := o.ExchangeAssertion(t.Context(), "machine-1", assertion); err != nil {
		t.Fatal(err)
	}
	_, err := o.ExchangeAssertion(t.Context(), "machine-1", assertion)
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("second exchange = %v, want invalid_grant", err)
	}
	if err != nil && strings.Contains(err.Error(), assertion) {
		t.Error("the error repeats the assertion")
	}
}

func TestExchangeAssertionErrors(t *testing.T) {
	down := OIDC{Issuer: "http://127.0.0.1:1", ClientID: "c", Resource: "r", HTTP: client()}
	if _, err := down.ExchangeAssertion(t.Context(), "machine-1", "assertion"); err == nil || !strings.Contains(err.Error(), "discover") {
		t.Errorf("ExchangeAssertion without a provider: err = %v, want a discovery error", err)
	}

	// a provider that answers 200 with no access token
	issuer := brokenIDP(t,
		func(http.ResponseWriter, *http.Request) {},
		func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, `{}`) })
	o := OIDC{Issuer: issuer, ClientID: "c", Resource: "r", HTTP: client()}
	if _, err := o.ExchangeAssertion(t.Context(), "machine-1", "assertion"); err == nil || !strings.Contains(err.Error(), "access token") {
		t.Errorf("ExchangeAssertion with an empty answer: err = %v, want a no-access-token error", err)
	}

	// a refused exchange must not echo the assertion back
	refuse := brokenIDP(t,
		func(http.ResponseWriter, *http.Request) {},
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"client_assertion":"assertion"}`)
		})
	o = OIDC{Issuer: refuse, ClientID: "c", Resource: "r", HTTP: client()}
	_, err := o.ExchangeAssertion(t.Context(), "machine-1", "assertion")
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("ExchangeAssertion with no error code: err = %v, want the status", err)
	}
	if err != nil && strings.Contains(err.Error(), "assertion") {
		t.Errorf("the error repeats the assertion: %v", err)
	}
}

// ---- the machine rides the stored login

func TestRefreshStoredMachine(t *testing.T) {
	o, m := newOIDC(t)
	s := Store{Dir: t.TempDir()}
	key, err := GenerateMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Dir, MachineKeyFile)
	if err := SaveMachineKey(path, key); err != nil {
		t.Fatal(err)
	}
	m.AddMachineKey("machine-1", key.Public())

	before := Tokens{AccessToken: "old", ClientID: "machine-1", MachineKey: path, Handle: "bot", Server: "https://tunnels.example"}
	if err := s.Save(before); err != nil {
		t.Fatal(err)
	}
	got, err := RefreshStored(t.Context(), s, o)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken == before.AccessToken || got.AccessToken == "" {
		t.Errorf("the access token was not replaced: %+v", got)
	}
	if sub := verifies(t, m, got.AccessToken); sub != "client-machine-1" {
		t.Errorf("refreshed access token is for %q, want client-machine-1", sub)
	}
	if got.ClientID != "machine-1" || got.MachineKey != path || got.Handle != "bot" || got.Server != "https://tunnels.example" {
		t.Errorf("the machine login was lost: %+v", got)
	}
	if got.RefreshToken != "" || got.ClientSecret != "" {
		t.Errorf("a machine store holds a secret: %+v", got)
	}
	if loaded, err := s.Load(); err != nil || loaded != got {
		t.Errorf("stored = %+v, %v, want what RefreshStored returned", loaded, err)
	}
}

func TestRefreshStoredMachineKeepsFilesWhenTheExchangeFails(t *testing.T) {
	o, _ := newOIDC(t)
	s := Store{Dir: t.TempDir()}
	before := Tokens{AccessToken: "at", ClientID: "machine-1", MachineKey: filepath.Join(s.Dir, "missing-key.json"), Handle: "bot", Server: "https://s"}
	if err := s.Save(before); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshStored(t.Context(), s, o); err == nil {
		t.Fatal("RefreshStored of a machine whose key file is missing succeeded")
	}
	if got, err := s.Load(); err != nil || got != before {
		t.Errorf("stored = %+v, %v, want the login unchanged", got, err)
	}
}

// A key file that parses but is not an ES256 private key fails when the assertion is signed.
func TestRefreshStoredMachineWithAnUnusableKey(t *testing.T) {
	o, _ := newOIDC(t)
	s := Store{Dir: t.TempDir()}
	path := filepath.Join(s.Dir, MachineKeyFile)
	if err := os.WriteFile(path, []byte(`{"kty":"oct","k":"AAAAAAAAAAAAAAAAAAAAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tok := Tokens{ClientID: "machine-1", MachineKey: path, Handle: "bot", Server: "https://s"}
	if err := s.Save(tok); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshStored(t.Context(), s, o); err == nil {
		t.Fatal("RefreshStored with a key the signer cannot use succeeded")
	}
}

// postToken's own failure branches, which the callers never reach with a well-formed endpoint.
func TestPostTokenErrors(t *testing.T) {
	o := OIDC{HTTP: client()}
	if _, err := o.postToken(t.Context(), "http://[::1", nil); err == nil || !strings.Contains(err.Error(), "auth:") {
		t.Errorf("postToken with an invalid URL = %v, want an auth error", err)
	}
	if _, err := o.postToken(t.Context(), "http://127.0.0.1:1/token", nil); err == nil || !strings.Contains(err.Error(), "exchange") {
		t.Errorf("postToken against a closed port = %v, want an exchange error", err)
	}
	readErr := io.ErrUnexpectedEOF
	o.HTTP = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(errBody{readErr})}, nil
	})}
	if _, err := o.postToken(t.Context(), "http://idp.example/token", nil); !errors.Is(err, readErr) {
		t.Errorf("postToken with a body that fails mid-read = %v, want %v", err, readErr)
	}
}

// ---- the machine API

func TestCreateMachine(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth, gotCT = r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"handle":"nas","clientId":"machine-nas"}`)
	}))
	defer srv.Close()

	key, err := GenerateMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	got, err := CreateMachine(t.Context(), client(), srv.URL, "tok-123", "nas", key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if got != (Machine{Handle: "nas", ClientID: "machine-nas"}) {
		t.Errorf("CreateMachine = %+v", got)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/machines" || gotAuth != "Bearer tok-123" || gotCT != "application/json" {
		t.Errorf("asked %s %s with Authorization %q and Content-Type %q", gotMethod, gotPath, gotAuth, gotCT)
	}
	var body struct {
		Handle    string          `json:"handle"`
		PublicKey json.RawMessage `json:"publicKey"`
	}
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatalf("the request body is not JSON: %v (%s)", err, gotBody)
	}
	if body.Handle != "nas" {
		t.Errorf("handle = %q", body.Handle)
	}
	if strings.Contains(string(body.PublicKey), `"d"`) {
		t.Error("the request body carries the private key")
	}
	var public map[string]string
	if err := json.Unmarshal(body.PublicKey, &public); err != nil || public["kty"] != "EC" || public["x"] == "" || public["y"] == "" {
		t.Errorf("publicKey = %s, want an EC public JWK", body.PublicKey)
	}
}

func TestCreateMachineErrors(t *testing.T) {
	status, body := http.StatusConflict, `{"error":"the handle \"nas\" is taken"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer srv.Close()
	key, _ := GenerateMachineKey()

	if _, err := CreateMachine(t.Context(), client(), srv.URL, "tok", "nas", key.Public()); err == nil || err.Error() != `the handle "nas" is taken` {
		t.Errorf("CreateMachine refusal = %v, want the service's sentence", err)
	}

	status, body = http.StatusCreated, `<html>`
	if _, err := CreateMachine(t.Context(), client(), srv.URL, "tok", "nas", key.Public()); err == nil || !strings.Contains(err.Error(), "did not create") {
		t.Errorf("CreateMachine with a bad answer = %v, want a did-not-create error", err)
	}

	status, body = http.StatusCreated, `{"handle":"nas","clientId":""}`
	if _, err := CreateMachine(t.Context(), client(), srv.URL, "tok", "nas", key.Public()); err == nil {
		t.Error("CreateMachine without a client id succeeded")
	}

	if _, err := CreateMachine(t.Context(), client(), "http://127.0.0.1:1", "tok", "nas", key.Public()); err == nil {
		t.Error("CreateMachine against a closed port succeeded")
	}
}

func TestListMachines(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	status, body := http.StatusOK, `{"machines":[{"handle":"nas","clientId":"machine-nas"},{"handle":"pi","clientId":"machine-pi"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer srv.Close()

	got, err := ListMachines(t.Context(), client(), srv.URL, "tok-123")
	want := []Machine{{Handle: "nas", ClientID: "machine-nas"}, {Handle: "pi", ClientID: "machine-pi"}}
	if err != nil || len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("ListMachines = %+v, %v, want %+v", got, err, want)
	}
	if gotMethod != http.MethodGet || gotPath != "/api/machines" || gotAuth != "Bearer tok-123" {
		t.Errorf("asked %s %s with Authorization %q", gotMethod, gotPath, gotAuth)
	}

	status, body = http.StatusOK, `{}`
	if got, err := ListMachines(t.Context(), client(), srv.URL, "tok"); err != nil || got == nil || len(got) != 0 {
		t.Errorf("ListMachines of no field = %+v, %v, want an empty, non-nil list", got, err)
	}

	status, body = http.StatusServiceUnavailable, `{"error":"machines unavailable, try again"}`
	if got, err := ListMachines(t.Context(), client(), srv.URL, "tok"); err == nil || got != nil || err.Error() != "machines unavailable, try again" {
		t.Errorf("ListMachines refusal = %+v, %v", got, err)
	}

	status, body = http.StatusOK, `<html>`
	if _, err := ListMachines(t.Context(), client(), srv.URL, "tok"); err == nil || !strings.Contains(err.Error(), "did not list") {
		t.Errorf("ListMachines with a bad answer = %v, want a did-not-list error", err)
	}

	if _, err := ListMachines(t.Context(), client(), "http://127.0.0.1:1", "tok"); err == nil {
		t.Error("ListMachines against a closed port succeeded")
	}
}

func TestDeleteMachine(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(status)
		if status != http.StatusNoContent {
			io.WriteString(w, `{"error":"no such machine"}`)
		}
	}))
	defer srv.Close()

	if err := DeleteMachine(t.Context(), client(), srv.URL, "tok-123", "nas"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/api/machines/nas" || gotAuth != "Bearer tok-123" {
		t.Errorf("asked %s %s with Authorization %q", gotMethod, gotPath, gotAuth)
	}

	status = http.StatusNotFound
	if err := DeleteMachine(t.Context(), client(), srv.URL, "tok", "nas"); err == nil || err.Error() != "no such machine" {
		t.Errorf("DeleteMachine refusal = %v, want the service's sentence", err)
	}
	if err := DeleteMachine(t.Context(), client(), "http://127.0.0.1:1", "tok", "nas"); err == nil {
		t.Error("DeleteMachine against a closed port succeeded")
	}
}

// An assertion the provider refuses carries the code, never the response body.
func TestAssertionError(t *testing.T) {
	for _, tt := range []struct {
		status int
		body   string
		want   string
	}{
		{400, `{"error":"invalid_grant"}`, "invalid_grant"},
		{400, `<html>`, "400"},
		{400, `{"error":""}`, "400"},
	} {
		got := assertionError(tt.status, []byte(tt.body))
		if !strings.Contains(got.Error(), tt.want) {
			t.Errorf("assertionError(%d, %s) = %q, want it to contain %q", tt.status, tt.body, got, tt.want)
		}
	}
	if got := assertionError(400, []byte(`{"client_assertion":"secret"}`)); strings.Contains(got.Error(), "secret") {
		t.Errorf("assertionError repeats the body: %v", got)
	}
}
