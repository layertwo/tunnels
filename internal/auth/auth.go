package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// maxBody bounds what is read from the service.
const maxBody = 1 << 20

// Bootstrap is the document at /.well-known/tunnels.json: where to log in and where to connect.
type Bootstrap struct {
	Issuer        string `json:"issuer"`
	CLIClientID   string `json:"cli_client_id"`
	APIResource   string `json:"api_resource"`
	ServiceHost   string `json:"service_host"`
	SitesDomain   string `json:"sites_domain"`
	MinCLIVersion string `json:"min_cli_version"`
}

// Discover fetches the bootstrap document of the service at baseURL (scheme and host).
func Discover(ctx context.Context, hc *http.Client, baseURL string) (Bootstrap, error) {
	status, body, err := get(ctx, hc, strings.TrimRight(baseURL, "/")+"/.well-known/tunnels.json", "")
	if err != nil {
		return Bootstrap{}, err
	}
	if status != http.StatusOK {
		return Bootstrap{}, fmt.Errorf("auth: tunnels.json answered %d", status)
	}
	var b Bootstrap
	if err := json.Unmarshal(body, &b); err != nil {
		return Bootstrap{}, fmt.Errorf("auth: decode tunnels.json: %w", err)
	}
	// MinCLIVersion is advice; the rest is needed to log in and to publish.
	for _, f := range []struct{ name, value string }{{"issuer", b.Issuer}, {"cli_client_id", b.CLIClientID},
		{"api_resource", b.APIResource}, {"service_host", b.ServiceHost}, {"sites_domain", b.SitesDomain}} {
		if f.value == "" {
			return Bootstrap{}, fmt.Errorf("auth: tunnels.json has no %s", f.name)
		}
	}
	return b, nil
}

// Me is who the service says a token belongs to.
type Me struct {
	Sub      string `json:"sub"`
	Username string `json:"username"`
	Handle   string `json:"handle"`
}

// GetMe asks the service at baseURL who accessToken is. When the service refuses, the error is its
// own sentence ({"error": "..."}), which says what the person can do.
func GetMe(ctx context.Context, hc *http.Client, baseURL, accessToken string) (Me, error) {
	status, body, err := get(ctx, hc, strings.TrimRight(baseURL, "/")+"/api/me", accessToken)
	if err != nil {
		return Me{}, err
	}
	if status != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return Me{}, errors.New(e.Error)
		}
		return Me{}, fmt.Errorf("the service answered %d", status)
	}
	var me Me
	if err := json.Unmarshal(body, &me); err != nil || me.Handle == "" {
		return Me{}, errors.New("auth: the service did not say who you are")
	}
	return me, nil
}

// get returns the status and the first megabyte of the body. A bearer token is sent when given.
func get(ctx context.Context, hc *http.Client, url, bearer string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("auth: %w", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("auth: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return 0, nil, fmt.Errorf("auth: read %s: %w", url, err)
	}
	return resp.StatusCode, body, nil
}

// OIDC is the identity provider as the CLI uses it: a public client of Issuer that asks for tokens
// meant for Resource.
type OIDC struct {
	Issuer, ClientID, Resource string
	HTTP                       *http.Client
}

var scopes = []string{"openid", "profile", "groups", "offline_access"}

// config finds the provider's endpoints. The returned context makes o.HTTP the client of every
// request oauth2 and go-oidc make.
func (o OIDC) config(ctx context.Context) (context.Context, *oauth2.Config, error) {
	ctx = oidc.ClientContext(ctx, o.HTTP)
	p, err := oidc.NewProvider(ctx, o.Issuer)
	if err != nil {
		return ctx, nil, fmt.Errorf("auth: discover %s: %w", o.Issuer, err)
	}
	ep := p.Endpoint()
	ep.AuthStyle = oauth2.AuthStyleInParams // a public client: client_id in the body, no secret
	return ctx, &oauth2.Config{ClientID: o.ClientID, Endpoint: ep, Scopes: scopes}, nil
}

// DeviceLogin runs the device flow: it prints where to go and the code to enter on out, then polls
// until the person approves. The tokens come back without Handle and Server.
func (o OIDC) DeviceLogin(ctx context.Context, out io.Writer) (Tokens, error) {
	ctx, cfg, err := o.config(ctx)
	if err != nil {
		return Tokens{}, err
	}
	if cfg.Endpoint.DeviceAuthURL == "" {
		return Tokens{}, fmt.Errorf("auth: %s has no device authorization endpoint, so the CLI cannot log in there", o.Issuer)
	}
	// The resource is asked for here, once: the provider stamps it as the audience of this grant.
	da, err := cfg.DeviceAuth(ctx, oauth2.SetAuthURLParam("resource", o.Resource))
	if err != nil {
		return Tokens{}, fmt.Errorf("auth: start the login: %w", err)
	}
	if da.VerificationURIComplete != "" {
		fmt.Fprintf(out, "To log in, open:\n\n    %s\n\nor open %s and enter the code %s\n", da.VerificationURIComplete, da.VerificationURI, da.UserCode)
	} else {
		fmt.Fprintf(out, "To log in, open:\n\n    %s\n\nand enter the code %s\n", da.VerificationURI, da.UserCode)
	}
	fmt.Fprintln(out, "\nWaiting for you to approve it...")

	tok, err := cfg.DeviceAccessToken(ctx, da)
	if err != nil {
		var re *oauth2.RetrieveError
		switch {
		case ctx.Err() != nil:
			return Tokens{}, ctx.Err()
		case errors.As(err, &re) && re.ErrorCode == "access_denied":
			return Tokens{}, errors.New("the login was denied")
		case errors.As(err, &re) && re.ErrorCode == "expired_token", errors.Is(err, context.DeadlineExceeded):
			return Tokens{}, errors.New("the login code expired before it was approved; run: tunnel login again")
		}
		return Tokens{}, fmt.Errorf("auth: wait for the login: %w", err)
	}
	return Tokens{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken}, nil
}

// Refresh exchanges a refresh token for a new access token and the rotated refresh token. It asks
// for no resource: the provider keeps the audience of the original grant.
func (o OIDC) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	if refreshToken == "" {
		return Tokens{}, errors.New("auth: there is no refresh token; run: tunnel login")
	}
	ctx, cfg, err := o.config(ctx)
	if err != nil {
		return Tokens{}, err
	}
	tok, err := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.ErrorCode == "invalid_grant" {
			return Tokens{}, errors.New("auth: the login has expired or was revoked; run: tunnel login")
		}
		return Tokens{}, fmt.Errorf("auth: refresh: %w", err)
	}
	return Tokens{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken}, nil
}

// RefreshStored refreshes the stored login. It reads the files first, so a token that another running
// process rotated is the one used, and it writes them only when the refresh worked: a failure leaves
// the files as they were.
//
// ponytail: no lock between processes. Two that refresh in the same second both start from the old
// token, which the provider still accepts for a grace period (60 s at Pocket ID); the last to save wins.
// A file lock if a provider ever has no grace.
func RefreshStored(ctx context.Context, s Store, o OIDC) (Tokens, error) {
	t, err := s.Load()
	if err != nil {
		return Tokens{}, err
	}
	fresh, err := o.Refresh(ctx, t.RefreshToken)
	if err != nil {
		return Tokens{}, err
	}
	t.AccessToken, t.RefreshToken = fresh.AccessToken, fresh.RefreshToken
	if err := s.Save(t); err != nil {
		return Tokens{}, err
	}
	return t, nil
}

// KeepFresh refreshes the stored login every `every` until ctx ends. A failed refresh is reported to
// onErr (which may be nil) and tried again at the next tick: the access token in the file stays good
// for its lifetime, so one failure is not the end of a tunnel.
func KeepFresh(ctx context.Context, s Store, o OIDC, every time.Duration, onErr func(error)) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if _, err := RefreshStored(ctx, s, o); err != nil && onErr != nil && ctx.Err() == nil {
				onErr(err)
			}
		}
	}
}
