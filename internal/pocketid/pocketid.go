// Package pocketid checks the access tokens Pocket ID issued and looks up who they belong to.
package pocketid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/layertwo/tunnels/internal/httpx"
)

// Identity is the account behind an access token.
type Identity struct {
	Sub, Username string
	Groups        []string
}

// ErrInvalidToken says the identity provider refused the token: it is malformed, expired,
// not meant for us or revoked. Any other error means the question could not be answered.
var ErrInvalidToken = errors.New("pocketid: invalid token")

// Client asks one Pocket ID instance about access tokens.
type Client struct {
	hc       *http.Client
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// New discovers the identity provider at issuer. Access tokens must be addressed to apiResource.
// All requests carry userAgent and give up after 10 seconds.
func New(ctx context.Context, issuer, apiResource, userAgent string) (*Client, error) {
	hc := httpx.Client(userAgent, 10*time.Second)
	// ctx bounds the discovery only. go-oidc keeps just hc from it (it fetches the key set later
	// on a context of its own), so ctx may end once New returns; the tests check both.
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, hc), issuer)
	if err != nil {
		return nil, fmt.Errorf("pocketid: discover %s: %w", issuer, err)
	}
	return &Client{
		hc:       hc,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: apiResource}),
	}, nil
}

// UserInfo asks the userinfo endpoint who accessToken belongs to. The identity provider decides
// whether the token is good, so a revoked token is caught here and not by VerifyAccessToken.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (Identity, error) {
	if accessToken == "" {
		return Identity{}, fmt.Errorf("%w: empty token", ErrInvalidToken)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.provider.UserInfoEndpoint(), nil)
	if err != nil {
		return Identity{}, fmt.Errorf("pocketid: build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("pocketid: userinfo request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return Identity{}, fmt.Errorf("%w: userinfo answered %d", ErrInvalidToken, resp.StatusCode)
	default:
		return Identity{}, fmt.Errorf("pocketid: userinfo answered %d", resp.StatusCode)
	}

	var claims struct {
		Sub               string   `json:"sub"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&claims); err != nil {
		return Identity{}, fmt.Errorf("pocketid: decode userinfo: %w", err)
	}
	if claims.Sub == "" {
		return Identity{}, errors.New("pocketid: userinfo has no sub")
	}
	return Identity{Sub: claims.Sub, Username: claims.PreferredUsername, Groups: claims.Groups}, nil
}

// VerifyAccessToken checks the signature, issuer, audience and expiry of the JWT raw, without
// asking the identity provider, and returns its subject. Every failure is an ErrInvalidToken.
func (c *Client) VerifyAccessToken(ctx context.Context, raw string) (sub string, err error) {
	tok, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return tok.Subject, nil
}
