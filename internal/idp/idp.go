// Package idp is the broker's view of an OpenID Connect identity provider: it checks the access
// tokens the provider issued and looks up who they belong to. It needs nothing beyond the standard
// discovery document, JWT access tokens and the userinfo endpoint.
package idp

import (
	"cmp"
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

// Identity is the account behind an access token. Username and Groups come from the userinfo claims
// named in New; a claim the provider leaves out stays empty.
type Identity struct {
	Sub, Username string
	Groups        []string
}

// ErrInvalidToken says the identity provider refused the token: it is malformed, expired,
// not meant for us or revoked. Any other error means the question could not be answered.
var ErrInvalidToken = errors.New("idp: invalid token")

// Client asks one identity provider about access tokens.
type Client struct {
	hc       *http.Client
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier

	usernameClaim, groupsClaim string
}

// New discovers the identity provider at issuer. Access tokens must be addressed to apiResource.
// All requests carry userAgent and give up after 10 seconds. The username and the group names are
// read from the userinfo claims usernameClaim and groupsClaim; "" means preferred_username and
// groups.
func New(ctx context.Context, issuer, apiResource, userAgent, usernameClaim, groupsClaim string) (*Client, error) {
	hc := httpx.Client(userAgent, 10*time.Second)
	// ctx bounds the discovery only. go-oidc keeps just hc from it (it fetches the key set later
	// on a context of its own), so ctx may end once New returns; the tests check both.
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, hc), issuer)
	if err != nil {
		return nil, fmt.Errorf("idp: discover %s: %w", issuer, err)
	}
	c := &Client{
		hc:            hc,
		provider:      provider,
		verifier:      provider.Verifier(&oidc.Config{ClientID: apiResource}),
		usernameClaim: cmp.Or(usernameClaim, "preferred_username"),
		groupsClaim:   cmp.Or(groupsClaim, "groups"),
	}
	return c, nil
}

// UserInfo asks the userinfo endpoint who accessToken belongs to. The identity provider decides
// whether the token is good, so a revoked token is caught here and not by VerifyAccessToken.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (Identity, error) {
	if accessToken == "" {
		return Identity{}, fmt.Errorf("%w: empty token", ErrInvalidToken)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.provider.UserInfoEndpoint(), nil)
	if err != nil {
		return Identity{}, fmt.Errorf("idp: build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("idp: userinfo request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return Identity{}, fmt.Errorf("%w: userinfo answered %d", ErrInvalidToken, resp.StatusCode)
	default:
		return Identity{}, fmt.Errorf("idp: userinfo answered %d", resp.StatusCode)
	}

	var claims map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&claims); err != nil {
		return Identity{}, fmt.Errorf("idp: decode userinfo: %w", err)
	}
	var id Identity
	for _, f := range []struct {
		name string
		dst  any
	}{{"sub", &id.Sub}, {c.usernameClaim, &id.Username}, {c.groupsClaim, &id.Groups}} {
		raw, ok := claims[f.name]
		if !ok {
			continue
		}
		if err := json.Unmarshal(raw, f.dst); err != nil {
			return Identity{}, fmt.Errorf("idp: userinfo claim %q: %w", f.name, err)
		}
	}
	if id.Sub == "" {
		return Identity{}, errors.New("idp: userinfo has no sub")
	}
	return id, nil
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
