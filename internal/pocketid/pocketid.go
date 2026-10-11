// Package pocketid talks to Pocket ID's admin REST API to mint the OIDC client a machine
// authenticates as. It never sees a private key: the caller sends the machine's public JWK only, and
// neither the API key nor that key is ever written to an error.
package pocketid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/layertwo/tunnels/internal/httpx"
)

// Client is Pocket ID's REST API as the broker uses it: create and delete OIDC clients.
type Client struct {
	base   string
	apiKey string
	http   *http.Client
}

// New returns a client for the Pocket ID instance at baseURL. apiKey is sent as X-API-KEY.
func New(baseURL, apiKey string, hc *http.Client) *Client {
	return &Client{base: strings.TrimRight(baseURL, "/"), apiKey: apiKey, http: hc}
}

// apiGrant grants an OIDC client access to an API as itself (M2M). Pocket ID requires the permission
// lists even when they are empty.
const apiGrant = `{"clientAccess":true,"clientPermissionIds":[],"userDelegatedPermissionIds":[]}`

// federatedIdentity is one key the client may assert with. The subject defaults to the client id.
type federatedIdentity struct {
	Issuer           string            `json:"issuer"`
	Audience         string            `json:"audience"`
	PublicKeys       []json.RawMessage `json:"publicKeys"`
	ReplayProtection bool              `json:"replayProtection"`
}

type createClientBody struct {
	Name        string `json:"name"`
	IsPublic    bool   `json:"isPublic"`
	Credentials struct {
		FederatedIdentities []federatedIdentity `json:"federatedIdentities"`
	} `json:"credentials"`
}

// CreateClient creates a confidential OIDC client whose only credential is the machine's public JWK,
// then grants it client access to the API, and returns the new client id. If the grant fails the
// client is deleted, so the caller never has to clean up a half-minted client.
func (c *Client) CreateClient(ctx context.Context, name, issuer, audience string, publicKey json.RawMessage, apiID string) (string, error) {
	body := createClientBody{Name: name, IsPublic: false}
	body.Credentials.FederatedIdentities = []federatedIdentity{{
		Issuer: issuer, Audience: audience, PublicKeys: []json.RawMessage{publicKey}, ReplayProtection: true,
	}}
	encoded, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("pocketid: encode client: %w", err)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/oidc/clients", encoded, &created); err != nil {
		return "", err
	}
	if created.ID == "" {
		return "", errors.New("pocketid: the created client has no id")
	}
	if err := c.do(ctx, http.MethodPut, "/api/apis/"+url.PathEscape(apiID)+"/clients/"+url.PathEscape(created.ID), []byte(apiGrant), nil); err != nil {
		_ = c.DeleteClient(ctx, created.ID) // no orphan: without the grant the client cannot be used
		return "", err
	}
	return created.ID, nil
}

// DeleteClient deletes an OIDC client by id.
func (c *Client) DeleteClient(ctx context.Context, clientID string) error {
	return c.do(ctx, http.MethodDelete, "/api/oidc/clients/"+url.PathEscape(clientID), nil, nil)
}

// do sends one request with the API key and fails on any non-2xx, decoding the answer into out when
// out is not nil. The cause of a transport error is unwrapped so a *url.Error's whole URL, and any
// value in it, is not repeated. The API key and the request body are never part of an error.
func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pocketid: build request: %w", err)
	}
	req.Header.Set("X-API-KEY", c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("pocketid: %s %s: %w", method, path, httpx.UnwrapURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("pocketid: %s %s answered %d", method, path, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
			return fmt.Errorf("pocketid: decode %s %s: %w", method, path, err)
		}
	}
	return nil
}
