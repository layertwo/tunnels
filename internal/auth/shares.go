package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// Share grants one user or group access to one tunnel. The empty Tunnel is the default tunnel.
type Share struct {
	Tunnel  string `json:"tunnel"`
	Kind    string `json:"kind"`
	Grantee string `json:"grantee"`
}

// PutShare grants the share. Putting a share that is already there does nothing.
func PutShare(ctx context.Context, hc *http.Client, baseURL, accessToken string, sh Share) error {
	return changeShare(ctx, hc, http.MethodPut, baseURL, accessToken, sh)
}

// DeleteShare removes the share. Deleting a share that is not there does nothing.
func DeleteShare(ctx context.Context, hc *http.Client, baseURL, accessToken string, sh Share) error {
	return changeShare(ctx, hc, http.MethodDelete, baseURL, accessToken, sh)
}

func changeShare(ctx context.Context, hc *http.Client, method, baseURL, accessToken string, sh Share) error {
	status, body, err := send(ctx, hc, method, strings.TrimRight(baseURL, "/")+"/api/shares", accessToken, sh)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return serviceError(status, body)
	}
	return nil
}

// ListShares returns the caller's own shares.
func ListShares(ctx context.Context, hc *http.Client, baseURL, accessToken string) ([]Share, error) {
	status, body, err := get(ctx, hc, strings.TrimRight(baseURL, "/")+"/api/shares", accessToken)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, serviceError(status, body)
	}
	var out struct {
		Shares []Share `json:"shares"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, errors.New("auth: the service did not list your shares")
	}
	if out.Shares == nil {
		out.Shares = []Share{}
	}
	return out.Shares, nil
}
