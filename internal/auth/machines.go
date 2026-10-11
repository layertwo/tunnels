package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// Machine is a broker-owned principal as the API reports it: the handle it publishes as and the
// Pocket ID client id it authenticates with.
type Machine struct {
	Handle   string `json:"handle"`
	ClientID string `json:"clientId"`
}

// CreateMachine asks the broker to register a machine for the caller. Only the public half of the
// key crosses the wire; the private key stays on this machine.
func CreateMachine(ctx context.Context, hc *http.Client, baseURL, accessToken, handle string, publicKey jose.JSONWebKey) (Machine, error) {
	body := struct {
		Handle    string          `json:"handle"`
		PublicKey jose.JSONWebKey `json:"publicKey"`
	}{Handle: handle, PublicKey: publicKey}
	status, raw, err := send(ctx, hc, http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/machines", accessToken, body)
	if err != nil {
		return Machine{}, err
	}
	if status != http.StatusCreated {
		return Machine{}, serviceError(status, raw)
	}
	var m Machine
	if err := json.Unmarshal(raw, &m); err != nil || m.ClientID == "" {
		return Machine{}, errors.New("auth: the service did not create the machine")
	}
	return m, nil
}

// ListMachines returns the caller's own machines.
func ListMachines(ctx context.Context, hc *http.Client, baseURL, accessToken string) ([]Machine, error) {
	status, raw, err := get(ctx, hc, strings.TrimRight(baseURL, "/")+"/api/machines", accessToken)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, serviceError(status, raw)
	}
	var out struct {
		Machines []Machine `json:"machines"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errors.New("auth: the service did not list your machines")
	}
	if out.Machines == nil {
		out.Machines = []Machine{}
	}
	return out.Machines, nil
}

// DeleteMachine revokes a machine by handle.
func DeleteMachine(ctx context.Context, hc *http.Client, baseURL, accessToken, handle string) error {
	status, raw, err := send(ctx, hc, http.MethodDelete, strings.TrimRight(baseURL, "/")+"/api/machines/"+url.PathEscape(handle), accessToken, nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return serviceError(status, raw)
	}
	return nil
}
