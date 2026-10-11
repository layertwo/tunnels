package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/layertwo/tunnels/internal/names"
	"github.com/layertwo/tunnels/internal/store"
)

// PocketID mints and deletes a machine's OIDC client; pocketid.Client implements it.
type PocketID interface {
	CreateClient(ctx context.Context, name, issuer, audience string, publicKey json.RawMessage, apiID string) (clientID string, err error)
	DeleteClient(ctx context.Context, clientID string) error
}

// machineRefused is what a machine is told when it calls an endpoint only its owner may use.
const machineRefused = "a machine cannot manage shares or machines; use its owner's account"

// ownerOnly resolves the caller and refuses a machine. A machine's Account carries no sub (see
// AccountBySubject), so an endpoint keyed by the caller's sub would otherwise act as the empty sub —
// and a machine must never carry its owner's authority (Decision 12). It writes the status itself and
// returns false, so the caller does nothing more.
func (s *server) ownerOnly(w http.ResponseWriter, r *http.Request) (Account, bool) {
	acct, ok := s.account(w, r)
	if !ok {
		return Account{}, false
	}
	if acct.Sub == "" {
		writeJSON(w, http.StatusForbidden, errorBody(machineRefused))
		return Account{}, false
	}
	return acct, true
}

// machineRequest is the body of POST /api/machines: the handle the owner chose and the machine's public
// key (a JWK object). The private key never leaves the machine.
type machineRequest struct {
	Handle    string          `json:"handle"`
	PublicKey json.RawMessage `json:"publicKey"`
}

// machineJSON is what a machine looks like on the wire: its handle and its Pocket ID client id.
type machineJSON struct {
	Handle   string `json:"handle"`
	ClientID string `json:"clientId"`
}

// machinesCreate bootstraps a machine for the caller: it mints the Pocket ID client that holds the
// machine's public key, then records the machine. The client is created first, so a mint that fails
// leaves nothing; a client whose row insert fails is deleted, so there is no orphan (Review Focus 6).
func (s *server) machinesCreate(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.ownerOnly(w, r)
	if !ok {
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	var body machineRequest
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid machine"))
		return
	}
	var jwk map[string]json.RawMessage
	if len(body.PublicKey) == 0 || json.Unmarshal(body.PublicKey, &jwk) != nil || len(jwk) == 0 {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid public key"))
		return
	}
	// Anything after the first JSON value is not the machine the caller asked for.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid machine"))
		return
	}
	// Lowercased before ValidHandle, because Task 1's uniqueness is exact and a handle is lowercase.
	handle := strings.ToLower(body.Handle)
	if !names.ValidHandle(handle) || reservedHandle(s.cfg.Reserved, handle) {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid handle"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultDecisionTimeout)
	defer cancel()

	clientID, err := s.d.PocketID.CreateClient(ctx, "machine-"+handle, s.cfg.Issuer, s.cfg.APIResource, body.PublicKey, s.cfg.PocketIDAPIID)
	if err != nil {
		s.d.Log.Warn("api/machines: could not mint the client", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, errorBody("could not create the machine, try again"))
		return
	}
	err = s.d.Machines.CreateMachine(ctx, store.Machine{Handle: handle, OwnerKind: "user", OwnerRef: acct.Sub, ClientID: clientID, CreatedBy: acct.Sub})
	switch {
	case errors.Is(err, store.ErrHandleTaken):
		_ = s.d.PocketID.DeleteClient(ctx, clientID) // roll back: the row is not there
		writeJSON(w, http.StatusConflict, errorBody("the handle "+strconv.Quote(handle)+" is taken"))
	case err != nil:
		_ = s.d.PocketID.DeleteClient(ctx, clientID)
		s.d.Log.Warn("api/machines: could not store the machine", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, errorBody("could not create the machine, try again"))
	default:
		writeJSON(w, http.StatusCreated, machineJSON{Handle: handle, ClientID: clientID})
	}
}

// machinesList reports the caller's own machines.
func (s *server) machinesList(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.ownerOnly(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultDecisionTimeout)
	defer cancel()

	machines, err := s.d.Machines.MachinesByOwner(ctx, acct.Sub)
	if err != nil {
		s.d.Log.Warn("api/machines: could not list the machines", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, errorBody("machines unavailable, try again"))
		return
	}
	out := make([]machineJSON, 0, len(machines))
	for _, m := range machines {
		out = append(out, machineJSON{Handle: m.Handle, ClientID: m.ClientID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"machines": out})
}

// machinesDelete revokes one of the caller's machines: the row first (the revocation lever), then its
// Pocket ID client (cleanup). A client that is gone from the table but has no row can do nothing.
func (s *server) machinesDelete(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.ownerOnly(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultDecisionTimeout)
	defer cancel()

	m, err := s.d.Machines.MachineByHandle(ctx, strings.ToLower(r.PathValue("handle")))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.d.Log.Warn("api/machines: could not look up the machine", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, errorBody("machines unavailable, try again"))
		return
	}
	// A machine another account owns is not there as far as this caller can tell: no enumeration.
	if errors.Is(err, store.ErrNotFound) || m.OwnerRef != acct.Sub {
		writeJSON(w, http.StatusNotFound, errorBody("no such machine"))
		return
	}
	if err := s.d.Machines.DeleteMachine(ctx, m.ClientID); err != nil {
		s.d.Log.Warn("api/machines: could not delete the machine", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, errorBody("machines unavailable, try again"))
		return
	}
	if err := s.d.PocketID.DeleteClient(ctx, m.ClientID); err != nil {
		// The row is the revocation lever; a client that could not be cleaned up only leaves litter.
		s.d.Log.Warn("api/machines: deleted the machine but not its client", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// reservedHandle reports whether handle is one nobody gets, compared case-insensitively.
func reservedHandle(list []string, handle string) bool {
	for _, r := range list {
		if strings.EqualFold(r, handle) {
			return true
		}
	}
	return false
}
