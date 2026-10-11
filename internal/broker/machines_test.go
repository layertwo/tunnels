package broker

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/layertwo/tunnels/internal/mockidp"
	"github.com/layertwo/tunnels/internal/store"
)

// fakePocketID is an in-memory PocketID that records every call and can fail either way.
type fakePocketID struct {
	clientID  string
	createErr error
	deleteErr error
	creates   []pocketIDCreate
	deletes   []string
	steps     *[]string // when set, shares a sequence with the machines fake
}

// pocketIDCreate is one CreateClient call.
type pocketIDCreate struct {
	name, issuer, audience, apiID string
	publicKey                     json.RawMessage
}

func (f *fakePocketID) CreateClient(_ context.Context, name, issuer, audience string, publicKey json.RawMessage, apiID string) (string, error) {
	if f.steps != nil {
		*f.steps = append(*f.steps, "CreateClient")
	}
	f.creates = append(f.creates, pocketIDCreate{name, issuer, audience, apiID, publicKey})
	if f.createErr != nil {
		return "", f.createErr
	}
	return f.clientID, nil
}

func (f *fakePocketID) DeleteClient(_ context.Context, clientID string) error {
	if f.steps != nil {
		*f.steps = append(*f.steps, "DeleteClient")
	}
	f.deletes = append(f.deletes, clientID)
	return f.deleteErr
}

// alice is a creator; a machine token for a machine registered in the rig.
func machineToken(r *serverRig, clientID string) string {
	r.machines.machines[clientID] = store.Machine{Handle: "nas", OwnerRef: "sub-bob", ClientID: clientID}
	return r.idp.Issue("client-"+clientID, mockidp.IssueOpts{})
}

const goodJWK = `{"kty":"EC","crv":"P-256","x":"abc","y":"def"}`

func machinesSteps(r *serverRig) *[]string {
	steps := &[]string{}
	r.machines.steps = steps
	r.pocket.steps = steps
	return steps
}

func TestMachinesCreate(t *testing.T) {
	r := newServerRig(t)
	steps := machinesSteps(r)
	w := r.do("POST", "/api/machines", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), `{"handle":"nas","publicKey":`+goodJWK+`}`)
	if w.Code != 201 || strings.TrimSpace(w.Body.String()) != `{"handle":"nas","clientId":"client-123"}` {
		t.Fatalf("= %d %q, want 201 with the client id", w.Code, w.Body)
	}
	if len(r.pocket.creates) != 1 {
		t.Fatalf("CreateClient calls = %+v", r.pocket.creates)
	}
	if c := r.pocket.creates[0]; c.name != "machine-nas" || c.issuer != r.cfg.Issuer || c.audience != r.cfg.APIResource || c.apiID != r.cfg.PocketIDAPIID || string(c.publicKey) != goodJWK {
		t.Errorf("CreateClient args = %+v", c)
	}
	want := store.Machine{Handle: "nas", OwnerKind: "user", OwnerRef: "sub-alice", ClientID: "client-123", CreatedBy: "sub-alice"}
	if got := r.machines.created; len(got) != 1 || got[0] != want {
		t.Errorf("stored = %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(*steps, []string{"CreateClient", "CreateMachine"}) {
		t.Errorf("steps = %v, want the client minted before the row", *steps)
	}
}

// A handle a person could type in any case lands lowercased, as Task 1's uniqueness is exact.
func TestMachinesCreateLowercasesTheHandle(t *testing.T) {
	r := newServerRig(t)
	w := r.do("POST", "/api/machines", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), `{"handle":"NAS","publicKey":`+goodJWK+`}`)
	if w.Code != 201 || strings.TrimSpace(w.Body.String()) != `{"handle":"nas","clientId":"client-123"}` {
		t.Fatalf("= %d %q, want the lowercased handle", w.Code, w.Body)
	}
	if got := r.machines.created; len(got) != 1 || got[0].Handle != "nas" {
		t.Errorf("stored = %+v, want the lowercased handle", got)
	}
}

func TestMachinesCreateRejectsBadHandles(t *testing.T) {
	handles := map[string]string{
		"empty":         ``,
		"too short":     `"a"`,
		"a dash":        `"al-ice"`,
		"too long":      `"` + strings.Repeat("a", 21) + `"`,
		"an underscore": `"nas_x"`,
		"reserved":      `"admin"`,
		"reserved case": `"ADMIN"`,
	}
	for name, handle := range handles {
		t.Run(name, func(t *testing.T) {
			r := newServerRig(t)
			w := r.do("POST", "/api/machines", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), `{"handle":`+handle+`,"publicKey":`+goodJWK+`}`)
			if w.Code != 400 {
				t.Errorf("handle %s = %d %q, want 400", handle, w.Code, w.Body)
			}
			if len(r.pocket.creates) != 0 || len(r.machines.created) != 0 {
				t.Errorf("a rejected handle reached the client or the store: %+v, %+v", r.pocket.creates, r.machines.created)
			}
		})
	}
}

func TestMachinesCreateRejectsBadPublicKey(t *testing.T) {
	bodies := map[string]string{
		"missing":   `{"handle":"nas"}`,
		"null":      `{"handle":"nas","publicKey":null}`,
		"a string":  `{"handle":"nas","publicKey":"abc"}`,
		"an array":  `{"handle":"nas","publicKey":[1]}`,
		"empty obj": `{"handle":"nas","publicKey":{}}`,
		"a number":  `{"handle":"nas","publicKey":7}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			r := newServerRig(t)
			w := r.do("POST", "/api/machines", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), body)
			if w.Code != 400 {
				t.Errorf("= %d %q, want 400", w.Code, w.Body)
			}
			if len(r.pocket.creates) != 0 {
				t.Errorf("a rejected key reached Pocket ID: %+v", r.pocket.creates)
			}
		})
	}
}

func TestMachinesCreateRejectsTrailingJSON(t *testing.T) {
	r := newServerRig(t)
	w := r.do("POST", "/api/machines", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), `{"handle":"nas","publicKey":`+goodJWK+`}{}`)
	if w.Code != 400 {
		t.Errorf("= %d %q, want 400", w.Code, w.Body)
	}
	if len(r.pocket.creates) != 0 {
		t.Errorf("a body with trailing JSON reached Pocket ID: %+v", r.pocket.creates)
	}
}

// A mint that fails leaves no machine row: the broker never stores a machine it could not register.
func TestMachinesCreateMintFailureLeavesNoRow(t *testing.T) {
	r := newServerRig(t)
	r.pocket.createErr = errors.New("pocket id is down")
	w := r.do("POST", "/api/machines", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), `{"handle":"nas","publicKey":`+goodJWK+`}`)
	if w.Code != 503 || strings.TrimSpace(w.Body.String()) != `{"error":"could not create the machine, try again"}` {
		t.Fatalf("= %d %q, want 503 with the fixed sentence", w.Code, w.Body)
	}
	if len(r.machines.created) != 0 || len(r.machines.machines) != 0 {
		t.Errorf("a row was stored without a client: %+v", r.machines.machines)
	}
	if !strings.Contains(r.logs.String(), "pocket id is down") {
		t.Errorf("the cause was not logged:\n%s", r.logs)
	}
	if strings.Contains(r.logs.String(), goodJWK) {
		t.Error("the JWK leaked into the log")
	}
}

// A handle taken by another account rolls the just-minted client back: no orphan.
func TestMachinesCreateDuplicateHandleRollsBack(t *testing.T) {
	r := newServerRig(t)
	r.machines.machines["existing"] = store.Machine{Handle: "nas", OwnerRef: "sub-bob", ClientID: "existing"}
	steps := machinesSteps(r)
	w := r.do("POST", "/api/machines", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), `{"handle":"nas","publicKey":`+goodJWK+`}`)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "taken") {
		t.Fatalf("= %d %q, want 409 saying the handle is taken", w.Code, w.Body)
	}
	if !reflect.DeepEqual(r.pocket.deletes, []string{"client-123"}) {
		t.Errorf("client deletes = %v, want the minted client rolled back", r.pocket.deletes)
	}
	if !reflect.DeepEqual(*steps, []string{"CreateClient", "CreateMachine", "DeleteClient"}) {
		t.Errorf("steps = %v, want mint, store-fail, rollback", *steps)
	}
	if _, ok := r.machines.machines["client-123"]; ok || len(r.machines.machines) != 1 {
		t.Errorf("machines = %+v, want only the pre-existing row", r.machines.machines)
	}
}

func TestMachinesCreateStoreErrorRollsBack(t *testing.T) {
	r := newServerRig(t)
	r.machines.createErr = errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")
	w := r.do("POST", "/api/machines", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), `{"handle":"nas","publicKey":`+goodJWK+`}`)
	if w.Code != 503 || strings.Contains(w.Body.String(), "5432") {
		t.Fatalf("= %d %q, want 503 without an internal address", w.Code, w.Body)
	}
	if !reflect.DeepEqual(r.pocket.deletes, []string{"client-123"}) {
		t.Errorf("client deletes = %v, want the minted client rolled back", r.pocket.deletes)
	}
}

func TestMachinesList(t *testing.T) {
	r := newServerRig(t)
	r.machines.machines["c1"] = store.Machine{Handle: "nas", OwnerRef: "sub-alice", ClientID: "c1"}
	r.machines.machines["c2"] = store.Machine{Handle: "pi", OwnerRef: "sub-alice", ClientID: "c2"}
	r.machines.machines["c3"] = store.Machine{Handle: "other", OwnerRef: "sub-bob", ClientID: "c3"}
	w := r.do("GET", "/api/machines", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), "")
	want := `{"machines":[{"handle":"nas","clientId":"c1"},{"handle":"pi","clientId":"c2"}]}`
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("= %d %q, want %s", w.Code, w.Body, want)
	}
}

func TestMachinesListEmptyIsArray(t *testing.T) {
	r := newServerRig(t)
	w := r.do("GET", "/api/machines", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), "")
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"machines":[]}` {
		t.Errorf("= %d %q, want an empty list, not null", w.Code, w.Body)
	}
}

func TestMachinesListStoreError(t *testing.T) {
	r := newServerRig(t)
	r.machines.err = errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")
	w := r.do("GET", "/api/machines", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), "")
	if w.Code != 503 || strings.Contains(w.Body.String(), "5432") {
		t.Fatalf("= %d %q, want 503 without an internal address", w.Code, w.Body)
	}
	if !strings.Contains(r.logs.String(), "connection refused") {
		t.Errorf("the cause was not logged:\n%s", r.logs)
	}
}

func TestMachinesDelete(t *testing.T) {
	r := newServerRig(t)
	r.machines.machines["c1"] = store.Machine{Handle: "nas", OwnerRef: "sub-alice", ClientID: "c1"}
	steps := machinesSteps(r)
	w := r.do("DELETE", "/api/machines/nas", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), "")
	if w.Code != 204 {
		t.Fatalf("= %d %q, want 204", w.Code, w.Body)
	}
	if !reflect.DeepEqual(r.machines.deleted, []string{"c1"}) {
		t.Errorf("machines deleted = %v, want c1", r.machines.deleted)
	}
	if !reflect.DeepEqual(r.pocket.deletes, []string{"c1"}) {
		t.Errorf("clients deleted = %v, want c1", r.pocket.deletes)
	}
	if !reflect.DeepEqual(*steps, []string{"DeleteMachine", "DeleteClient"}) {
		t.Errorf("steps = %v, want the row removed before the client", *steps)
	}
}

func TestMachinesDeleteUnknown(t *testing.T) {
	r := newServerRig(t)
	w := r.do("DELETE", "/api/machines/nas", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), "")
	if w.Code != 404 {
		t.Errorf("= %d %q, want 404", w.Code, w.Body)
	}
	if len(r.machines.deleted) != 0 || len(r.pocket.deletes) != 0 {
		t.Errorf("something was deleted for an unknown handle: %v, %v", r.machines.deleted, r.pocket.deletes)
	}
}

// A machine another account owns is not there as far as this caller can tell: no enumeration.
func TestMachinesDeleteRefusesAnotherOwnersMachine(t *testing.T) {
	r := newServerRig(t)
	r.machines.machines["c1"] = store.Machine{Handle: "nas", OwnerRef: "sub-bob", ClientID: "c1"}
	w := r.do("DELETE", "/api/machines/nas", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), "")
	if w.Code != 404 {
		t.Errorf("= %d %q, want 404", w.Code, w.Body)
	}
	if len(r.machines.deleted) != 0 || len(r.pocket.deletes) != 0 {
		t.Errorf("another owner's machine was deleted: %v, %v", r.machines.deleted, r.pocket.deletes)
	}
}

func TestMachinesDeleteLookupError(t *testing.T) {
	r := newServerRig(t)
	r.machines.machines["c1"] = store.Machine{Handle: "nas", OwnerRef: "sub-alice", ClientID: "c1"}
	r.machines.err = errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")
	w := r.do("DELETE", "/api/machines/nas", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), "")
	if w.Code != 503 || strings.Contains(w.Body.String(), "5432") {
		t.Fatalf("= %d %q, want 503 without an internal address", w.Code, w.Body)
	}
}

func TestMachinesDeleteRowError(t *testing.T) {
	r := newServerRig(t)
	r.machines.machines["c1"] = store.Machine{Handle: "nas", OwnerRef: "sub-alice", ClientID: "c1"}
	r.machines.deleteErr = errors.New("db down")
	w := r.do("DELETE", "/api/machines/nas", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), "")
	if w.Code != 503 {
		t.Fatalf("= %d %q, want 503", w.Code, w.Body)
	}
	if len(r.pocket.deletes) != 0 {
		t.Errorf("the client was deleted though the row was not: %v", r.pocket.deletes)
	}
}

// Deleting the client is cleanup, not the revocation lever: the row is gone, so the machine is revoked
// even if Pocket ID cannot be reached.
func TestMachinesDeleteClientCleanupFailureStillRevokes(t *testing.T) {
	r := newServerRig(t)
	r.machines.machines["c1"] = store.Machine{Handle: "nas", OwnerRef: "sub-alice", ClientID: "c1"}
	r.pocket.deleteErr = errors.New("pocket id is down")
	w := r.do("DELETE", "/api/machines/nas", bearer(r.idp.Issue("sub-alice", mockidp.IssueOpts{})), "")
	if w.Code != 204 {
		t.Fatalf("= %d %q, want 204", w.Code, w.Body)
	}
	if !reflect.DeepEqual(r.machines.deleted, []string{"c1"}) {
		t.Errorf("machines deleted = %v, want c1", r.machines.deleted)
	}
	if !strings.Contains(r.logs.String(), "not its client") {
		t.Errorf("the cleanup failure was not logged:\n%s", r.logs)
	}
}

func TestMachinesNeedAToken(t *testing.T) {
	r := newServerRig(t)
	for _, tt := range []struct{ method, target, body string }{
		{"POST", "/api/machines", `{"handle":"nas","publicKey":` + goodJWK + `}`},
		{"GET", "/api/machines", ""},
		{"DELETE", "/api/machines/nas", ""},
	} {
		w := r.do(tt.method, tt.target, nil, tt.body)
		if w.Code != 401 {
			t.Errorf("%s without a token = %d %q, want 401", tt.method, w.Code, w.Body)
		}
	}
}

// Decision 12: a machine must not create, list or delete machines — only its owner may.
func TestMachinesRefuseAMachineSubject(t *testing.T) {
	r := newServerRig(t)
	token := machineToken(r, "abc")
	steps := machinesSteps(r)
	for _, tt := range []struct{ method, target, body string }{
		{"POST", "/api/machines", `{"handle":"pi","publicKey":` + goodJWK + `}`},
		{"GET", "/api/machines", ""},
		{"DELETE", "/api/machines/nas", ""},
	} {
		w := r.do(tt.method, tt.target, bearer(token), tt.body)
		if w.Code != 403 || strings.TrimSpace(w.Body.String()) != `{"error":"`+machineRefused+`"}` {
			t.Errorf("%s as a machine = %d %q, want 403 refused", tt.method, w.Code, w.Body)
		}
	}
	if len(r.pocket.creates) != 0 || len(r.pocket.deletes) != 0 || len(r.machines.created) != 0 || len(r.machines.deleted) != 0 {
		t.Errorf("a machine reached the store or Pocket ID: %+v", *steps)
	}
}

// Decision 12, the landmine Task 3 left: a machine subject has no sub, so /api/shares must refuse it
// rather than act as owner_sub="".
func TestSharesRefuseAMachineSubject(t *testing.T) {
	r := newServerRig(t)
	token := machineToken(r, "abc")
	body := `{"tunnel":"blog","kind":"user","grantee":"bob"}`
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		w := r.do(method, "/api/shares", bearer(token), body)
		if w.Code != 403 || strings.TrimSpace(w.Body.String()) != `{"error":"`+machineRefused+`"}` {
			t.Errorf("%s as a machine = %d %q, want 403 refused", method, w.Code, w.Body)
		}
	}
	if len(r.shares.getSubs) != 0 || len(r.shares.puts) != 0 || len(r.shares.deletes) != 0 {
		t.Errorf("a machine reached the shares store: %+v", r.shares)
	}
}
