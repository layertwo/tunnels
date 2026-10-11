// Package broker holds what the tunnel service decides: who may publish, which names they may use,
// and what frps and the ingress are told.
package broker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/layertwo/tunnels/internal/idp"
	"github.com/layertwo/tunnels/internal/names"
	"github.com/layertwo/tunnels/internal/store"
)

// IdP is the identity provider as the resolver uses it.
type IdP interface {
	UserInfo(ctx context.Context, accessToken string) (idp.Identity, error)
}

// TokenVerifier checks an access token locally (signature, issuer, audience, expiry) and returns the
// sub it was issued for; idp.Client implements it.
type TokenVerifier interface {
	VerifyAccessToken(ctx context.Context, raw string) (sub string, err error)
}

// Users is where accounts are kept; store.Store implements it.
type Users interface {
	UserBySub(ctx context.Context, sub string) (store.User, error)
	UserByHandle(ctx context.Context, handle string) (store.User, error)
	CreateUser(ctx context.Context, sub, handle string) (store.User, error)
}

// MachineStore is where machines are kept; store.Store implements it.
type MachineStore interface {
	MachineByClientID(ctx context.Context, clientID string) (store.Machine, error)
	MachineByHandle(ctx context.Context, handle string) (store.Machine, error)
	CreateMachine(ctx context.Context, m store.Machine) error
	MachinesByOwner(ctx context.Context, ownerRef string) ([]store.Machine, error)
	DeleteMachine(ctx context.Context, clientID string) error
	SetMachineDisabled(ctx context.Context, clientID string, disabled bool) error
}

// Account is a principal who may publish tunnels: a person or a machine. Handle is the stored one and
// never changes; Username is whatever the identity provider says today, and empty for a machine.
type Account struct {
	Sub      string `json:"sub"`
	Username string `json:"username"`
	Handle   string `json:"handle"`
	Machine  bool   `json:"machine,omitempty"` // a machine is its own principal; /api/me reports it
}

// What Resolve refuses with. A token the identity provider rejects surfaces as idp.ErrInvalidToken
// and a handle that another account owns as store.ErrHandleTaken.
var (
	ErrNotCreator     = errors.New("broker: not in the creators group")
	ErrDisabled       = errors.New("broker: account is disabled")
	ErrBadHandle      = errors.New("broker: username cannot be a handle")
	ErrUnknownMachine = errors.New("broker: machine is not usable")
)

// notValid is what a person is told when their token is refused.
const notValid = "your session is not valid; run: tunnel login"

// refusal is one of the errors above together with the sentence the person is shown.
type refusal struct {
	kind error
	text string
}

func (e *refusal) Error() string { return e.kind.Error() + ": " + e.text }
func (e *refusal) Unwrap() error { return e.kind }

// Resolver turns an access token into an Account. It keeps no state and is safe for concurrent use.
type Resolver struct {
	IdP           IdP
	Verifier      TokenVerifier
	Users         Users
	Machines      MachineStore
	CreatorsGroup string   // the group whose members may publish
	Reserved      []string // handles nobody gets
}

// Resolve says who the token belongs to and creates their row on the first login. Every failure is
// an error: nothing is allowed because a lookup could not be answered.
func (r Resolver) Resolve(ctx context.Context, accessToken string) (Account, error) {
	// Before anybody is asked about the token: userinfo accepts any application's token for the same
	// person, so the audience is checked here, and junk is turned away without a request to the
	// identity provider (frps calls the plugin before it checks anything, so anybody can send junk).
	sub, err := r.Verifier.VerifyAccessToken(ctx, accessToken)
	if err != nil {
		return Account{}, err
	}
	// A client_credentials token names its client, not a person: it is a machine, resolved from the
	// machines table, so it has no username or groups to ask the identity provider about and never
	// passes the group check.
	if _, ok := strings.CutPrefix(sub, "client-"); ok {
		return r.AccountBySubject(ctx, sub)
	}
	id, err := r.IdP.UserInfo(ctx, accessToken)
	if err != nil {
		return Account{}, err
	}
	if id.Sub == "" || id.Sub != sub {
		return Account{}, errors.New("broker: the token and the identity provider name different subjects")
	}
	// Before the store, so that somebody who may not publish never creates or probes a row.
	if r.CreatorsGroup == "" || !slices.Contains(id.Groups, r.CreatorsGroup) {
		return Account{}, &refusal{ErrNotCreator, "your account is not allowed to publish tunnels: ask an admin to add you to " + r.CreatorsGroup}
	}

	u, err := r.Users.UserBySub(ctx, id.Sub)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if u, err = r.create(ctx, id); err != nil {
			return Account{}, err
		}
	case err != nil:
		return Account{}, fmt.Errorf("broker: look up user: %w", err)
	}
	if u.Disabled {
		return Account{}, &refusal{ErrDisabled, "your account is disabled: ask an admin"}
	}
	return Account{Sub: u.Sub, Username: id.Username, Handle: u.Handle}, nil
}

// AccountBySubject resolves a verified token's subject to the account that may publish. A
// client_credentials subject is a machine: its handle comes only from the machines row (invariant 5),
// so it can never claim another's and a disabled or deleted machine is refused. Anything else is a
// person's stored row. It creates nothing.
func (r Resolver) AccountBySubject(ctx context.Context, sub string) (Account, error) {
	if id, ok := strings.CutPrefix(sub, "client-"); ok {
		m, err := r.Machines.MachineByClientID(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return Account{}, &refusal{ErrUnknownMachine, "this machine is not registered; ask its owner to create it"}
		case err != nil:
			return Account{}, fmt.Errorf("broker: look up machine: %w", err)
		}
		if m.Disabled {
			return Account{}, &refusal{ErrDisabled, "this machine is disabled; ask its owner"}
		}
		// A machine's authority derives from its owner, so the owner must still exist and be enabled (the
		// design's Publish flow). A missing owner row orphans the machine: fail closed, as /authz already
		// denies a site whose owner is gone.
		owner, err := r.Users.UserBySub(ctx, m.OwnerRef)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return Account{}, &refusal{ErrUnknownMachine, "this machine's owner no longer exists; ask an admin"}
		case err != nil:
			return Account{}, fmt.Errorf("broker: look up machine owner: %w", err)
		case owner.Disabled:
			return Account{}, &refusal{ErrDisabled, "this machine's owner is disabled; ask an admin"}
		}
		return Account{Machine: true, Handle: m.Handle}, nil
	}
	u, err := r.Users.UserBySub(ctx, sub)
	if err != nil {
		return Account{}, fmt.Errorf("broker: look up user: %w", err)
	}
	return Account{Sub: u.Sub, Handle: u.Handle}, nil
}

// create gives a first-time user the handle their username makes. Existing users never come here,
// so a stored handle outlives a rename and a username that stopped being a valid handle.
func (r Resolver) create(ctx context.Context, id idp.Identity) (store.User, error) {
	handle, err := names.HandleFromUsername(id.Username, r.Reserved)
	if err != nil {
		return store.User{}, &refusal{ErrBadHandle, err.Error() + "; ask an admin to change your username"}
	}
	u, err := r.Users.CreateUser(ctx, id.Sub, handle)
	if errors.Is(err, store.ErrHandleTaken) {
		return store.User{}, &refusal{store.ErrHandleTaken, "the handle " + strconv.Quote(handle) + " belongs to another account; ask an admin to change your username"}
	}
	if err != nil {
		return store.User{}, fmt.Errorf("broker: create user: %w", err)
	}
	return u, nil
}

// refusalOf returns the refusal behind err, if it is one. A failure that is not a refusal (a bad
// token, or a dependency that could not answer) is not the person's own doing.
func refusalOf(err error) (r *refusal, ok bool) {
	ok = errors.As(err, &r)
	return r, ok
}

// reasonOf is what to tell the person behind a failed Resolve, and whether they caused the failure.
// Only refusals and an invalid token have their own sentence; any other error gets a fixed one, so no
// internal detail reaches them. The failures they did not cause (a dependency is down) are the only
// ones worth logging in full.
func reasonOf(err error) (text string, theirs bool) {
	if r, ok := refusalOf(err); ok {
		return r.text, true
	}
	if errors.Is(err, idp.ErrInvalidToken) {
		return notValid, true
	}
	return "login unavailable, try again", false
}
