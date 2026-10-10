// Package broker holds what the tunnel service decides: who may publish, which names they may use,
// and what frps and the ingress are told.
package broker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/layertwo/tunnels/internal/idp"
	"github.com/layertwo/tunnels/internal/names"
	"github.com/layertwo/tunnels/internal/store"
)

// IdP is the identity provider as the resolver uses it.
type IdP interface {
	UserInfo(ctx context.Context, accessToken string) (idp.Identity, error)
}

// Users is where accounts are kept; store.Store implements it.
type Users interface {
	UserBySub(ctx context.Context, sub string) (store.User, error)
	UserByHandle(ctx context.Context, handle string) (store.User, error)
	CreateUser(ctx context.Context, sub, handle string) (store.User, error)
}

// Account is a person who may publish tunnels. Handle is the stored one and never changes;
// Username is whatever the identity provider says today.
type Account struct{ Sub, Username, Handle string }

// What Resolve refuses with. A token the identity provider rejects surfaces as idp.ErrInvalidToken
// and a handle that another account owns as store.ErrHandleTaken.
var (
	ErrNotCreator = errors.New("broker: not in the creators group")
	ErrDisabled   = errors.New("broker: account is disabled")
	ErrBadHandle  = errors.New("broker: username cannot be a handle")
)

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
	Users         Users
	CreatorsGroup string   // the group whose members may publish
	Reserved      []string // handles nobody gets
}

// Resolve says who the token belongs to and creates their row on the first login. Every failure is
// an error: nothing is allowed because a lookup could not be answered.
func (r Resolver) Resolve(ctx context.Context, accessToken string) (Account, error) {
	id, err := r.IdP.UserInfo(ctx, accessToken)
	if err != nil {
		return Account{}, err
	}
	if id.Sub == "" {
		return Account{}, errors.New("broker: identity has no sub")
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

// Reason is what to tell the person behind a failed Resolve. Only refusals and an invalid token have
// their own sentence; any other error gets a fixed one, so no internal detail reaches them.
func Reason(err error) string {
	text, _ := reasonOf(err)
	return text
}

// reasonOf is Reason plus whether the person caused the failure. The ones they did not cause (a
// dependency is down) are the only ones worth logging in full.
func reasonOf(err error) (text string, theirs bool) {
	var r *refusal
	switch {
	case errors.As(err, &r):
		return r.text, true
	case errors.Is(err, idp.ErrInvalidToken):
		return "your session is not valid; run: tunnel login", true
	}
	return "login unavailable, try again", false
}
