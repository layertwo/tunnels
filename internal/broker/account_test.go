package broker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/layertwo/tunnels/internal/idp"
	"github.com/layertwo/tunnels/internal/store"
)

const creators = "tunnels-creators"

// fakeIdP answers every UserInfo call with the same identity or error and remembers the last token.
type fakeIdP struct {
	id    idp.Identity
	err   error
	token string
	calls int
}

func (f *fakeIdP) UserInfo(_ context.Context, token string) (idp.Identity, error) {
	f.calls++
	f.token = token
	return f.id, f.err
}

// fakeVerifier stands for the local check of an access token (signature, audience, expiry). A good
// token is for the sub the identity provider reports, unless sub says otherwise.
type fakeVerifier struct {
	idp   *fakeIdP
	sub   string
	err   error
	token string
	calls int
}

func (f *fakeVerifier) VerifyAccessToken(_ context.Context, token string) (string, error) {
	f.calls++
	f.token = token
	if f.err != nil {
		return "", f.err
	}
	if f.sub != "" {
		return f.sub, nil
	}
	return f.idp.id.Sub, nil
}

// fakeUsers is an in-memory Users that behaves like store.Store, and records every call.
type fakeUsers struct {
	users                            map[string]store.User // by sub
	bySubErr, byHandleErr, createErr error
	calls                            []string
	block                            bool // UserBySub and UserByHandle wait for their context to end
	deadline                         time.Time
	hasDeadline                      bool // whether the context UserBySub got last had a deadline
}

func newUsers(existing ...store.User) *fakeUsers {
	f := &fakeUsers{users: map[string]store.User{}}
	for _, u := range existing {
		f.users[u.Sub] = u
	}
	return f
}

func (f *fakeUsers) UserBySub(ctx context.Context, sub string) (store.User, error) {
	f.calls = append(f.calls, "UserBySub "+sub)
	f.deadline, f.hasDeadline = ctx.Deadline()
	if f.block {
		<-ctx.Done()
		return store.User{}, ctx.Err()
	}
	if f.bySubErr != nil {
		return store.User{}, f.bySubErr
	}
	if u, ok := f.users[sub]; ok {
		return u, nil
	}
	return store.User{}, store.ErrNotFound
}

func (f *fakeUsers) UserByHandle(ctx context.Context, handle string) (store.User, error) {
	f.calls = append(f.calls, "UserByHandle "+handle)
	if f.block {
		<-ctx.Done()
		return store.User{}, ctx.Err()
	}
	if f.byHandleErr != nil {
		return store.User{}, f.byHandleErr
	}
	for _, u := range f.users {
		if u.Handle == handle {
			return u, nil
		}
	}
	return store.User{}, store.ErrNotFound
}

func (f *fakeUsers) CreateUser(_ context.Context, sub, handle string) (store.User, error) {
	f.calls = append(f.calls, "CreateUser "+sub+" "+handle)
	if f.createErr != nil {
		return store.User{}, f.createErr
	}
	if u, ok := f.users[sub]; ok {
		return u, nil
	}
	for _, u := range f.users {
		if u.Handle == handle {
			return store.User{}, store.ErrHandleTaken
		}
	}
	u := store.User{Sub: sub, Handle: handle}
	f.users[sub] = u
	return u, nil
}

func (f *fakeUsers) created() []string {
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "CreateUser ") {
			out = append(out, c)
		}
	}
	return out
}

func identity(sub, username string, groups ...string) idp.Identity {
	return idp.Identity{Sub: sub, Username: username, Groups: groups}
}

func resolver(id idp.Identity, users *fakeUsers) (Resolver, *fakeIdP) {
	i := &fakeIdP{id: id}
	return Resolver{IdP: i, Verifier: &fakeVerifier{idp: i}, Users: users, CreatorsGroup: creators, Reserved: []string{"admin", "root"}}, i
}

func verifierOf(r Resolver) *fakeVerifier { return r.Verifier.(*fakeVerifier) }

// Reason is the sentence a failed Resolve shows the person.
func Reason(err error) string { text, _ := reasonOf(err); return text }

func TestResolveNewUser(t *testing.T) {
	users := newUsers()
	r, i := resolver(identity("sub-1", "Alice", creators, "tunnels-viewers"), users)

	got, err := r.Resolve(t.Context(), "tok-1")
	if err != nil {
		t.Fatal(err)
	}
	if want := (Account{Sub: "sub-1", Username: "Alice", Handle: "alice"}); got != want {
		t.Errorf("account = %+v, want %+v", got, want)
	}
	if i.token != "tok-1" {
		t.Errorf("the identity provider was asked about %q, want tok-1", i.token)
	}
	if got := users.created(); len(got) != 1 || got[0] != "CreateUser sub-1 alice" {
		t.Errorf("created %q, want exactly CreateUser sub-1 alice", got)
	}

	// The row exists now: the second login reads it and creates nothing.
	if again, err := r.Resolve(t.Context(), "tok-2"); err != nil || again != got {
		t.Errorf("second Resolve = %+v, %v, want %+v, nil", again, err, got)
	}
	if got := users.created(); len(got) != 1 {
		t.Errorf("created %q, want the one row from the first login", got)
	}
}

// The stored handle is the account's name for good: it does not follow the username, and a
// username that would not make a handle today does not lock an existing account out.
func TestResolveExistingUserKeepsHandle(t *testing.T) {
	for _, username := range []string{"Bob_Smith", "robert", "bob", "", "a"} {
		t.Run("username "+username, func(t *testing.T) {
			users := newUsers(store.User{Sub: "sub-2", Handle: "bob"})
			r, _ := resolver(identity("sub-2", username, creators), users)

			got, err := r.Resolve(t.Context(), "tok")
			if err != nil {
				t.Fatal(err)
			}
			if want := (Account{Sub: "sub-2", Username: username, Handle: "bob"}); got != want {
				t.Errorf("account = %+v, want %+v", got, want)
			}
			if c := users.created(); len(c) != 0 {
				t.Errorf("created %q for an existing user", c)
			}
		})
	}
}

// A machine client is pre-authorised by config: its id maps to a handle, and it acts as that person.
// No userinfo and no creators-group check, because a client_credentials token has neither username
// nor groups.
func TestResolveMachineClient(t *testing.T) {
	users := newUsers(store.User{Sub: "sub-alice", Handle: "alice"})
	r, i := resolver(identity("", "", creators), users)
	r.MachineClients = map[string]string{"abc": "alice"}
	verifierOf(r).sub = "client-abc"

	got, err := r.Resolve(t.Context(), "tok-machine")
	if err != nil {
		t.Fatal(err)
	}
	if want := (Account{Sub: "sub-alice", Handle: "alice"}); got != want {
		t.Errorf("account = %+v, want %+v", got, want)
	}
	if i.calls != 0 {
		t.Errorf("userinfo called %d times for a machine token", i.calls)
	}
	if len(users.created()) != 0 {
		t.Errorf("created %q for a machine token", users.created())
	}

	// A normal subject still goes through userinfo; only "client-" is a machine.
	r, i = resolver(identity("sub-bob", "Bob", creators), newUsers())
	if _, err := r.Resolve(t.Context(), "tok-human"); err != nil || i.calls != 1 {
		t.Errorf("human login = %v, userinfo calls %d, want no error and one call", err, i.calls)
	}
}

func TestResolveMachineUnknownClient(t *testing.T) {
	users := newUsers(store.User{Sub: "sub-alice", Handle: "alice"})
	r, i := resolver(identity("", ""), users)
	r.MachineClients = map[string]string{"abc": "alice"}
	verifierOf(r).sub = "client-zzz"

	got, err := r.Resolve(t.Context(), "tok")
	if !errors.Is(err, ErrUnknownMachine) || got != (Account{}) {
		t.Fatalf("Resolve = %+v, %v, want the zero value and ErrUnknownMachine", got, err)
	}
	if i.calls != 0 || len(users.calls) != 0 {
		t.Errorf("userinfo calls %d, store calls %q after an unknown machine client", i.calls, users.calls)
	}
}

func TestResolveMachineUnknownHandle(t *testing.T) {
	users := newUsers() // configured to "box", who has never logged in
	r, _ := resolver(identity("", ""), users)
	r.MachineClients = map[string]string{"abc": "box"}
	verifierOf(r).sub = "client-abc"

	got, err := r.Resolve(t.Context(), "tok")
	if !errors.Is(err, store.ErrNotFound) || got != (Account{}) {
		t.Fatalf("Resolve = %+v, %v, want the zero value and store.ErrNotFound", got, err)
	}
	if _, ok := refusalOf(err); !ok {
		t.Errorf("err = %v, want a refusal", err)
	}
}

func TestResolveMachineDisabled(t *testing.T) {
	users := newUsers(store.User{Sub: "sub-alice", Handle: "alice", Disabled: true})
	r, _ := resolver(identity("", ""), users)
	r.MachineClients = map[string]string{"abc": "alice"}
	verifierOf(r).sub = "client-abc"

	got, err := r.Resolve(t.Context(), "tok")
	if !errors.Is(err, ErrDisabled) || got != (Account{}) {
		t.Fatalf("Resolve = %+v, %v, want the zero value and ErrDisabled", got, err)
	}
}

// A store that cannot answer the handle lookup is infrastructure, not the machine's fault.
func TestResolveMachineLookupFails(t *testing.T) {
	boom := errors.New("dial tcp: connection refused")
	users := newUsers()
	users.byHandleErr = boom
	r, _ := resolver(identity("", ""), users)
	r.MachineClients = map[string]string{"abc": "alice"}
	verifierOf(r).sub = "client-abc"

	got, err := r.Resolve(t.Context(), "tok")
	if err == nil || got != (Account{}) || Reason(err) != "login unavailable, try again" {
		t.Fatalf("Resolve = %+v, %v (%q), want the zero value and the fixed sentence", got, err, Reason(err))
	}
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want it to wrap the lookup failure", err)
	}
}

func TestResolveRefusals(t *testing.T) {
	tests := []struct {
		name     string
		id       idp.Identity
		existing []store.User
		want     error
	}{
		{"no groups", identity("s", "alice"), nil, ErrNotCreator},
		{"only the viewers group", identity("s", "alice", "tunnels-viewers"), nil, ErrNotCreator},
		{"group name in another case", identity("s", "alice", "Tunnels-Creators"), nil, ErrNotCreator},
		{"group name as a substring", identity("s", "alice", "tunnels-creators-2", "tunnels-creator"), nil, ErrNotCreator},
		{"existing user who left the group", identity("s", "alice", "tunnels-viewers"), []store.User{{Sub: "s", Handle: "alice"}}, ErrNotCreator},
		{"disabled", identity("s", "alice", creators), []store.User{{Sub: "s", Handle: "alice", Disabled: true}}, ErrDisabled},
		{"username with an underscore", identity("s", "alice_b", creators), nil, ErrBadHandle},
		{"username too short", identity("s", "a", creators), nil, ErrBadHandle},
		{"username too long", identity("s", strings.Repeat("a", 21), creators), nil, ErrBadHandle},
		{"username with a dash", identity("s", "alice-b", creators), nil, ErrBadHandle},
		{"username with a dot", identity("s", "alice.b", creators), nil, ErrBadHandle},
		{"username with a space", identity("s", "alice b", creators), nil, ErrBadHandle},
		{"username with a newline", identity("s", "alice\n", creators), nil, ErrBadHandle},
		{"empty username", identity("s", "", creators), nil, ErrBadHandle},
		{"non-ASCII letter", identity("s", "ünal", creators), nil, ErrBadHandle},
		{"Kelvin sign", identity("s", "\u212Aevin", creators), nil, ErrBadHandle},
		{"reserved handle", identity("s", "Admin", creators), nil, ErrBadHandle},
		{"reserved handle, other case", identity("s", "ROOT", creators), nil, ErrBadHandle},
		{"handle owned by another sub", identity("s", "Alice", creators), []store.User{{Sub: "other", Handle: "alice"}}, store.ErrHandleTaken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := newUsers(tt.existing...)
			r, _ := resolver(tt.id, users)

			got, err := r.Resolve(t.Context(), "tok")
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if got != (Account{}) {
				t.Errorf("account = %+v with an error, want the zero value", got)
			}
			// Nobody who is refused leaves a row behind, and only a handle clash gets as far as asking the
			// store to create one (the store is what finds the clash).
			if len(users.users) != len(tt.existing) {
				t.Errorf("rows after a refused login: %v, started with %d", users.users, len(tt.existing))
			}
			if asked, want := len(users.created()) > 0, errors.Is(tt.want, store.ErrHandleTaken); asked != want {
				t.Errorf("CreateUser called = %v, want %v (calls %q)", asked, want, users.calls)
			}
		})
	}
}

// An identity without a sub cannot own a row, and a resolver that was never told which group may
// publish has no right answer: both refuse, and neither touches the store.
func TestResolveRefusesWhatItCannotDecide(t *testing.T) {
	t.Run("identity without a sub", func(t *testing.T) {
		users := newUsers()
		r, _ := resolver(identity("", "alice", creators), users)
		if got, err := r.Resolve(t.Context(), "tok"); err == nil || got != (Account{}) {
			t.Errorf("Resolve = %+v, %v, want the zero value and an error", got, err)
		}
		if len(users.calls) != 0 {
			t.Errorf("store calls %q for an identity without a sub", users.calls)
		}
	})
	t.Run("no creators group configured", func(t *testing.T) {
		users := newUsers()
		r, _ := resolver(identity("s", "alice", ""), users) // a group with an empty name
		r.CreatorsGroup = ""
		if got, err := r.Resolve(t.Context(), "tok"); !errors.Is(err, ErrNotCreator) || got != (Account{}) {
			t.Errorf("Resolve = %+v, %v, want the zero value and ErrNotCreator", got, err)
		}
		if len(users.calls) != 0 {
			t.Errorf("store calls %q", users.calls)
		}
	})
}

// Somebody who may not publish never reaches the store, so the database is not a way to probe accounts.
func TestResolveChecksTheGroupBeforeTheStore(t *testing.T) {
	users := newUsers(store.User{Sub: "s", Handle: "alice"})
	r, _ := resolver(identity("s", "alice", "tunnels-viewers"), users)
	if _, err := r.Resolve(t.Context(), "tok"); !errors.Is(err, ErrNotCreator) {
		t.Fatalf("err = %v, want ErrNotCreator", err)
	}
	if len(users.calls) != 0 {
		t.Errorf("store calls %q for a login that is not a creator", users.calls)
	}
}

// Every dependency failure refuses; nothing is allowed because a lookup could not be answered.
func TestResolveFailsClosed(t *testing.T) {
	boom := errors.New("dial tcp 10.0.0.5:5432: connect: connection refused (password=hunter2)")
	tests := []struct {
		name       string
		idpErr     error
		bySubErr   error
		createErr  error
		wantReason string
		wantCreate bool
	}{
		{"identity provider down", boom, nil, nil, "login unavailable, try again", false},
		{"identity provider deadline", context.DeadlineExceeded, nil, nil, "login unavailable, try again", false},
		{"store read failed", nil, boom, nil, "login unavailable, try again", false},
		{"store read canceled", nil, fmt.Errorf("query: %w", context.Canceled), nil, "login unavailable, try again", false},
		{"store write failed", nil, nil, boom, "login unavailable, try again", true},
		{"token not valid", idp.ErrInvalidToken, nil, nil, "your session is not valid; run: tunnel login", false},
		{"token not valid, wrapped", fmt.Errorf("idp: userinfo answered 401: %w", idp.ErrInvalidToken), nil, nil, "your session is not valid; run: tunnel login", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := newUsers()
			users.bySubErr, users.createErr = tt.bySubErr, tt.createErr
			r, i := resolver(identity("s", "alice", creators), users)
			i.err = tt.idpErr

			got, err := r.Resolve(t.Context(), "tok")
			if err == nil {
				t.Fatalf("Resolve = %+v, nil, want an error", got)
			}
			if got != (Account{}) {
				t.Errorf("account = %+v with an error, want the zero value", got)
			}
			if reason := Reason(err); reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", reason, tt.wantReason)
			}
			if created := len(users.created()) > 0; created != tt.wantCreate {
				t.Errorf("CreateUser called = %v, want %v (calls %q)", created, tt.wantCreate, users.calls)
			}
		})
	}
}

// What the person is told names what they can do, and never what the broker is made of.
func TestReasonMessages(t *testing.T) {
	tests := []struct {
		name     string
		id       idp.Identity
		existing []store.User
		contains []string
	}{
		{"not a creator", identity("s", "alice", "tunnels-viewers"), nil, []string{"not allowed to publish tunnels", "ask an admin to add you to " + creators}},
		{"disabled", identity("s", "alice", creators), []store.User{{Sub: "s", Handle: "alice", Disabled: true}}, []string{"disabled", "ask an admin"}},
		{"bad username", identity("s", "alice_b", creators), nil, []string{`"alice_b"`, "use 2 to 20 letters and digits", "ask an admin to change your username"}},
		{"reserved", identity("s", "Admin", creators), nil, []string{"is reserved", "ask an admin to change your username"}},
		{"handle taken", identity("s", "Alice", creators), []store.User{{Sub: "other", Handle: "alice"}}, []string{"another account", "ask an admin to change your username"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := resolver(tt.id, newUsers(tt.existing...))
			_, err := r.Resolve(t.Context(), "tok")
			if err == nil {
				t.Fatal("Resolve succeeded")
			}
			reason := Reason(err)
			for _, want := range tt.contains {
				if !strings.Contains(reason, want) {
					t.Errorf("Reason = %q, want it to contain %q", reason, want)
				}
			}
		})
	}

	// Anything that is not a refusal gets one fixed sentence, whatever the error says.
	for _, err := range []error{errors.New("pq: password authentication failed for user broker"), context.Canceled} {
		if got := Reason(err); got != "login unavailable, try again" {
			t.Errorf("Reason(%v) = %q, want the fixed sentence", err, got)
		}
	}
}

// A refusal is still a refusal after a caller adds context to it.
func TestReasonSurvivesWrapping(t *testing.T) {
	r, _ := resolver(identity("s", "alice", "tunnels-viewers"), newUsers())
	_, err := r.Resolve(t.Context(), "tok")
	wrapped := fmt.Errorf("login: %w", err)
	if !errors.Is(wrapped, ErrNotCreator) || Reason(wrapped) != Reason(err) {
		t.Errorf("wrapped refusal lost: Is = %v, Reason = %q", errors.Is(wrapped, ErrNotCreator), Reason(wrapped))
	}
}

// The token is checked locally before anybody is asked about it: one meant for another application
// never reaches the identity provider and never creates a row, and a junk token costs no request.
func TestResolveVerifiesTheTokenFirst(t *testing.T) {
	const notValid = "your session is not valid; run: tunnel login"
	tests := []struct {
		name   string
		err    error
		reason string
	}{
		{"not valid", idp.ErrInvalidToken, notValid},
		{"not valid, wrapped", fmt.Errorf("idp: token audience: %w", idp.ErrInvalidToken), notValid},
		{"the check itself failed", errors.New("keys unavailable"), "login unavailable, try again"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := newUsers()
			r, i := resolver(identity("s", "alice", creators), users)
			verifierOf(r).err = tt.err

			got, err := r.Resolve(t.Context(), "tok-x")
			if err == nil || got != (Account{}) {
				t.Fatalf("Resolve = %+v, %v, want the zero value and an error", got, err)
			}
			if reason := Reason(err); reason != tt.reason {
				t.Errorf("Reason = %q, want %q", reason, tt.reason)
			}
			if verifierOf(r).token != "tok-x" {
				t.Errorf("the verifier was given %q, want the token", verifierOf(r).token)
			}
			if i.calls != 0 || len(users.calls) != 0 {
				t.Errorf("identity provider calls %d, store calls %q after a token that did not verify", i.calls, users.calls)
			}
		})
	}
}

// Two answers about one token that name different people are not something to guess about.
func TestResolveRefusesAVerifierAndAProviderThatDisagree(t *testing.T) {
	users := newUsers()
	r, _ := resolver(identity("sub-a", "alice", creators), users)
	verifierOf(r).sub = "sub-b"
	got, err := r.Resolve(t.Context(), "tok")
	if err == nil || got != (Account{}) || Reason(err) != "login unavailable, try again" {
		t.Errorf("Resolve = %+v, %v (%q), want the zero value and the fixed sentence", got, err, Reason(err))
	}
	if len(users.calls) != 0 {
		t.Errorf("store calls %q", users.calls)
	}
}
