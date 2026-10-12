package broker

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/layertwo/tunnels/internal/idp"
	"github.com/layertwo/tunnels/internal/names"
	"github.com/layertwo/tunnels/internal/store"
)

// Shares manages an owner's tunnel shares; store.Store implements it.
type Shares interface {
	PutShare(ctx context.Context, ownerSub string, sh store.Share) error
	DeleteShare(ctx context.Context, ownerSub string, sh store.Share) error
	SharesByOwner(ctx context.Context, ownerSub string) ([]store.Share, error)
	ShareMatches(ctx context.Context, ownerSub, handle, tunnel, username string, groups []string) (bool, error)
}

// ShareMatcher is the part of Shares the authz decision needs: whether a share covers a visitor.
type ShareMatcher interface {
	ShareMatches(ctx context.Context, ownerSub, handle, tunnel, username string, groups []string) (bool, error)
}

// LookupObserver records how long one store lookup in the /authz decision took; *Metrics implements
// it, and tests substitute a recorder.
type LookupObserver interface {
	ObserveLookup(phase string, d time.Duration)
}

// Authz is the decision Traefik's forwardAuth asks for before it lets a request reach a site: allow
// (200, with X-Tunnel-User set to the visitor's username) or deny (403). The answer is built from
// the host the visitor asked for (X-Forwarded-Host) and the identity the OIDC gate put on the
// request (X-Tunnels-Sub, X-Tunnels-User, X-Tunnels-Groups). The owner gets in, and so does a
// visitor the owner has shared the tunnel with.
//
// A host under SSHDomain is decided from the bearer token instead: the terminal has no browser and
// no cookie, so it presents a Pocket ID access token and only the owner is let in. The two modes do
// not cross-talk — an identity header never authorizes an SSH host and a bearer token never
// authorizes a site host.
//
// Everything that is not a clear allow is the same empty 403, so nothing tells a name that exists
// from one that does not. A missing or invalid bearer token is a 401, and a store that cannot
// answer is an empty 503. It keeps no state and is safe for concurrent use.
type Authz struct {
	Users       Users
	Machines    MachineStore
	Shares      ShareMatcher
	Verifier    TokenVerifier // checks an SSH visitor's bearer token locally; nil when SSH is off
	SitesDomain string        // the domain sites live under, without a port or a trailing dot
	SSHDomain   string        // the domain SSH tunnels live under; empty when the feature is off
	Timeout     time.Duration // for the store lookup; zero means 5 s
	Log         *slog.Logger
	Metrics     LookupObserver // optional; times the store lookups
}

func (a Authz) timeout() time.Duration { return cmp.Or(a.Timeout, 5*time.Second) }

// observe records one lookup's duration when the broker was built with metrics.
func (a Authz) observe(phase string, start time.Time) {
	if a.Metrics != nil {
		a.Metrics.ObserveLookup(phase, time.Since(start))
	}
}

// outcome is one decision and what is logged about it.
type outcome struct {
	allow  bool
	reason string // the class of the decision: owner, shared, host, identity, cross_owner, unknown_owner, disabled, not_owner, token, verify, store
	status int    // the refusal status: 401 for a bad token, 503 for a dependency; zero means 403
	label  string
	sub    string
	user   string // the visitor's username, for the allow answer
	err    error  // set when the store or the verifier could not answer
}

func (a Authz) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o := a.decide(r)

	log := a.Log
	attrs := []slog.Attr{slog.String("reason", o.reason)}
	if o.label != "" {
		attrs = append(attrs, slog.String("label", o.label))
	}
	if o.sub != "" {
		attrs = append(attrs, slog.String("sub", o.sub))
	}
	switch {
	case o.err != nil:
		attrs = append(attrs, slog.String("decision", "error"), slog.String("err", o.err.Error()))
		log.LogAttrs(r.Context(), slog.LevelWarn, "authz", attrs...)
		w.WriteHeader(http.StatusServiceUnavailable)
	case o.allow:
		log.LogAttrs(r.Context(), slog.LevelInfo, "authz", append(attrs, slog.String("decision", "allow"))...)
		// A site tells the app who is looking; an SSH visitor has no username to tell it.
		if o.user != "" {
			w.Header().Set("X-Tunnel-User", o.user)
		}
		w.WriteHeader(http.StatusOK)
	default:
		log.LogAttrs(r.Context(), slog.LevelInfo, "authz", append(attrs, slog.String("decision", "deny"))...)
		w.WriteHeader(cmp.Or(o.status, http.StatusForbidden))
	}
}

// decide picks the mode from the host and refuses a host under neither domain. The subtrees are
// checked in a fixed order, so a host that somehow matches both is a site.
func (a Authz) decide(r *http.Request) outcome {
	// A header that is missing, empty or repeated is refused: with more than one value there is no
	// telling which one the gate set. The headers are indexed by their canonical names (how net/http
	// stores them) rather than read with Values: that is how CodeQL's clear-text-logging check sees a
	// header that holds no credential, and the label and the sub from them are logged.
	hosts := r.Header["X-Forwarded-Host"]
	if len(hosts) != 1 {
		return outcome{reason: "host", status: http.StatusForbidden}
	}
	if a.SitesDomain != "" {
		if label, ok := names.SiteLabel(hosts[0], a.SitesDomain); ok {
			return a.decideSite(r, label)
		}
	}
	if a.SSHDomain != "" {
		if label, ok := names.SSHLabel(hosts[0], a.SSHDomain); ok {
			return a.decideSSH(r, label)
		}
	}
	return outcome{reason: "host", status: http.StatusForbidden}
}

func (a Authz) decideSite(r *http.Request, label string) outcome {
	handle, tunnel, _ := names.ParseLabel(label) // SiteLabel only returns ok for a label it can parse

	o := outcome{label: label}
	subs, users := r.Header["X-Tunnels-Sub"], r.Header["X-Tunnels-User"]
	if len(subs) != 1 || subs[0] == "" || len(users) != 1 || users[0] == "" {
		o.reason = "identity"
		return o
	}
	o.sub = subs[0]

	// A browser page served from one creator's tunnel must not drive a state-changing request to
	// another creator's tunnel with the visitor's cookies. A foreign or absent Origin is harmless.
	if a.crossOwner(r, handle) {
		o.reason = "cross_owner"
		return o
	}

	ctx, cancel := context.WithTimeout(r.Context(), a.timeout())
	defer cancel()
	ownerStart := time.Now()
	owner, err := a.siteOwner(ctx, handle)
	a.observe("owner", ownerStart)
	switch {
	case errors.Is(err, store.ErrNotFound):
		o.reason = "unknown_owner"
	case err != nil:
		o.reason, o.err = "store", err
	case owner.disabled:
		o.reason = "disabled"
	case owner.ref == o.sub:
		o.allow, o.reason, o.user = true, "owner", users[0]
	default:
		if a.Shares == nil {
			o.reason, o.err = "store", errors.New("authz: no shares store")
			return o
		}
		sharesStart := time.Now()
		shared, err := a.Shares.ShareMatches(ctx, owner.ref, handle, tunnel, users[0], groupsOf(r))
		a.observe("shares", sharesStart)
		switch {
		case err != nil:
			o.reason, o.err = "store", err
		case shared:
			o.allow, o.reason, o.user = true, "shared", users[0]
		default:
			o.reason = "not_owner"
		}
	}
	return o
}

// decideSSH authorizes an SSH host by bearer token. The terminal cannot show a cookie, so the token
// is verified locally and only the owner of the handle the label names is let in. A missing or
// invalid token is a 401 (the client may retry with a fresh one); anything else but a clear owner is
// a 403; a store or verifier that cannot answer is a 503.
func (a Authz) decideSSH(r *http.Request, label string) outcome {
	handle, _, valid := names.ParseLabel(label)
	if !valid {
		return outcome{reason: "host", status: http.StatusForbidden}
	}
	o := outcome{label: label, status: http.StatusForbidden}
	token, ok := bearerToken(r)
	if !ok {
		o.reason, o.status = "token", http.StatusUnauthorized
		return o
	}
	ctx, cancel := context.WithTimeout(r.Context(), a.timeout())
	defer cancel()
	// A broker built without a token verifier (a bare Deps) must answer 503, not panic.
	if a.Verifier == nil {
		o.reason, o.err, o.status = "verify", errors.New("authz: no token verifier"), http.StatusServiceUnavailable
		return o
	}
	sub, err := a.Verifier.VerifyAccessToken(ctx, token)
	if err != nil {
		o.status = http.StatusServiceUnavailable
		if errors.Is(err, idp.ErrInvalidToken) {
			o.status, o.reason = http.StatusUnauthorized, "token"
		} else {
			o.reason, o.err = "verify", err
		}
		return o
	}
	o.sub = sub
	ownerStart := time.Now()
	owner, err := a.Users.UserByHandle(ctx, handle)
	a.observe("owner", ownerStart)
	switch {
	case errors.Is(err, store.ErrNotFound):
		o.reason = "unknown_owner"
	case err != nil:
		o.reason, o.err, o.status = "store", err, http.StatusServiceUnavailable
	case owner.Disabled:
		o.reason = "disabled"
	case owner.Sub != sub:
		o.reason = "not_owner"
	default:
		o.allow, o.reason = true, "owner"
	}
	return o
}

// siteOwner is who owns the site named by handle. A person's own handle is their row. A machine's
// handle names a machine, whose site is owned by the machine's owner_ref (a user), never by the
// machine's own handle: the share that admits a viewer is keyed by that owner and the machine's
// handle together. A disabled machine, or a disabled or absent owner, is refused.
func (a Authz) siteOwner(ctx context.Context, handle string) (siteOwner, error) {
	u, err := a.Users.UserByHandle(ctx, handle)
	switch {
	case err == nil:
		return siteOwner{ref: u.Sub, disabled: u.Disabled}, nil
	case !errors.Is(err, store.ErrNotFound):
		return siteOwner{}, err
	}
	// A broker built without a machine store (a bare Deps) must deny rather than panic.
	if a.Machines == nil {
		return siteOwner{}, store.ErrNotFound
	}
	m, err := a.Machines.MachineByHandle(ctx, handle)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return siteOwner{}, store.ErrNotFound
	case err != nil:
		return siteOwner{}, err
	case m.Disabled:
		return siteOwner{ref: m.OwnerRef, disabled: true}, nil
	}
	// The machine's owner_ref is a user sub today; a group-owned machine (Decision 8) would miss here
	// and deny — fail closed, as an unknown owner should.
	owner, err := a.Users.UserBySub(ctx, m.OwnerRef)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return siteOwner{}, store.ErrNotFound
	case err != nil:
		return siteOwner{}, err
	}
	return siteOwner{ref: owner.Sub, disabled: owner.Disabled}, nil
}

// siteOwner is the principal that owns a site: the users row whose shares may admit a visitor.
type siteOwner struct {
	ref      string // a users sub
	disabled bool
}

// crossOwner reports whether a state-changing request (not GET, HEAD or OPTIONS) carries an Origin
// whose host is a valid sites host owned by someone other than target. A missing or foreign Origin
// is allowed: only a browser Origin that Traefik actually routes is a cross-owner page.
func (a Authz) crossOwner(r *http.Request, target string) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	origins := r.Header["Origin"]
	if len(origins) == 0 {
		return false
	}
	u, err := url.Parse(origins[0])
	if err != nil {
		return false
	}
	label, ok := names.SiteLabel(u.Hostname(), a.SitesDomain)
	if !ok {
		return false
	}
	handle, _, _ := names.ParseLabel(label)
	return handle != target
}

// groupsOf reads the visitor's groups from X-Tunnels-Groups: several values, each possibly a
// comma-separated list. Names are matched exactly; a group name containing a comma is unsupported.
func groupsOf(r *http.Request) []string {
	var groups []string
	for _, value := range r.Header.Values("X-Tunnels-Groups") {
		for _, group := range strings.Split(value, ",") {
			if group = strings.TrimSpace(group); group != "" {
				groups = append(groups, group)
			}
		}
	}
	return groups
}
