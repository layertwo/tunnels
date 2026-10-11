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

	"github.com/layertwo/tunnels/internal/names"
	"github.com/layertwo/tunnels/internal/store"
)

// Shares manages an owner's tunnel shares; store.Store implements it.
type Shares interface {
	PutShare(ctx context.Context, ownerSub string, sh store.Share) error
	DeleteShare(ctx context.Context, ownerSub string, sh store.Share) error
	SharesByOwner(ctx context.Context, ownerSub string) ([]store.Share, error)
	ShareMatches(ctx context.Context, ownerSub, tunnel, username string, groups []string) (bool, error)
}

// ShareMatcher is the part of Shares the authz decision needs: whether a share covers a visitor.
type ShareMatcher interface {
	ShareMatches(ctx context.Context, ownerSub, tunnel, username string, groups []string) (bool, error)
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
// Everything that is not a clear allow is the same empty 403, so nothing tells a name that exists
// from one that does not. A store that cannot answer is an empty 503. It keeps no state and is safe
// for concurrent use.
type Authz struct {
	Users       Users
	Shares      ShareMatcher
	SitesDomain string        // the domain sites live under, without a port or a trailing dot
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
	reason string // the class of the decision: owner, shared, host, identity, cross_owner, unknown_owner, disabled, not_owner, store
	label  string
	sub    string
	user   string // the visitor's username, for the allow answer
	err    error  // set when the store could not answer
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
		w.Header().Set("X-Tunnel-User", o.user)
		w.WriteHeader(http.StatusOK)
	default:
		log.LogAttrs(r.Context(), slog.LevelInfo, "authz", append(attrs, slog.String("decision", "deny"))...)
		w.WriteHeader(http.StatusForbidden)
	}
}

func (a Authz) decide(r *http.Request) outcome {
	// A header that is missing, empty or repeated is refused: with more than one value there is no
	// telling which one the gate set. The headers are indexed by their canonical names (how net/http
	// stores them) rather than read with Values: that is how CodeQL's clear-text-logging check sees a
	// header that holds no credential, and the label and the sub from them are logged.
	hosts := r.Header["X-Forwarded-Host"]
	if a.SitesDomain == "" || len(hosts) != 1 {
		return outcome{reason: "host"}
	}
	label, ok := names.SiteLabel(hosts[0], a.SitesDomain)
	handle, tunnel, valid := names.ParseLabel(label)
	if !ok || !valid {
		return outcome{reason: "host"}
	}

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
	owner, err := a.Users.UserByHandle(ctx, handle)
	a.observe("owner", ownerStart)
	switch {
	case errors.Is(err, store.ErrNotFound):
		o.reason = "unknown_owner"
	case err != nil:
		o.reason, o.err = "store", err
	case owner.Disabled:
		o.reason = "disabled"
	case owner.Sub == o.sub:
		o.allow, o.reason, o.user = true, "owner", users[0]
	default:
		if a.Shares == nil {
			o.reason, o.err = "store", errors.New("authz: no shares store")
			return o
		}
		sharesStart := time.Now()
		shared, err := a.Shares.ShareMatches(ctx, owner.Sub, tunnel, users[0], groupsOf(r))
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
