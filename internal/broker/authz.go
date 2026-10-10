package broker

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/layertwo/tunnels/internal/names"
	"github.com/layertwo/tunnels/internal/store"
)

// Authz is the decision Traefik's forwardAuth asks for before it lets a request reach a site: allow
// (200, with X-Tunnel-User set to the visitor's username) or deny (403). The answer is built from
// the host the visitor asked for (X-Forwarded-Host) and the identity the OIDC gate put on the
// request (X-Tunnels-Sub, X-Tunnels-User). Only the owner gets in.
//
// Everything that is not a clear allow is the same empty 403, so nothing tells a name that exists
// from one that does not. A store that cannot answer is an empty 503. It keeps no state and is safe
// for concurrent use.
type Authz struct {
	Users       Users
	SitesDomain string        // the domain sites live under, without a port or a trailing dot
	Timeout     time.Duration // for the store lookup; zero means 5 s
	Log         *slog.Logger
}

func (a Authz) timeout() time.Duration { return cmp.Or(a.Timeout, 5*time.Second) }

// outcome is one decision and what is logged about it.
type outcome struct {
	allow  bool
	reason string // the class of the decision: owner, host, identity, unknown_owner, disabled, not_owner, store
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
	// telling which one the gate set.
	hosts := r.Header.Values("X-Forwarded-Host")
	if a.SitesDomain == "" || len(hosts) != 1 {
		return outcome{reason: "host"}
	}
	label, ok := names.SiteLabel(hosts[0], a.SitesDomain)
	handle, _, valid := names.ParseLabel(label)
	if !ok || !valid {
		return outcome{reason: "host"}
	}

	o := outcome{label: label}
	subs, users := r.Header.Values("X-Tunnels-Sub"), r.Header.Values("X-Tunnels-User")
	if len(subs) != 1 || subs[0] == "" || len(users) != 1 || users[0] == "" {
		o.reason = "identity"
		return o
	}
	o.sub = subs[0]

	ctx, cancel := context.WithTimeout(r.Context(), a.timeout())
	defer cancel()
	owner, err := a.Users.UserByHandle(ctx, handle)
	switch {
	case errors.Is(err, store.ErrNotFound):
		o.reason = "unknown_owner"
	case err != nil:
		o.reason, o.err = "store", err
	case owner.Disabled:
		o.reason = "disabled"
	case owner.Sub != o.sub:
		o.reason = "not_owner"
	default:
		o.allow, o.reason, o.user = true, "owner", users[0]
	}
	return o
}
