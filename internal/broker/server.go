package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/layertwo/tunnels/internal/auth"
	"github.com/layertwo/tunnels/internal/idp"
	"github.com/layertwo/tunnels/internal/names"
	"github.com/layertwo/tunnels/internal/store"
)

// Deps are what the handler talks to.
type Deps struct {
	IdP      IdP
	Verifier TokenVerifier
	Users    Users
	Shares   Shares
	Frps     Frps
	Log      *slog.Logger
}

// NewHandler serves everything the broker answers: the frps plugin, /authz for Traefik, the API the
// CLI uses and the document that tells it where to log in.
func NewHandler(cfg Config, d Deps) http.Handler {
	resolver := Resolver{IdP: d.IdP, Verifier: d.Verifier, Users: d.Users, CreatorsGroup: cfg.CreatorsGroup, Reserved: cfg.Reserved}
	s := &server{cfg: cfg, d: d, resolver: resolver}

	mux := http.NewServeMux()
	// No method here: Hooks answers a wrong secret with 404 whatever the method, so a probe learns nothing.
	mux.Handle("/plugin/", &Hooks{
		Resolver: resolver, Frps: d.Frps, Secret: cfg.PluginSecret,
		MaxTunnelsPerUser: cfg.MaxTunnelsPerUser, BandwidthLimit: cfg.BandwidthLimit, Log: d.Log,
	})
	mux.Handle("/authz", Authz{Users: d.Users, Shares: d.Shares, SitesDomain: cfg.SitesDomain, Log: d.Log})
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("GET /api/shares", s.sharesGet)
	mux.HandleFunc("PUT /api/shares", s.sharesPut)
	mux.HandleFunc("DELETE /api/shares", s.sharesDelete)
	mux.HandleFunc("GET /.well-known/tunnels.json", s.wellKnown)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return mux
}

type server struct {
	cfg      Config
	d        Deps
	resolver Resolver
}

// account resolves the request's bearer token exactly as /api/me has always done. On failure it
// writes the status and sentence and returns false, so the caller does nothing more.
func (s *server) account(w http.ResponseWriter, r *http.Request) (Account, bool) {
	token, ok := bearerToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody(notValid))
		return Account{}, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultDecisionTimeout)
	defer cancel()

	acct, err := s.resolver.Resolve(ctx, token)
	if err == nil {
		return acct, true
	}
	text, theirs := reasonOf(err)
	switch {
	case errors.Is(err, idp.ErrInvalidToken):
		writeJSON(w, http.StatusUnauthorized, errorBody(text))
	case theirs:
		writeJSON(w, http.StatusForbidden, errorBody(text))
	default:
		s.d.Log.Warn("api: could not resolve the account", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, errorBody(text))
	}
	return Account{}, false
}

// me tells a logged-in creator their handle.
func (s *server) me(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.account(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, acct)
}

// noSharesStore is what the share endpoints say when the broker has no shares store at all.
const noSharesStore = "sharing is unavailable, try again"

// sharesGet lists the caller's own shares.
func (s *server) sharesGet(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.account(w, r)
	if !ok {
		return
	}
	if s.d.Shares == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorBody(noSharesStore))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultDecisionTimeout)
	defer cancel()

	shares, err := s.d.Shares.SharesByOwner(ctx, acct.Sub)
	if err != nil {
		s.d.Log.Warn("api/shares: could not list the shares", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, errorBody("shares unavailable, try again"))
		return
	}
	if shares == nil {
		shares = []store.Share{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": shares})
}

// sharesPut and sharesDelete change the caller's own shares; both are idempotent.
func (s *server) sharesPut(w http.ResponseWriter, r *http.Request)    { s.changeShare(w, r, true) }
func (s *server) sharesDelete(w http.ResponseWriter, r *http.Request) { s.changeShare(w, r, false) }

func (s *server) changeShare(w http.ResponseWriter, r *http.Request, put bool) {
	acct, ok := s.account(w, r)
	if !ok {
		return
	}
	// Checked after the identity, so a caller with no session gets 401, not a 503.
	if s.d.Shares == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorBody(noSharesStore))
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	var sh store.Share
	if err := dec.Decode(&sh); err != nil || !validShare(sh) {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid share"))
		return
	}
	// Anything after the first JSON value is not the share the caller asked for.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid share"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultDecisionTimeout)
	defer cancel()

	apply := s.d.Shares.PutShare
	if !put {
		apply = s.d.Shares.DeleteShare
	}
	if err := apply(ctx, acct.Sub, sh); err != nil {
		s.d.Log.Warn("api/shares: could not store the share", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, errorBody("shares unavailable, try again"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validShare reports whether the body describes a share an owner may set. The empty tunnel is the
// default tunnel; names.ValidTunnelName already rejects "default".
func validShare(sh store.Share) bool {
	if sh.Tunnel != "" && !names.ValidTunnelName(sh.Tunnel) {
		return false
	}
	if sh.Grantee == "" {
		return false
	}
	switch sh.Kind {
	case "user":
		return true
	case "group":
		return !strings.Contains(sh.Grantee, ",")
	}
	return false
}

// wellKnown is what the CLI needs to find the identity provider and the service.
func (s *server) wellKnown(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, auth.Bootstrap{Issuer: s.cfg.Issuer, CLIClientID: s.cfg.CLIClientID, APIResource: s.cfg.APIResource,
		ServiceHost: s.cfg.ServiceHost, SitesDomain: s.cfg.SitesDomain, MinCLIVersion: s.cfg.MinCLIVersion})
}

// bearerToken is the token of an Authorization header that holds exactly one "Bearer <token>".
func bearerToken(r *http.Request) (string, bool) {
	v := r.Header.Values("Authorization")
	if len(v) != 1 {
		return "", false
	}
	scheme, token, ok := strings.Cut(v[0], " ")
	return token, ok && strings.EqualFold(scheme, "Bearer") && token != ""
}

func errorBody(text string) map[string]string { return map[string]string{"error": text} }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
