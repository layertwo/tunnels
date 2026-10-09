package broker

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/layertwo/tunnels/internal/idp"
)

// TokenVerifier checks that an access token was issued for this API and returns its subject.
type TokenVerifier interface {
	VerifyAccessToken(ctx context.Context, raw string) (sub string, err error)
}

// Deps are what the handler talks to.
type Deps struct {
	IdP      IdP
	Verifier TokenVerifier
	Users    Users
	Frps     Frps
	Log      *slog.Logger
}

// NewHandler serves everything the broker answers: the frps plugin, /authz for Traefik, the API the
// CLI uses and the document that tells it where to log in.
func NewHandler(cfg Config, d Deps) http.Handler {
	resolver := Resolver{IdP: d.IdP, Users: d.Users, CreatorsGroup: cfg.CreatorsGroup, Reserved: cfg.Reserved}
	s := &server{cfg: cfg, d: d, resolver: resolver}

	mux := http.NewServeMux()
	// No method here: Hooks answers a wrong secret with 404 whatever the method, so a probe learns nothing.
	mux.Handle("/plugin/", &Hooks{
		Resolver: resolver, Frps: d.Frps, Secret: cfg.PluginSecret,
		MaxTunnelsPerUser: cfg.MaxTunnelsPerUser, BandwidthLimit: cfg.BandwidthLimit, Log: d.Log,
	})
	mux.Handle("/authz", Authz{Users: d.Users, SitesDomain: cfg.SitesDomain, Log: d.Log})
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("GET /.well-known/tunnels.json", s.wellKnown)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return mux
}

type server struct {
	cfg      Config
	d        Deps
	resolver Resolver
}

// me tells a logged-in creator their handle. The token must have been issued for this API, which
// userinfo alone does not show: any application's token for the same person would pass there.
func (s *server) me(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody("invalid token"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultDecisionTimeout)
	defer cancel()
	if _, err := s.d.Verifier.VerifyAccessToken(ctx, token); err != nil {
		writeJSON(w, http.StatusUnauthorized, errorBody("invalid token"))
		return
	}

	acct, err := s.resolver.Resolve(ctx, token)
	if err == nil {
		writeJSON(w, http.StatusOK, acct)
		return
	}
	text, theirs := reasonOf(err)
	switch {
	case errors.Is(err, idp.ErrInvalidToken):
		writeJSON(w, http.StatusUnauthorized, errorBody(text))
	case theirs:
		writeJSON(w, http.StatusForbidden, errorBody(text))
	default:
		cmpLogger(s.d.Log).Warn("api/me: could not resolve the account", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, errorBody(text))
	}
}

// wellKnown is what the CLI needs to find the identity provider and the service.
func (s *server) wellKnown(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Issuer        string `json:"issuer"`
		CLIClientID   string `json:"cli_client_id"`
		APIResource   string `json:"api_resource"`
		ServiceHost   string `json:"service_host"`
		SitesDomain   string `json:"sites_domain"`
		MinCLIVersion string `json:"min_cli_version"`
	}{s.cfg.Issuer, s.cfg.CLIClientID, s.cfg.APIResource, s.cfg.ServiceHost, s.cfg.SitesDomain, s.cfg.MinCLIVersion})
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
