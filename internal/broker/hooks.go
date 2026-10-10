package broker

import (
	"cmp"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	plugin "github.com/fatedier/frp/pkg/plugin/server"

	"github.com/layertwo/tunnels/internal/names"
)

// Frps is what the hooks ask the frps dashboard; frpsapi.Client implements it.
type Frps interface {
	OnlineRunIDUser(ctx context.Context, runID string) (user string, online bool, err error)
	OnlineProxyCount(ctx context.Context, user string) (int, error)
}

// Hooks is frps's HTTP plugin for the Login, NewProxy, CloseProxy and Ping ops, mounted at /plugin/<Secret>.
// It keeps no state and is safe for concurrent use.
//
// Every decision, accept or reject, is HTTP 200: frps shows its client any other error status as an
// opaque "send Login request to plugin error". A decision that cannot be made (a dependency is down
// or slow) is a reject, except a Ping: a ping the broker cannot verify is allowed, because frps
// re-verifies the ping's token itself and this hook only adds the account checks frps cannot make.
type Hooks struct {
	Resolver          Resolver
	Frps              Frps
	Secret            string        // the last path element frps is configured with; empty refuses everything
	MaxTunnelsPerUser int           // proxies one user may have online
	BandwidthLimit    string        // applied to every proxy, in "server" mode
	Timeout           time.Duration // for one decision; zero means 8 s
	Log               *slog.Logger
}

const maxBody = 1 << 20

// defaultDecisionTimeout stays under the 10 s a frp client waits for its Login answer before failing
// with a bare i/o timeout, so a slow dependency still gets a reason. /api/me uses it too.
const defaultDecisionTimeout = 8 * time.Second

func (h *Hooks) timeout() time.Duration { return cmp.Or(h.Timeout, defaultDecisionTimeout) }

func (h *Hooks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	secret, ok := strings.CutPrefix(r.URL.Path, "/plugin/")
	if !ok || h.Secret == "" || subtle.ConstantTimeCompare([]byte(secret), []byte(h.Secret)) != 1 {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		Op      string          `json:"op"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout())
	defer cancel()
	var (
		res plugin.Response
		err error
	)
	switch req.Op {
	case plugin.OpLogin:
		res, err = h.login(ctx, req.Content)
	case plugin.OpNewProxy:
		res, err = h.newProxy(ctx, req.Content)
	case plugin.OpCloseProxy:
		res, err = h.closeProxy(ctx, req.Content)
	case plugin.OpPing:
		res, err = h.ping(ctx, req.Content)
	default:
		err = fmt.Errorf("unknown op %q", req.Op)
	}
	if err != nil { // the request was malformed; a decision never gets here
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// login binds the connection to the account behind its privilege_key by setting user to the handle.
// privilege_key stays as it is: frps verifies it itself afterwards.
func (h *Hooks) login(ctx context.Context, raw json.RawMessage) (plugin.Response, error) {
	var c plugin.LoginContent
	if err := json.Unmarshal(raw, &c); err != nil {
		return plugin.Response{}, err
	}
	// Which CLI the person runs, as it says; a long value is cut, an old CLI sends none.
	var who []slog.Attr
	if v := c.Metas["tunnel_version"]; v != "" {
		who = append(who, slog.String("cli_version", v[:min(len(v), 64)]))
	}
	if c.PrivilegeKey == "" {
		return h.reject(ctx, plugin.OpLogin, "missing token", nil, who...), nil
	}
	acct, err := h.Resolver.Resolve(ctx, c.PrivilegeKey)
	if err != nil {
		text, theirs := reasonOf(err)
		if theirs {
			err = nil // the person's own doing is not a failure of ours
		}
		return h.reject(ctx, plugin.OpLogin, text, err, who...), nil
	}
	who = append(who, slog.String("handle", acct.Handle), slog.String("sub", acct.Sub))

	// A run ID that is online under somebody else would let this login push that client off.
	if c.RunID != "" {
		owner, online, err := h.Frps.OnlineRunIDUser(ctx, c.RunID)
		if err != nil {
			text, _ := reasonOf(err)
			return h.reject(ctx, plugin.OpLogin, text, err, who...), nil
		}
		if online && owner != acct.Handle {
			return h.reject(ctx, plugin.OpLogin, "run id belongs to another session", nil, who...), nil
		}
	}
	c.User = acct.Handle
	return h.accept(ctx, plugin.OpLogin, c, who...), nil
}

// newProxy lets through plain http tunnels the user owns, up to the limit.
func (h *Hooks) newProxy(ctx context.Context, raw json.RawMessage) (plugin.Response, error) {
	var c plugin.NewProxyContent
	if err := json.Unmarshal(raw, &c); err != nil {
		return plugin.Response{}, err
	}
	// user.user is what login set, not something the client sent.
	handle := c.User.User
	who := []slog.Attr{slog.String("handle", handle), slog.String("proxy", c.ProxyName)}

	if h.BandwidthLimit == "" { // frps reads "" as no limit, so this must not fail open
		return h.reject(ctx, plugin.OpNewProxy, "cannot verify your tunnels right now, try again", errors.New("hooks: no bandwidth limit configured"), who...), nil
	}
	if c.ProxyType != "http" || len(c.CustomDomains) > 0 || len(c.Locations) > 0 {
		return h.reject(ctx, plugin.OpNewProxy, "only plain http tunnels are allowed", nil, who...), nil
	}
	if !ownsProxy(handle, c.ProxyName, c.SubDomain) {
		return h.reject(ctx, plugin.OpNewProxy, "name "+c.ProxyName+" is not yours", nil, who...), nil
	}
	// ponytail: the dashboard only counts a proxy once frps has acted on the answer given here, so a
	// user who connects many clients at once can overshoot the limit (12 at once against a limit of 3
	// left 5 online). A lock here would not help; remember the names accepted in the last few seconds
	// and count them with the dashboard's if that ever matters (one broker replica assumed).
	online, err := h.Frps.OnlineProxyCount(ctx, handle)
	if err != nil {
		return h.reject(ctx, plugin.OpNewProxy, "cannot verify your tunnels right now, try again", err, who...), nil
	}
	if online >= h.MaxTunnelsPerUser {
		return h.reject(ctx, plugin.OpNewProxy, fmt.Sprintf("tunnel limit of %d reached", h.MaxTunnelsPerUser), nil, who...), nil
	}
	c.BandwidthLimit, c.BandwidthLimitMode = h.BandwidthLimit, "server"
	return h.accept(ctx, plugin.OpNewProxy, c, who...), nil
}

// ownsProxy reports whether proxy and subdomain are the name and the label of one of handle's
// tunnels: <handle>.default with <handle>, <handle>.<name> with <handle>-<name>. The handle is
// checked as well, because the label has to parse back to this owner.
func ownsProxy(handle, proxy, subdomain string) bool {
	tunnel, ok := strings.CutPrefix(proxy, handle+".")
	return ok && names.ValidHandle(handle) &&
		(tunnel == names.Default || names.ValidTunnelName(tunnel)) &&
		subdomain == names.Label(handle, tunnel)
}

func (h *Hooks) closeProxy(ctx context.Context, raw json.RawMessage) (plugin.Response, error) {
	var c plugin.CloseProxyContent
	if err := json.Unmarshal(raw, &c); err != nil {
		return plugin.Response{}, err
	}
	res := h.accept(ctx, plugin.OpCloseProxy, nil, slog.String("handle", c.User.User), slog.String("proxy", c.ProxyName))
	res.Unchange = true
	return res, nil
}

// ping is frps's heartbeat check, run for every client every 30 s with the token the client just read
// from disk. Re-resolving that token ends a removed or disabled account's tunnel on the next
// heartbeat: a rejection makes frpc close the session.
//
// Only an identity refusal is rejected here. An invalid or expired token, and a dependency of ours
// being down, are both left to frps, which re-verifies the ping's token itself (AuthVerifier.VerifyPing,
// HeartBeats in its auth scopes): a token that is genuinely bad still fails end-to-end, while a signing
// key we cannot fetch does not tear down a session frps would have accepted. This hook exists to add
// the account checks frps cannot make (group membership, disabled), not to duplicate frps's token check.
func (h *Hooks) ping(ctx context.Context, raw json.RawMessage) (plugin.Response, error) {
	var c plugin.PingContent
	if err := json.Unmarshal(raw, &c); err != nil {
		return plugin.Response{}, err
	}
	if c.PrivilegeKey == "" {
		return h.reject(ctx, plugin.OpPing, "missing token", nil), nil
	}
	acct, err := h.Resolver.Resolve(ctx, c.PrivilegeKey)
	if err != nil {
		if r, ok := refusalOf(err); ok {
			return h.reject(ctx, plugin.OpPing, r.text, nil), nil
		}
		h.Log.DebugContext(ctx, "ping: could not verify the session, allowed", "err", err)
		return plugin.Response{Unchange: true}, nil
	}
	// A heartbeat claiming another handle is not this client's heartbeat, whatever its token.
	if c.User.User != "" && c.User.User != acct.Handle {
		return h.reject(ctx, plugin.OpPing, "token does not belong to this session", nil), nil
	}
	return plugin.Response{Unchange: true}, nil
}

// accept answers with content, the whole of it, in place of what frps sent.
func (h *Hooks) accept(ctx context.Context, op string, content any, attrs ...slog.Attr) plugin.Response {
	h.Log.LogAttrs(ctx, slog.LevelInfo, "plugin decision", append(attrs, slog.String("op", op), slog.String("result", "accepted"))...)
	return plugin.Response{Content: content}
}

// reject answers with the reason the client shows. cause is the failure behind it when it was ours
// rather than the person's; it is logged, the client never sees it.
func (h *Hooks) reject(ctx context.Context, op, reason string, cause error, attrs ...slog.Attr) plugin.Response {
	level := slog.LevelInfo
	attrs = append(attrs, slog.String("op", op), slog.String("result", "rejected"), slog.String("reason", reason))
	if cause != nil {
		level = slog.LevelWarn
		attrs = append(attrs, slog.String("err", cause.Error()))
	}
	h.Log.LogAttrs(ctx, level, "plugin decision", attrs...)
	return plugin.Response{Reject: true, RejectReason: reason}
}
