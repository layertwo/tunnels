// Package cli is the tunnel command: login, up, logout and version.
package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/pflag"

	"github.com/layertwo/tunnels/internal/auth"
	"github.com/layertwo/tunnels/internal/httpx"
	"github.com/layertwo/tunnels/internal/names"
	"github.com/layertwo/tunnels/internal/tunnel"
	"github.com/layertwo/tunnels/internal/ws"
)

// Env is what the command runs against.
type Env struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	ConfigDir      string // "" means $TUNNELS_CONFIG_DIR, else <os.UserConfigDir()>/tunnels
	DefaultServer  string // set at build time
	Version        string // set at build time
	HTTP           *http.Client
	// Run starts the tunnel; nil means tunnel.Run. Tests replace it so that they need no frps.
	Run func(ctx context.Context, o tunnel.Options, onStatus func(tunnel.Status)) error
}

const usage = `Usage:
  tunnel login [--server HOST]                    log in with your browser
  tunnel up PORT [--name NAME]                    publish http://127.0.0.1:PORT until you stop it
  tunnel up PORT --ssh [--target HOST] [--name NAME]  publish an ssh service on HOST at PORT
  tunnel ssh-config [--name NAME]                 print an ssh_config block for an ssh tunnel
  tunnel dial HOST PORT                           pipe ssh through a published tunnel (an ssh ProxyCommand)
  tunnel share [--group] [--for DURATION] LABEL GRANTEE  let someone else reach a site (group shares need the gate to forward groups)
  tunnel unshare [--group] LABEL GRANTEE  stop sharing a site
  tunnel list                                     show what you share
  tunnel machine create NAME                      make a machine publish as itself, no passkey (run it on the machine)
  tunnel machine list                             show your machines
  tunnel machine remove NAME                      revoke a machine
  tunnel logout                                   forget the login on this computer
  tunnel version
`

const usageUp = "Usage: tunnel up PORT [--ssh] [--target HOST] [--name NAME]"

const usageMachine = "Usage: tunnel machine create NAME | list | remove NAME"

const usageDial = "Usage: tunnel dial HOST PORT"

// Main runs the command in args and returns the exit code: 0 done, 1 failed, 2 used wrongly.
func Main(args []string, env Env) int {
	if env.HTTP == nil {
		env.HTTP = httpx.Client("tunnels/"+env.Version, 10*time.Second)
	}
	if env.Stdin == nil {
		env.Stdin = os.Stdin
	}
	if env.Run == nil {
		env.Run = tunnel.Run
	}
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, usage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd, rest := args[0], args[1:]; cmd {
	case "login":
		return login(ctx, env, rest)
	case "up":
		return up(ctx, env, rest)
	case "share":
		return share(ctx, env, rest, false)
	case "unshare":
		return share(ctx, env, rest, true)
	case "list":
		return list(ctx, env, rest)
	case "ssh-config":
		return sshConfig(ctx, env, rest)
	case "dial":
		return dial(ctx, env, rest)
	case "machine":
		return machine(ctx, env, rest)
	case "logout", "version":
		if len(rest) > 0 {
			fmt.Fprint(env.Stderr, usage)
			return 2
		}
		if cmd == "version" {
			fmt.Fprintf(env.Stdout, "tunnel %s (server %s)\n", env.Version, env.DefaultServer)
			return 0
		}
		return logout(env)
	case "help", "-h", "--help":
		fmt.Fprint(env.Stdout, usage)
		return 0
	default:
		fmt.Fprintf(env.Stderr, "unknown command %q\n%s", cmd, usage)
		return 2
	}
}

func store(env Env) (auth.Store, error) {
	dir := env.ConfigDir
	if dir == "" {
		dir = os.Getenv("TUNNELS_CONFIG_DIR")
	}
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return auth.Store{}, fmt.Errorf("no place for the login: %w", err)
		}
		dir = filepath.Join(base, "tunnels")
	}
	return auth.Store{Dir: dir}, nil
}

// baseURL is the service's address: a value with a scheme as it is, otherwise https.
func baseURL(server string) string {
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		server = "https://" + server
	}
	return strings.TrimRight(server, "/")
}

func oidcFor(b auth.Bootstrap, hc *http.Client) auth.OIDC {
	return auth.OIDC{Issuer: b.Issuer, ClientID: b.CLIClientID, Resource: b.APIResource, HTTP: hc}
}

func login(ctx context.Context, env Env, args []string) int {
	fs := pflag.NewFlagSet("login", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	server := fs.String("server", env.DefaultServer, "the tunnel service")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		if err != nil {
			fmt.Fprintln(env.Stderr, err)
		}
		fmt.Fprint(env.Stderr, usage)
		return 2
	}
	s, err := store(env)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	base := baseURL(*server)
	b, err := auth.Discover(ctx, env.HTTP, base)
	if err != nil {
		fmt.Fprintf(env.Stderr, "cannot reach %s: %v\n", base, err)
		return 1
	}
	o := oidcFor(b, env.HTTP)
	tok, err := o.DeviceLogin(ctx, env.Stdout)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	me, err := auth.GetMe(ctx, env.HTTP, base, tok.AccessToken)
	if err != nil { // the service's own sentence, e.g. what to ask an admin for
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	tok.Handle, tok.Server, tok.SSHDomain = me.Handle, base, b.SSHDomain
	if err := s.Save(tok); err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	fmt.Fprintf(env.Stdout, "Logged in as %s (%s)\n", me.Username, me.Handle)
	return 0
}

func up(ctx context.Context, env Env, args []string) int {
	fs := pflag.NewFlagSet("up", pflag.ContinueOnError)
	fs.SetOutput(io.Discard) // with ContinueOnError pflag prints nothing useful; bad() says what was wrong
	name := fs.String("name", "", "the tunnel's name; none publishes https://<handle>.<sites domain>")
	ssh := fs.Bool("ssh", false, "publish an ssh service on the target at PORT instead of a site")
	target := fs.String("target", "127.0.0.1", "the ssh target host; a bare host, no port and no scheme")
	bad := func(format string, a ...any) int {
		fmt.Fprintf(env.Stderr, format+"\n%s\n", append(a, usageUp)...)
		return 2
	}
	if err := fs.Parse(args); err != nil {
		return bad("%v", err)
	}
	if fs.NArg() != 1 {
		return bad("give the port to publish")
	}
	port, err := strconv.Atoi(fs.Arg(0))
	if err != nil || port < 1 || port > 65535 {
		return bad("%q is not a port: use 1 to 65535", fs.Arg(0))
	}
	if *name != "" && !names.ValidTunnelName(*name) {
		return bad("%q is not a tunnel name: use 1 to 42 lowercase letters, digits and inner dashes, other than %q", *name, names.Default)
	}
	if *ssh && (*target == "" || strings.ContainsAny(*target, ":/")) {
		return bad("--target %q is not a bare host: use a host, without a port or a scheme", *target)
	}

	// Start with a fresh token: the stored one may be hours old, and frp logs in with what the file holds.
	s, b, tok, ok := session(ctx, env)
	if !ok {
		return 1
	}
	if *ssh && b.SSHDomain == "" {
		fmt.Fprintln(env.Stderr, "this server has ssh disabled")
		return 2
	}
	o := oidcFor(b, env.HTTP)
	caFile, err := tunnel.WriteCABundle(s.Dir)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // ends the refresher with the tunnel
	go auth.KeepFresh(ctx, s, o, 30*time.Minute, warnRefreshFailed(env.Stderr))

	label := names.Label(tok.Handle, *name)
	// In ssh mode the bridge chooses its own local port and dials the target, so PORT is the target's.
	url := "https://" + label + "." + b.SitesDomain
	if *ssh {
		url = "ssh " + label + "." + b.SSHDomain
	}
	printed := map[string]bool{}
	onStatus := func(st tunnel.Status) {
		switch st.Phase {
		case "running":
			fmt.Fprintln(env.Stdout, url)
		case "start error":
			if printed[st.Err] {
				return // frp retries; the same answer once is enough
			}
			printed[st.Err] = true
			msg := st.Err
			// keep in sync with the broker's newProxy message in hooks.go: "tunnel limit of %d reached"
			if strings.HasPrefix(msg, "tunnel limit of") {
				msg += " (a tunnel that ended without saying goodbye counts for up to 90 seconds)"
			}
			fmt.Fprintln(env.Stderr, msg)
		}
	}
	opts := tunnel.Options{
		ServerHost: b.ServiceHost, ServerPort: 443, Protocol: "wss",
		Handle: tok.Handle, Name: *name, LocalPort: port,
		TokenFile: s.AccessTokenPath(), CAFile: caFile, Version: env.Version,
	}
	if *ssh {
		opts.SSH, opts.SSHTarget, opts.SSHPort, opts.SSHDomain = true, *target, port, b.SSHDomain
	}
	err = env.Run(ctx, opts, onStatus)
	if err != nil { // a refused first login: "login to the server failed: <the broker's reason>"
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	return 0
}

// sshConfig prints the ssh_config Host block for one of the owner's ssh tunnels. It needs only the
// stored handle and the service's ssh domain, so it sends no token.
func sshConfig(ctx context.Context, env Env, args []string) int {
	fs := pflag.NewFlagSet("ssh-config", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	name := fs.String("name", "", "the tunnel's name; none configures the default tunnel")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		if err != nil {
			fmt.Fprintln(env.Stderr, err)
		}
		fmt.Fprint(env.Stderr, usage)
		return 2
	}
	if *name != "" && !names.ValidTunnelName(*name) {
		fmt.Fprintf(env.Stderr, "%q is not a tunnel name: use 1 to 42 lowercase letters, digits and inner dashes, other than %q\n%s\n", *name, names.Default, usageUp)
		return 2
	}
	s, err := store(env)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	tok, err := s.Load()
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	b, err := auth.Discover(ctx, env.HTTP, tok.Server)
	if err != nil {
		fmt.Fprintf(env.Stderr, "cannot reach %s: %v\n", tok.Server, err)
		return 1
	}
	if b.SSHDomain == "" {
		fmt.Fprintln(env.Stderr, "this server has ssh disabled")
		return 2
	}
	label := names.Label(tok.Handle, *name)
	fmt.Fprintf(env.Stdout, "Host %s\n\tHostName %s.%s\n\tProxyCommand tunnel dial %%h %%p\n", label, label, b.SSHDomain)
	return 0
}

// warnRefreshFailed is KeepFresh's onErr for a running tunnel: it says the login could not be
// refreshed and will be tried again, so a failed refresh is not mistaken for the tunnel ending.
func warnRefreshFailed(out io.Writer) func(error) {
	return func(err error) {
		fmt.Fprintf(out, "could not refresh your session, will try again: %v\n", err)
	}
}

// session loads the stored login, finds the service and refreshes the token; it is the one place that
// prints what a failure of either step means. It also returns the store and the bootstrap document, for
// the caller that needs them (up).
func session(ctx context.Context, env Env) (auth.Store, auth.Bootstrap, auth.Tokens, bool) {
	s, err := store(env)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return auth.Store{}, auth.Bootstrap{}, auth.Tokens{}, false
	}
	tok, err := s.Load()
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return auth.Store{}, auth.Bootstrap{}, auth.Tokens{}, false
	}
	b, err := auth.Discover(ctx, env.HTTP, tok.Server)
	if err != nil {
		fmt.Fprintf(env.Stderr, "cannot reach %s: %v\n", tok.Server, err)
		return auth.Store{}, auth.Bootstrap{}, auth.Tokens{}, false
	}
	tok, err = auth.RefreshStored(ctx, s, oidcFor(b, env.HTTP))
	if err != nil {
		refreshFailed(env, err)
		return auth.Store{}, auth.Bootstrap{}, auth.Tokens{}, false
	}
	return s, b, tok, true
}

// refreshFailed says a login could not be refreshed, and what to run about it.
func refreshFailed(env Env, err error) {
	// auth.Refresh's errors already end with "; run: tunnel login"; strip it so the sentence is not doubled.
	fmt.Fprintf(env.Stderr, "could not refresh your session (%s); run: tunnel login\n", strings.TrimSuffix(err.Error(), "; run: tunnel login"))
}

// dial pipes this process's stdin and stdout to the published ssh tunnel at HOST, so ssh's
// ProxyCommand sees a raw stream. ssh runs it once per connection, so it is short-lived.
func dial(ctx context.Context, env Env, args []string) int {
	fs := pflag.NewFlagSet("dial", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bad := func(format string, a ...any) int {
		fmt.Fprintf(env.Stderr, format+"\n"+usageDial+"\n", a...)
		return 2
	}
	if err := fs.Parse(args); err != nil {
		return bad("%v", err)
	}
	if fs.NArg() != 2 {
		return bad("give the ssh host and port")
	}
	// PORT is what ssh passed (%p); the data route is ordinary https, so it is checked and then unused.
	if port, err := strconv.Atoi(fs.Arg(1)); err != nil || port < 1 || port > 65535 {
		return bad("%q is not a port: use 1 to 65535", fs.Arg(1))
	}
	host := fs.Arg(0)

	s, err := store(env)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	tok, err := s.Load()
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	// ssh passes %h from ~/.ssh/config, so a mistyped or tampered HostName would otherwise send
	// the access token to a third party. The login stored the service's ssh domain: a host outside
	// it, or one carrying a port, is refused here before TLS and before any discovery.
	if _, ok := names.SSHLabel(host, tok.SSHDomain); !ok {
		return bad("%q is not an ssh host of this service", host)
	}
	// The provider is needed only to refresh, so it is discovered on first use: a fresh token dials
	// with no .well-known request, and a momentarily broken endpoint cannot fail a dial that does
	// not refresh.
	var (
		resolveOnce sync.Once
		refresher   auth.OIDC
		resolveErr  error
	)
	resolve := func(ctx context.Context) (auth.OIDC, error) {
		resolveOnce.Do(func() {
			b, err := auth.Discover(ctx, env.HTTP, tok.Server)
			if err != nil {
				resolveErr = fmt.Errorf("cannot reach %s: %v", tok.Server, err)
				return
			}
			refresher = oidcFor(b, env.HTTP)
		})
		return refresher, resolveErr
	}
	caFile, err := tunnel.WriteCABundle(s.Dir)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	pool, err := rootPool(caFile)
	if err != nil {
		fmt.Fprintln(env.Stderr, err) // coverage-ignore: WriteCABundle just wrote this file, so it always parses
		return 1
	}
	d := &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			ServerName: host, NextProtos: []string{"http/1.1"}, RootCAs: pool,
		},
	}
	// ssh's %p is the target's port, not the data route's: the tunnel is reached on 443 through Traefik.
	return dialStream(ctx, env, d, "wss://"+host+":443/", s, resolve, tok)
}

// wsDial opens the WebSocket; *websocket.Dialer is the real one.
type wsDial interface {
	DialContext(ctx context.Context, urlStr string, requestHeader http.Header) (*websocket.Conn, *http.Response, error)
}

// oidcSource resolves the identity provider a token refresh needs. dial's discovers the service
// on first use, so a dial that does not refresh makes no discovery request.
type oidcSource func(context.Context) (auth.OIDC, error)

// dialStream opens the WebSocket to url presenting the login, then pumps it to this process's stdin
// and stdout. On a 401 handshake it refreshes the login once and retries.
func dialStream(ctx context.Context, env Env, d wsDial, url string, s auth.Store, src oidcSource, tok auth.Tokens) int {
	token, err := dialToken(ctx, s, src, tok)
	if err != nil {
		refreshFailed(env, err)
		return 1
	}
	conn, resp, err := d.DialContext(ctx, url, dialHeader(token, env.Version))
	if refused(err, resp) {
		// The token aged between the check and the dial: refresh once and try again.
		token, err = refreshLogin(ctx, s, src)
		if err != nil {
			refreshFailed(env, err)
			return 1
		}
		conn, resp, err = d.DialContext(ctx, url, dialHeader(token, env.Version))
		if refused(err, resp) {
			fmt.Fprintln(env.Stderr, "your login was refused; run: tunnel login")
			return 1
		}
	}
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	defer conn.Close()
	_ = ws.Pipe(conn, stdio{in: env.Stdin, out: env.Stdout})
	return 0
}

// tokenSkew is how early an access token counts as stale at the dial handshake.
const tokenSkew = time.Minute

// dialToken is the token to present: the stored one while it has not expired, else a refreshed one.
// Refreshing only when stale keeps dial from rotating the login that a running up also holds.
func dialToken(ctx context.Context, s auth.Store, src oidcSource, tok auth.Tokens) (string, error) {
	if jwtExpiry(tok.AccessToken).After(time.Now().Add(tokenSkew)) {
		return tok.AccessToken, nil
	}
	return refreshLogin(ctx, s, src)
}

// refreshLogin mints a fresh access token from the stored refresh token, resolving the provider only
// now: a stale token needs it, and so does a 401 retry.
func refreshLogin(ctx context.Context, s auth.Store, src oidcSource) (string, error) {
	o, err := src(ctx)
	if err != nil {
		return "", err
	}
	fresh, err := auth.RefreshStored(ctx, s, o)
	if err != nil {
		return "", err
	}
	return fresh.AccessToken, nil
}

// jwtExpiry reads a JWT's exp claim without checking its signature: the broker is the verifier, and
// dial only needs to know whether the stored token is worth presenting. The zero time means it
// could not be read, which is treated as stale.
func jwtExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var c struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &c) != nil || c.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(c.Exp, 0)
}

// dialHeader is the handshake's headers: the token's only place, plus the CLI's own name. The token
// never goes in the URL.
func dialHeader(token, version string) http.Header {
	return http.Header{"Authorization": {"Bearer " + token}, "User-Agent": {"tunnels/" + version}}
}

// refused reports whether a handshake answered 401, the sign of an aged token.
func refused(err error, resp *http.Response) bool {
	return errors.Is(err, websocket.ErrBadHandshake) && resp != nil && resp.StatusCode == http.StatusUnauthorized
}

// rootPool is the certificate pool that verifies the tunnel's server, from the CA bundle a login
// writes.
func rootPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no certificates", caFile)
	}
	return pool, nil
}

// stdio is this process's stdin and stdout as the stream ws.Pipe pumps.
type stdio struct {
	in  io.Reader
	out io.Writer
}

func (s stdio) Read(p []byte) (int, error)  { return s.in.Read(p) }
func (s stdio) Write(p []byte) (int, error) { return s.out.Write(p) }
func (s stdio) Close() error                { return nil }

// share grants or, when remove is set, removes access to one of the owner's sites, named by its label
// (<handle> for the default site, <handle>-<name> for a named one).
func share(ctx context.Context, env Env, args []string, remove bool) int {
	verb := "share"
	if remove {
		verb = "unshare"
	}
	fs := pflag.NewFlagSet(verb, pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	group := fs.Bool("group", false, "share with a Pocket ID group instead of a username")
	lifetime := fs.String("for", "", "how long the share lasts, e.g. 24h or 7d")
	shape := "[--group] LABEL GRANTEE"
	if !remove {
		shape = "[--group] [--for DURATION] LABEL GRANTEE"
	}
	bad := func(format string, a ...any) int {
		fmt.Fprintf(env.Stderr, format+"\nUsage: tunnel "+verb+" "+shape+"\n", a...)
		return 2
	}
	if err := fs.Parse(args); err != nil {
		return bad("%v", err)
	}
	if remove && fs.Changed("for") {
		return bad("--for is only for share, not unshare")
	}
	if fs.NArg() != 2 {
		return bad("give the site's label and the username or group to share with")
	}
	handle, tunnel, ok := names.ParseLabel(fs.Arg(0))
	if !ok {
		return bad("%q is not a site label: use <handle> or <handle>-<name>", fs.Arg(0))
	}
	var expiresAt time.Time
	if *lifetime != "" {
		d, err := parseDuration(*lifetime)
		if err != nil {
			return bad("--for %q: %v", *lifetime, err)
		}
		expiresAt = time.Now().Add(d)
	}
	kind := "user"
	if *group {
		kind = "group"
	}
	sh := auth.Share{Handle: handle, Tunnel: tunnel, Kind: kind, Grantee: fs.Arg(1), ExpiresAt: expiresAt}

	_, _, tok, ok := session(ctx, env)
	if !ok {
		return 1
	}
	var err error
	if remove {
		err = auth.DeleteShare(ctx, env.HTTP, tok.Server, tok.AccessToken, sh)
	} else {
		err = auth.PutShare(ctx, env.HTTP, tok.Server, tok.AccessToken, sh)
	}
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	label := names.Label(sh.Handle, sh.Tunnel)
	if remove {
		fmt.Fprintf(env.Stdout, "Stopped sharing %s with %s\n", label, sh.Grantee)
	} else {
		fmt.Fprintf(env.Stdout, "Shared %s with %s\n", label, sh.Grantee)
	}
	return 0
}

// list prints the shares the owner set on the service, each named by its site label.
func list(ctx context.Context, env Env, args []string) int {
	if len(args) > 0 {
		fmt.Fprint(env.Stderr, usage)
		return 2
	}
	_, _, tok, ok := session(ctx, env)
	if !ok {
		return 1
	}
	shares, err := auth.ListShares(ctx, env.HTTP, tok.Server, tok.AccessToken)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	for _, sh := range shares {
		fmt.Fprintf(env.Stdout, "%s\t%s\t%s\t%s\n", names.Label(sh.Handle, sh.Tunnel), sh.Kind, sh.Grantee, expiryLabel(sh.ExpiresAt))
	}
	return 0
}

// machine dispatches the machine subcommands: create, list and remove.
func machine(ctx context.Context, env Env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(env.Stderr, usageMachine)
		return 2
	}
	switch sub, rest := args[0], args[1:]; sub {
	case "create":
		return machineCreate(ctx, env, rest)
	case "list":
		return machineList(ctx, env, rest)
	case "remove":
		return machineRemove(ctx, env, rest)
	default:
		fmt.Fprintf(env.Stderr, "unknown machine command %q\n%s\n", sub, usageMachine)
		return 2
	}
}

// machineBad prints the usage line and fails the command as used wrongly.
func machineBad(env Env, format string, a ...any) int {
	fmt.Fprintf(env.Stderr, format+"\n"+usageMachine+"\n", a...)
	return 2
}

// machineCreate runs on the target machine: it generates a key pair here, asks the broker (as the
// owner) to register the public half, and leaves the config dir ready for up. The private key never
// leaves this machine.
func machineCreate(ctx context.Context, env Env, args []string) int {
	if len(args) != 1 || !names.ValidHandle(args[0]) {
		return machineBad(env, "give a machine handle: 2 to 20 lowercase letters and digits")
	}
	handle := args[0]
	s, err := store(env)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	_, b, tok, ok := session(ctx, env)
	if !ok {
		return 1
	}
	key, err := auth.GenerateMachineKey()
	if err != nil {
		fmt.Fprintln(env.Stderr, err) // coverage-ignore: ecdsa generation cannot fail; crypto/rand.Reader does not
		return 1
	}
	keyPath := s.MachineKeyPath()
	if err := auth.SaveMachineKey(keyPath, key); err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	m, err := auth.CreateMachine(ctx, env.HTTP, tok.Server, tok.AccessToken, handle, key.Public())
	if err != nil {
		os.Remove(keyPath) // no key without a machine
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	login := auth.Tokens{ClientID: m.ClientID, MachineKey: keyPath, Handle: m.Handle, Server: tok.Server, SSHDomain: b.SSHDomain}
	if err := s.Save(login); err != nil {
		fmt.Fprintln(env.Stderr, err) // coverage-ignore: session just wrote here, so saving the machine login cannot fail
		return 1
	}
	fmt.Fprintf(env.Stdout, "Created machine %s\n", m.Handle)
	return 0
}

// machineList prints the owner's machines, each as its handle and client id.
func machineList(ctx context.Context, env Env, args []string) int {
	if len(args) != 0 {
		return machineBad(env, "list takes no arguments")
	}
	_, _, tok, ok := session(ctx, env)
	if !ok {
		return 1
	}
	machines, err := auth.ListMachines(ctx, env.HTTP, tok.Server, tok.AccessToken)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	for _, m := range machines {
		fmt.Fprintf(env.Stdout, "%s\t%s\n", m.Handle, m.ClientID)
	}
	return 0
}

// machineRemove revokes a machine by handle.
func machineRemove(ctx context.Context, env Env, args []string) int {
	if len(args) != 1 || !names.ValidHandle(args[0]) {
		return machineBad(env, "give the machine's handle: 2 to 20 lowercase letters and digits")
	}
	_, _, tok, ok := session(ctx, env)
	if !ok {
		return 1
	}
	if err := auth.DeleteMachine(ctx, env.HTTP, tok.Server, tok.AccessToken, args[0]); err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	// If this box is logged in as the machine just removed, its local login and private key go too.
	// The server-side machine is already gone; a local cleanup that fails must not undo that.
	if tok.Handle == args[0] {
		_ = forgetLocal(env)
	}
	fmt.Fprintf(env.Stdout, "Removed machine %s\n", args[0])
	return 0
}

// parseDuration is time.ParseDuration with "d" meaning 24 hours, so "7d" is a week.
func parseDuration(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseFloat(days, 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(n * 24 * float64(time.Hour)), nil
	}
	return time.ParseDuration(s)
}

// expiryLabel is a share's end as a person reads it: "never" when it has none.
func expiryLabel(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format(time.RFC3339)
}

// forgetLocal clears this computer's login and the machine's private key from the config dir.
func forgetLocal(env Env) error {
	s, err := store(env)
	if err != nil {
		return err
	}
	return s.Clear()
}

func logout(env Env) int {
	if err := forgetLocal(env); err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	fmt.Fprintln(env.Stdout, "Logged out")
	return 0
}
