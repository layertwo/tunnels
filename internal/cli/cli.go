// Package cli is the tunnel command: login, up, logout and version.
package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/layertwo/tunnels/internal/auth"
	"github.com/layertwo/tunnels/internal/httpx"
	"github.com/layertwo/tunnels/internal/names"
	"github.com/layertwo/tunnels/internal/tunnel"
)

// Env is what the command runs against.
type Env struct {
	Stdout, Stderr io.Writer
	ConfigDir      string // "" means $TUNNELS_CONFIG_DIR, else <os.UserConfigDir()>/tunnels
	DefaultServer  string // set at build time
	Version        string // set at build time
	HTTP           *http.Client
	// Run starts the tunnel; nil means tunnel.Run. Tests replace it so that they need no frps.
	Run func(ctx context.Context, o tunnel.Options, onStatus func(tunnel.Status)) error
}

const usage = `Usage:
  tunnel login [--server HOST]   log in with your browser
  tunnel up PORT [--name NAME]   publish http://127.0.0.1:PORT until you stop it
  tunnel logout                  forget the login on this computer
  tunnel version
`

const usageUp = "Usage: tunnel up PORT [--name NAME]"

// Main runs the command in args and returns the exit code: 0 done, 1 failed, 2 used wrongly.
func Main(args []string, env Env) int {
	if env.HTTP == nil {
		env.HTTP = httpx.Client("tunnels/"+env.Version, 10*time.Second)
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
	tok, err := oidcFor(b, env.HTTP).DeviceLogin(ctx, env.Stdout)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	me, err := auth.GetMe(ctx, env.HTTP, base, tok.AccessToken)
	if err != nil { // the service's own sentence, e.g. what to ask an admin for
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	tok.Handle, tok.Server = me.Handle, base
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
	o := oidcFor(b, env.HTTP)
	// Start with a fresh token: the stored one may be hours old, and frp logs in with what the file holds.
	if _, err := auth.RefreshStored(ctx, s, o); err != nil {
		fmt.Fprintf(env.Stderr, "could not refresh your session (%s); run: tunnel login\n", strings.TrimSuffix(err.Error(), "; run: tunnel login"))
		return 1
	}
	caFile, err := tunnel.WriteCABundle(s.Dir)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // ends the refresher with the tunnel
	go auth.KeepFresh(ctx, s, o, 30*time.Minute, func(err error) {
		fmt.Fprintf(env.Stderr, "could not refresh your session, will try again: %v\n", err)
	})

	url := "https://" + names.Label(tok.Handle, *name) + "." + b.SitesDomain
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
			if strings.HasPrefix(msg, "tunnel limit of") {
				msg += " (a tunnel that ended without saying goodbye counts for up to 90 seconds)"
			}
			fmt.Fprintln(env.Stderr, msg)
		}
	}
	err = env.Run(ctx, tunnel.Options{
		ServerHost: b.ServiceHost, ServerPort: 443, Protocol: "wss",
		Handle: tok.Handle, Name: *name, LocalPort: port,
		TokenFile: s.AccessTokenPath(), CAFile: caFile, Version: env.Version,
	}, onStatus)
	if err != nil { // a refused first login: "login to the server failed: <the broker's reason>"
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	return 0
}

func logout(env Env) int {
	s, err := store(env)
	if err == nil {
		err = s.Clear()
	}
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	fmt.Fprintln(env.Stdout, "Logged out")
	return 0
}
