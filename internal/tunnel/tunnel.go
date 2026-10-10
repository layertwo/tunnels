// Package tunnel builds and runs the frp client that publishes one local port.
package tunnel

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/policy/security"
	"github.com/fatedier/frp/pkg/util/log"

	"github.com/layertwo/tunnels/internal/names"
)

// Options describe one tunnel.
type Options struct {
	ServerHost string // tunnels.layertwo.dev
	ServerPort int    // 443
	Protocol   string // "wss" in production; "tcp" against a local frps in tests

	Handle string // what the service said at login
	Name   string // the tunnel name; "" is the default tunnel

	LocalPort int    // the port on 127.0.0.1 to publish
	TokenFile string // the access token; frp reads it again for every login, ping and work connection
	CAFile    string // the roots that verify the server; frp verifies nothing without one

	HeartbeatInterval int // seconds; 0 means 30

	Version string // the CLI's own; the login carries it to the broker, which logs it
}

// Build turns the options into frp's client configuration, loaded and checked the way frpc loads a
// file: as JSON (no escaping of Windows paths), in strict mode, completed and validated.
func Build(o Options) (*v1.ClientCommonConfig, []v1.ProxyConfigurer, error) {
	switch {
	case !names.ValidHandle(o.Handle):
		return nil, nil, errors.New("no valid handle; run: tunnel login")
	case o.Name != "" && !names.ValidTunnelName(o.Name):
		return nil, nil, fmt.Errorf("%q is not a tunnel name: use 1 to 42 lowercase letters, digits and inner dashes, other than %q", o.Name, names.Default)
	case o.LocalPort < 1 || o.LocalPort > 65535:
		return nil, nil, fmt.Errorf("port %d: use a port from 1 to 65535", o.LocalPort)
	case o.TokenFile == "":
		return nil, nil, errors.New("tunnel: no token file")
	case o.Protocol == "wss" && o.CAFile == "":
		return nil, nil, errors.New("tunnel: wss needs a CA file, otherwise frp does not check the server's certificate")
	}
	raw, err := json.Marshal(map[string]any{
		"serverAddr": o.ServerHost,
		"serverPort": o.ServerPort,
		"user":       o.Handle,
		"metadatas":  map[string]string{"tunnel_version": o.Version}, // frp's login reports frp's version, not ours
		"transport": map[string]any{
			"protocol": o.Protocol,
			// with tcpMux on, frp sends no heartbeats unless told to, and then never notices a revoked token
			"heartbeatInterval": cmp.Or(o.HeartbeatInterval, 30),
			"tls":               map[string]any{"trustedCaFile": o.CAFile},
		},
		"auth": map[string]any{
			"method":           "oidc",
			"additionalScopes": []string{"HeartBeats", "NewWorkConns"},
			"oidc":             map[string]any{"tokenSource": map[string]any{"type": "file", "file": map[string]any{"path": o.TokenFile}}},
		},
		"proxies": []any{map[string]any{
			"name": cmp.Or(o.Name, names.Default), "type": "http", "localIP": "127.0.0.1", "localPort": o.LocalPort,
			"subdomain": names.Label(o.Handle, o.Name),
			// frps sets x-forwarded-proto to http for the last hop; the visitor came over https.
			"requestHeaders": map[string]any{"set": map[string]string{"x-forwarded-proto": "https"}},
		}},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("tunnel: %w", err) // coverage-ignore // the map above holds only strings, ints and maps, which always marshal
	}

	var cfg v1.ClientConfig
	if err := config.LoadConfigure(raw, &cfg, true, "json"); err != nil {
		return nil, nil, fmt.Errorf("tunnel: load the frp configuration: %w", err) // coverage-ignore // raw is built here from ClientConfig's own shape, so it always decodes
	}
	if err := cfg.Complete(); err != nil {
		return nil, nil, fmt.Errorf("tunnel: %w", err) // coverage-ignore // the only caller that could fail, AuthClientConfig.Complete, never returns an error
	}
	proxies := make([]v1.ProxyConfigurer, 0, len(cfg.Proxies))
	for _, p := range cfg.Proxies {
		proxies = append(proxies, p.ProxyConfigurer)
	}
	proxies = config.CompleteProxyConfigurers(proxies)
	if _, err := validation.ValidateAllClientConfig(&cfg.ClientCommonConfig, proxies, nil, security.NewUnsafeFeatures(nil)); err != nil {
		return nil, nil, fmt.Errorf("tunnel: %w", err)
	}
	return &cfg.ClientCommonConfig, proxies, nil
}

// Status is the tunnel as frp sees it. Phase is frp's ("wait start", "running", "start error",
// "closed", ...), and Err why a start failed: the service's own sentence when it refused the tunnel.
type Status struct{ Phase, Err string }

var initLog sync.Once

// loginFailExitNote is what frp appends to the reason a first login failed.
const loginFailExitNote = ". With loginFailExit enabled, no additional retries will be attempted"

// Run connects and keeps the tunnel up until ctx ends, reporting every change of its status to
// onStatus (which may be nil). Once the first login has worked frp reconnects by itself; a first
// login that fails ends Run with the reason. Run returns nil when ctx ends.
func Run(ctx context.Context, o Options, onStatus func(Status)) error {
	common, proxies, err := Build(o)
	if err != nil {
		return err
	}
	initLog.Do(func() { log.InitLogger("console", "warn", 1, true) }) // frp's logger is global

	src := source.NewConfigSource()
	if err := src.ReplaceAll(proxies, nil); err != nil {
		return fmt.Errorf("tunnel: %w", err) // coverage-ignore // Build already validated the one proxy's name
	}
	svr, err := client.NewService(client.ServiceOptions{
		Common:                 common,
		ConfigSourceAggregator: source.NewAggregator(src),
		UnsafeFeatures:         security.NewUnsafeFeatures(nil),
	})
	if err != nil {
		return fmt.Errorf("tunnel: %w", err) // coverage-ignore // the config Build returns always passes NewService's checks
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	if onStatus != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			watch(svr.StatusExporter(), proxies[0].GetBaseConfig().Name, onStatus, stop)
		}()
	}
	err = svr.Run(ctx) // returns once ctx ends, or when the first login fails
	close(stop)
	wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return errors.New(strings.TrimSuffix(err.Error(), loginFailExitNote))
	}
	return nil // coverage-ignore // svr.Run returns nil only after ctx is done, which returned just above
}

// watch reports each change of the proxy's status until stop is closed.
func watch(status client.StatusExporter, name string, onStatus func(Status), stop <-chan struct{}) {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	var last Status
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		ws, ok := status.GetProxyStatus(name)
		if !ok {
			continue
		}
		if s := (Status{Phase: ws.Phase, Err: ws.Err}); s != last {
			last = s
			onStatus(s)
		}
	}
}
