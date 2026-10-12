// Command broker is the tunnel service's brain: the frps plugin, the access decision behind /authz,
// and the small API and bootstrap document the CLI uses. Settings come from the environment and,
// when one is present, a configuration file.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/layertwo/tunnels/internal/broker"
	"github.com/layertwo/tunnels/internal/frpsapi"
	"github.com/layertwo/tunnels/internal/httpx"
	"github.com/layertwo/tunnels/internal/idp"
	"github.com/layertwo/tunnels/internal/pocketid"
	"github.com/layertwo/tunnels/internal/store"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// defaultConfigPath is used when neither --config nor BROKER_CONFIG names a file. A missing file here is
// not fatal — the broker runs from the environment alone, as before the file existed.
const defaultConfigPath = "/etc/tunnels/broker.toml"

// readConfig resolves the configuration file's path (--config, else BROKER_CONFIG, else the default),
// reads and parses it. Only the default path may be absent; an explicit path must exist, and any
// read or parse error is fatal. Errors name the path, never a value.
func readConfig() (*broker.FileConfig, error) {
	path := flag.String("config", os.Getenv("BROKER_CONFIG"), "broker configuration file, else $BROKER_CONFIG, else "+defaultConfigPath)
	flag.Parse()
	explicit := *path != ""
	if !explicit {
		*path = defaultConfigPath
	}

	data, err := os.ReadFile(*path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !explicit {
			return nil, nil
		}
		return nil, fmt.Errorf("config %s: %w", *path, err)
	}
	file, err := broker.ParseFile(data)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", *path, err)
	}
	return file, nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version)
		return
	}
	// JSON from the first line, so a refused start is as easy to read in the log collector as the rest.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("broker stopped", "err", err)
		os.Exit(1)
	}
}

func run() error {
	file, err := readConfig()
	if err != nil {
		return err
	}
	cfg, err := broker.LoadConfig(os.Getenv, file)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	userAgent := "tunnels/" + version
	users, err := store.OpenRetry(ctx, cfg.DatabaseURL, 2*time.Minute)
	if err != nil {
		return err
	}
	defer users.Close()
	provider, err := idp.New(ctx, cfg.Issuer, cfg.APIResource, userAgent, cfg.UsernameClaim, cfg.GroupsClaim)
	if err != nil {
		return err
	}
	frps := frpsapi.New(cfg.FrpsDashboardURL, cfg.FrpsDashboardUser, cfg.FrpsDashboardPassword, userAgent)
	// Machines are optional: with no admin config the broker still serves people, and with the
	// feature off the machine routes are not mounted, so they answer 404.
	var pocket broker.PocketID
	if cfg.PocketIDURL != "" {
		pocket = pocketid.New(cfg.PocketIDURL, cfg.PocketIDAPIKey, httpx.Client(userAgent, 10*time.Second))
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           broker.NewHandler(cfg, broker.Deps{IdP: provider, Verifier: provider, Users: users, Machines: users, PocketID: pocket, Shares: users, Frps: frps, Log: log}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second, // a plugin body or a bearer token is small
		WriteTimeout:      30 * time.Second, // longer than the 8 s a decision may take
		IdleTimeout:       60 * time.Second, // otherwise a finished keep-alive connection stays for ever
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Info("broker listening", "addr", cfg.ListenAddr, "version", version)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
