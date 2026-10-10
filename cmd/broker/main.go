// Command broker is the tunnel service's brain: the frps plugin, the access decision behind /authz,
// and the small API and bootstrap document the CLI uses. Settings come from the environment.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/layertwo/tunnels/internal/broker"
	"github.com/layertwo/tunnels/internal/frpsapi"
	"github.com/layertwo/tunnels/internal/idp"
	"github.com/layertwo/tunnels/internal/store"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

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
	cfg, err := broker.LoadConfig(os.Getenv)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	userAgent := "tunnels/" + version
	users, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer users.Close()
	provider, err := idp.New(ctx, cfg.Issuer, cfg.APIResource, userAgent, cfg.UsernameClaim, cfg.GroupsClaim)
	if err != nil {
		return err
	}
	frps := frpsapi.New(cfg.FrpsDashboardURL, cfg.FrpsDashboardUser, cfg.FrpsDashboardPassword, userAgent)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           broker.NewHandler(cfg, broker.Deps{IdP: provider, Verifier: provider, Users: users, Shares: users, Frps: frps, Log: log}),
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
