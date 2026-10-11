# Tunnels v0.3.0 Additions Implementation Plan: metrics and machine clients

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add broker Prometheus metrics (with `/authz` phase timers) and machine clients (headless publishers via Pocket ID `client_credentials`).

**Architecture:** A broker metrics package wired as HTTP middleware plus `/metrics`; and a resolver branch that recognises a `client-…` subject and maps its client id to a handle from config, with the CLI gaining a machine login and a client-credentials token path.

**Tech Stack:** Go 1.27, `github.com/prometheus/client_golang` (already indirect), `golang.org/x/oauth2/clientcredentials`.

**Spec:** `docs/design.md` — the "Machine clients" simplification and the "Broker `/metrics`" observability note.

## Global Constraints

- **The 100% coverage gate is live:** every `./internal/...` package must stay at 100.0% (`go-test-coverage --config=.testcoverage.yml`). New lines need tests, or a commented `// coverage-ignore` for a provably unreachable line.
- **Metric labels are bounded and secret-free.** Never label with the raw path (the plugin path holds the secret), the `Host`, or any identity. The route label is a fixed classifier; the method and status are bounded.
- The default tunnel is `''`; `names.Default` never appears as a stored tunnel.
- **A machine client acts as a configured handle.** The broker maps `client_id` → handle from config, requires a `users` row for that handle to exist (created by that person's login), and never derives a handle from the machine token's own claims. Secrets are never logged; token files are 0600.
- Fail closed on an unknown/disabled/misconfigured machine client; fail open only where frps re-verifies (a hook).
- Tests: `go test -race ./...`; Postgres tests read `TEST_DATABASE_URL` and skip when unset; the e2e test is tagged.

## Review Focus

1. Metric cardinality and secrecy: no label can carry the plugin secret, a host, or a user; the series count stays small.
2. The machine branch cannot grant an arbitrary handle: only a `client_id` present in config, mapping to an existing, enabled user.
3. The client secret never reaches a log, an error, or the wire; the token file stays 0600.
4. Every package stays at 100% under the gate.

---

### Task 1: Broker metrics and `/authz` phase timers

**Files:** `internal/broker/metrics.go` (new), `internal/broker/metrics_test.go` (new), `internal/broker/server.go`, `internal/broker/server_test.go`, `internal/broker/authz.go`, `internal/broker/authz_test.go`, `go.mod`/`go.sum`

**Interfaces:** produces `NewMetrics() *Metrics`, `(*Metrics).Middleware(http.Handler) http.Handler`, `(*Metrics).Handler() http.Handler`, `(*Metrics).ObserveLookup(phase string, d time.Duration)`; `Authz.Metrics *Metrics`; `GET /metrics` serving the registry.

- [ ] **Step 1: Write the failing tests.** `TestRouteOf` (table: `/plugin/abc` → `/plugin/`, `/authz`, `/api/me`, `/api/shares`, `/.well-known/tunnels.json`, `/healthz`, `/metrics`, `/nope` → `other`; a `/plugin/<secret>` never appears as a label). `TestMiddlewareRecords` (a request through the wrapped mux increments the route/method/status series; the response body and status are unchanged). `TestMetricsEndpoint` (GET `/metrics` → 200, `text/plain`, contains `tunnels_http_requests_total`). `TestAuthzObservesPhases` (an `/authz` decision records the `owner` and, for a stranger, the `shares` phase in `ObserveLookup`; a fake `Metrics` recorder captures the phases and durations).
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.** `NewMetrics` builds a **private** `prometheus.NewRegistry()` and registers: `tunnels_http_requests_total{route,method,status}` counter, `tunnels_http_request_duration_seconds{route,method,status}` histogram, `tunnels_http_in_flight` gauge, `tunnels_authz_lookup_duration_seconds{phase}` histogram. `Middleware` wraps the writer to capture the status and times the request; `routeOf` classifies the path. `Handler` returns `promhttp.HandlerFor(reg, ...)`. In `NewHandler`, build `NewMetrics()`, mount `GET /metrics`, and wrap the mux with the middleware; set `Authz.Metrics` and, when non-nil, time `UserByHandle` (`phase="owner"`) and `ShareMatches` (`phase="shares"`). `go get github.com/prometheus/client_golang && go mod tidy`.
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/ -v`; confirm 100%.
- [ ] **Step 5: Commit.** `feat(broker): expose request and authz metrics`.

---

### Task 2: Machine clients in the broker

**Files:** `internal/broker/config.go`, `internal/broker/config_test.go`, `internal/broker/account.go`, `internal/broker/account_test.go`, `cmd/broker/main.go`

**Interfaces:** `Config.MachineClients map[string]string` (env `MACHINE_CLIENTS`, `id=handle,…`, optional); `Resolver.MachineClients map[string]string`; a `client-<id>` subject resolves to the configured handle's account; new sentinel `ErrUnknownMachine`.

- [ ] **Step 1: Write the failing tests.** config: `TestLoadConfigMachineClients` (parses `id1=alice,id2=box` to a map; trims; an empty value → `nil`; a malformed pair with no `=` → an error naming `MACHINE_CLIENTS`). account: `TestResolveMachineClient` (sub `client-abc` configured to `alice`, an existing enabled `alice` → account handle `alice`; **userinfo is not called**); `TestResolveMachineUnknownClient` (`client-zzz` not in config → `ErrUnknownMachine`); `TestResolveMachineUnknownHandle` (maps to a handle with no user row → refusal); `TestResolveMachineDisabled` (disabled user → `ErrDisabled`); and that a normal `sub` still goes through userinfo.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.** `LoadConfig` parses `MACHINE_CLIENTS` into a map (bad input → error). `Resolve`: after `VerifyAccessToken` returns `sub`, if `id, ok := strings.CutPrefix(sub, "client-"); ok` — map `id` through `r.MachineClients`; unknown → `refusal{ErrUnknownMachine, "this machine client is not configured; ask an admin"}`; else `UserByHandle(handle)` (not found → refusal; error → infra; disabled → `ErrDisabled`) and return `Account{Sub: u.Sub, Handle: u.Handle}` **without** userinfo or the creators-group check. `cmd/broker/main.go` passes `cfg.MachineClients` into the resolver via `Deps` (add the field).
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/ -v`; 100%.
- [ ] **Step 5: Commit.** `feat(broker): let a configured machine client publish as a handle`.

---

### Task 3: CLI machine login and client-credentials refresh

**Files:** `internal/auth/auth.go`, `internal/auth/store.go`, `internal/auth/auth_test.go`, `internal/auth/store_test.go`, `internal/cli/cli.go`, `internal/cli/cli_test.go`

**Interfaces:** `Tokens` gains `ClientID, ClientSecret string` (json); `OIDC.ClientCredentials(ctx, clientID, clientSecret string) (Tokens, error)`; `RefreshStored`/`KeepFresh` use client credentials when there is no refresh token; CLI `tunnel login --machine CLIENT_ID` (secret from `TUNNELS_CLIENT_SECRET`).

- [ ] **Step 1: Write the failing tests.** auth: `TestClientCredentials` (against `mockidp`'s `client_credentials` endpoint → an access token; no refresh token; the request carries `client_id`, `client_secret`, `grant_type=client_credentials`, `resource`). `TestRefreshStoredClientCredentials` (no refresh token + a client id/secret → a new access token, files updated, secret preserved). store: `TestSaveLoadClientCredentials` (round-trips `ClientID`/`ClientSecret`; 0600). cli: `TestLoginMachine` (`login --machine abc` with `TUNNELS_CLIENT_SECRET` set → stores a machine login, prints the handle from `/api/me`); `TestLoginMachineNeedsASecret` (missing env → error); `TestMachineLoginNeverPrintsTheSecret` (the secret is absent from stdout/stderr).
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.** `ClientCredentials` uses `golang.org/x/oauth2/clientcredentials` (with `resource` in `EndpointParams`) against the discovered token endpoint. `RefreshStored`/`KeepFresh`: if `t.RefreshToken == ""` and `t.ClientID != ""` → `ClientCredentials(t.ClientID, t.ClientSecret)` and save; else the existing refresh. `cli.login` with `--machine CLIENT_ID`: read `TUNNELS_CLIENT_SECRET` (missing → error, never a flag), `ClientCredentials`, `GetMe`, `Save`; never print the secret.
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/auth/ ./internal/cli/ -v`; 100%.
- [ ] **Step 5: Commit.** `feat(cli): log in as a machine client`.

---

### Task 4: Enable it in the homelab

Out of this repo: `layertwo/homelab` and Pocket ID.

- [ ] **Step 1:** Prometheus scrapes the broker's `GET /metrics` (a scrape config), and the NetworkPolicy allows Prometheus → broker `:8080`.
- [ ] **Step 2:** Create a Pocket ID confidential client (client access to the `Tunnels` API) and set `MACHINE_CLIENTS=<client id>=<handle>` on the broker.
- [ ] **Step 3:** Verify a `tunnel login --machine` publishes a site under the handle, and that the site is owner-authorized as that handle.

---

### Task 5: Docs

**Files:** `README.md`, `docs/design.md`

- [ ] **Step 1:** Document `tunnel login --machine CLIENT_ID` (secret from `TUNNELS_CLIENT_SECRET`) and the `MACHINE_CLIENTS` broker variable; note `/metrics` and what it exposes.
- [ ] **Step 2:** Update the machine-clients and metrics entries in the design.
- [ ] **Step 3: Commit.** `docs: record metrics and machine clients`.

---

## Self-Review

- **Spec coverage:** metrics + `/authz` phase timers (Task 1); machine clients in the broker (Task 2, enabled in Task 4); the CLI login/refresh (Task 3); docs (Task 5).
- **Type consistency:** `NewMetrics`/`Middleware`/`Handler`/`ObserveLookup`; `Config.MachineClients` ↔ `Resolver.MachineClients`; `Tokens.ClientID/ClientSecret`; `OIDC.ClientCredentials`.
- **Review Focus:** each line names its owning test (metrics labels in Task 1; the machine handle grant in Task 2; the secret in Task 3; the gate everywhere).
- **Proportion:** five tasks for two medium features plus a deploy step and docs; no bodies transcribed.
