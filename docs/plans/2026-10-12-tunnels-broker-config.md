# Tunnels Broker Config File Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the broker a TOML configuration file that is its whole config, where a feature with no section is off.

**Architecture:** A strict TOML decoder produces a `FileConfig` of optional sections (pointer fields, so "absent" is distinct from "empty"). `LoadConfig` merges the file with the environment (the environment wins) into the existing `Config`, applies the feature rules, and validates. `cmd/broker` resolves the path and reads the file; a missing default path is tolerated, a missing explicit path is an error.

**Tech Stack:** Go 1.27; `github.com/pelletier/go-toml/v2` (new dependency — Go's stdlib has no TOML).

**Spec:** `docs/plans/2026-10-12-tunnels-broker-config-design.md` — read it with this plan.

## Global Constraints

- **100% coverage** on `./internal/...`; `cmd/` and the tagged `e2e` package are excluded. Every new branch needs a test or a commented `// coverage-ignore`.
- **A feature with no section, or `enabled = false`, is off.** Not mounted / refused, never a startup failure.
- **Secrets never live in the file** (`DATABASE_URL`, `POCKET_ID_API_KEY`, `FRPS_DASHBOARD_PASSWORD`, `PLUGIN_SECRET`): the file schema has no key for them, and a key that names one is a startup error.
- **The environment overrides a file value**; the environment keeps every secret. An **enabling** environment variable (e.g. `POCKET_ID_URL`) with no section is a startup error; a **secret** never enables a feature.
- **A missing file is not fatal** (a release must not require new configuration); an explicit `--config PATH` that is absent **is** an error.
- Fail closed: a bad file or value is a startup error **naming the key**, never a partial start; never echo a value.
- Existing behaviour and messages are preserved when no file is present.

## Review Focus

1. An absent section must not be mistaken for "present but empty" — the feature is off, and a set enabling env var is then an error, not a silent disable.
2. A secret key accidentally written into the (world-readable, committed) file must be rejected, not ignored.
3. The environment must still win over the file for every setting, and a value must never be echoed in an error.
4. A missing default file must leave today's env-only behaviour identical.
5. A feature that is off must not remove or weaken any other feature's endpoint.

---

### Task 1: parse and strictly validate the TOML file

**Files:** `internal/broker/config_file.go` (new), `internal/broker/config_file_test.go` (new), `go.mod`/`go.sum`

**Interfaces:**
- Produces: `FileConfig` with pointer fields so "absent" ≠ "empty": `Server *serverFile`, `Identity *identityFile`, `Tunnels *tunnelsFile`, `Machines *machinesFile`, `Metrics *metricsFile`; each `*File`'s fields are pointers too (`*string`, `*int`). Section key names from the spec: `[server]` (`listen_addr`, `log_level`), `[identity]` (`issuer`, `api_resource`, `creators_group`, `cli_client_id`, `min_cli_version`, `username_claim`, `groups_claim`), `[tunnels]` (`service_host`, `sites_domain`, `max_tunnels_per_user`, `bandwidth_limit`, `reserved_handles`), `[machines]` (`enabled`, `pocket_id_url`, `pocket_id_api_id`), `[metrics]` (`enabled`).
- Produces: `func ParseFile(data []byte) (*FileConfig, error)`.

- [ ] **Step 1: Write the failing tests.** A full valid file parses into the expected `FileConfig` (each section present, values set); an empty file gives empty sections (all nil); `[machine]` (typo) → an error naming `machine`; `[tunnels] bogus = 1` → an error naming it; `[machines] pocket_id_api_key = "x"` (a secret) → an error naming the key; `[server] database_url = "x"` → the same; malformed TOML → an error.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.** `go get github.com/pelletier/go-toml/v2`. Decode with the library's strict mode so an unknown key or section is an error; keep a set of secret key names (`database_url`, `pocket_id_api_key`, `frps_dashboard_password`, `plugin_secret`) and reject any key in it, anywhere.
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/ -run File`; 100%.
- [ ] **Step 5: Commit.** `feat(broker): parse a strict TOML config file`.

---

### Task 2: merge the file and the environment into `Config`

**Files:** `internal/broker/config.go`, `internal/broker/config_test.go`

**Interfaces:**
- Consumes: `FileConfig`, `ParseFile`.
- Produces: `func LoadConfig(getenv func(string) string, file *FileConfig) (Config, error)` (replaces the current one-argument `LoadConfig`); `Config` gains `MachinesEnabled bool` and `MetricsEnabled bool`, and keeps `PocketIDURL`, `PocketIDAPIKey`, `PocketIDAPIID`.

- [ ] **Step 1: Write the failing tests.** No file → identical to today (the existing tests, updated to pass `nil`); a file with `[server]`/`[identity]`/`[tunnels]` sets the settings; `POCKET_ID_URL` in the env **overrides** the file's `[machines].pocket_id_url`; **no `[machines]` section but `POCKET_ID_URL` set → an error naming both**; **no `[machines]` and only `POCKET_ID_API_KEY`/`POCKET_ID_API_ID` set → no error, machines off** (a secret does not enable); `[machines] enabled = false` with `POCKET_ID_URL` set → machines off, no error; `[machines] enabled = true` with `POCKET_ID_API_KEY` absent → an error naming it; `[metrics]` present → `MetricsEnabled`; absent → false.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.** A `pick(env, filePtr, default)` that prefers the environment, then the file, then the default. The feature rule: a feature is enabled iff its section exists and `enabled != false`; then a set non-secret enabling var with no section is an error, a secret is ignored for enablement, and an enabled feature missing a required input is an error. Keep today's validation and messages.
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/`; 100%.
- [ ] **Step 5: Commit.** `feat(broker): merge the config file with the environment`.

---

### Task 3: mount a feature's routes only when it is on

**Files:** `internal/broker/server.go`, `internal/broker/machines.go`, `internal/broker/server_test.go`, `internal/broker/machines_test.go`

**Interfaces:**
- Consumes: `Config.MachinesEnabled`, `Config.MetricsEnabled`.
- Produces: `NewHandler` mounts `/api/machines*` only when `MachinesEnabled`, and `GET /metrics` only when `MetricsEnabled`; an unmounted route is a 404. The machine handlers keep the `noPocketID` 503 guard (reachable when the section is on but `Deps.PocketID` is nil).

- [ ] **Step 1: Write the failing tests.** `MachinesEnabled=false` → `POST /api/machines` and `DELETE /api/machines/x` are 404; `MetricsEnabled=false` → `GET /metrics` is 404; `MetricsEnabled=true` → 200; `MachinesEnabled=true` with a nil `PocketID` → 503 `noPocketID`; a user site and `/api/shares` are unaffected by either flag.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.** Guard the four `mux.HandleFunc` machine routes and the metrics route on the config flags.
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/`; 100%.
- [ ] **Step 5: Commit.** `feat(broker): mount a feature's routes only when it is on`.

---

### Task 4: `cmd/broker` reads the file

**Files:** `cmd/broker/main.go`

**Interfaces:** consumes `ParseFile`, `LoadConfig`.

- [ ] **Step 1: Implement.** Add a `--config PATH` flag; the path is the flag, else `BROKER_CONFIG`, else `/etc/tunnels/broker.toml`. Read it: a missing file is tolerated **only** at the default path (and leaves `file` nil); an explicit path that is missing, or any read error, is fatal. Parse with `ParseFile` and call `LoadConfig(os.Getenv, file)`.
- [ ] **Step 2: Build + smoke.** `go build ./...`; `go run ./cmd/broker --config /nonexistent` exits with an error naming the path; with no `--config` and no default file it starts as today (env-only).
- [ ] **Step 3: Commit.** `feat(broker): read the configuration file at startup`.

---

### Task 5: docs and the homelab

**Files:** `README.md`, `docs/design.md`; and `/Users/lucas/homelab` (out of this repo)

- [ ] **Step 1: Docs.** `README.md`: document `--config`/`BROKER_CONFIG`, the sections, and that an absent feature section is off. `docs/design.md`: point the configuration section at the design.
- [ ] **Step 2: Homelab.** A `ConfigMap` with `broker.toml` (the `[server]`/`[identity]`/`[tunnels]` sections, `[machines]`/`[metrics]` as wanted), mounted into the broker; the HelmRelease's plain `env` shrinks to the secrets (`envFrom` unchanged). Ship it with the release, per `releasing-tunnels` — no required new config: the file is additive.
- [ ] **Step 3: Verify.** `go test -race ./...`, the coverage gate at 100%, and `go test -tags e2e ./e2e/`; then the homelab PR and the reconcile.
- [ ] **Step 4: Commit.** `docs: record the broker configuration file`.

---

## Self-Review

- **Spec coverage:** the file + strict decoding (T1); file/env precedence + the feature rules (T2); absent = off at the endpoints (T3); the path + missing-file policy (T4); docs + homelab (T5). Every "Resolved from the builder check" line has a task.
- **Type consistency:** `FileConfig`/`ParseFile` (T1) feed `LoadConfig` (T2); `MachinesEnabled`/`MetricsEnabled` (T2) drive `NewHandler` (T3); `ParseFile`/`LoadConfig` (T4) are the ones T1/T2 defined.
- **Review Focus:** each of the five lines is pinned by a named test in T1–T3.
- **Proportion:** five tasks for a config layer, its feature-gating, the wiring and the deploy; no task transcribes a body it does not have to.

## Left to the builder

- The exact TOML tags and the pointer/absent representation.
- The precise `pick` and feature-rule error wording.
- The default path and flag shape.
