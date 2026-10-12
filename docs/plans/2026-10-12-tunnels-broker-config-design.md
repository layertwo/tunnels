# Tunnels Broker Configuration - Design

> Companion to `docs/design.md`. The broker's settings are today a flat set of environment
> variables; this document replaces them with **a configuration file that is the broker's whole
> config**, where **a feature with no section is off**. It is the working design; a plan follows
> once it is approved.

## Intent and why

The broker's config is ~15 environment variables with no grouping and no way to say "this feature is
off". As features accrue — machines, metrics, later SSH — each needs switches and settings, and the
admin has no single place to see or change them. A missing variable cannot mean "disabled": v0.3.0
made `POCKET_ID_*` **required**, so a deploy that did not want machines could not start the broker.
That is the failure this design removes.

We want a **configuration file** the admin reads and edits: one section per feature, settings beside
each other, and **absence means off**. The file is the whole broker config; the environment keeps the
secrets and can override a value.

## Goals

- One file holds the broker's whole config — the server, its limits, and each feature.
- **A feature with no section, or `enabled = false`, is off.** The broker starts; that feature's routes
  are not mounted, so they answer **404** (its handlers keep the `noPocketID` 503 for a section that is
  on but has no Pocket ID client).
- **No secret in the file.** The database URL, the Pocket ID API key, the frps dashboard password and
  the plugin secret come from the environment (a mounted Secret).
- The environment **overrides** a file value, so containers and per-environment deploys work.
- A setting keeps its current environment-variable name, so migration is a move, not a rename.

## Non-goals

- A command-line flag for every setting. One `--config PATH` flag (and a `BROKER_CONFIG` env) chooses
  the file; per-setting flags are later.
- Hot reload; a restart applies a change.
- Per-user or per-machine config.

## Anti-goals

- **Two sources of truth.** A setting that lives in both the file and env with no rule is the problem
  we are removing; the precedence is explicit and one-directional.
- **A secret in the file.** It is world-readable and versioned in git.
- **A feature that cannot be turned off.**

## Constraints

- Fail closed: a malformed file or a bad value is a **startup error naming the key**, never a partial
  start. `AGENTS.md` still holds — an option must be optional.
- 100% test coverage on `./internal/...`; no secret in an error or a log.
- **TOML**, matching `frps.toml`, so an operator reads one syntax. This adds one dependency
  (`github.com/pelletier/go-toml/v2`); Go's standard library has no TOML or YAML.

## The file

- **Path:** `--config PATH`, else `BROKER_CONFIG`, else `/etc/tunnels/broker.toml`.
- **Sections.** `[server]` and `[identity]` are the plumbing; `[tunnels]` is the service itself
  (always on); `[machines]` and `[metrics]` are switchable features; `[ssh]` joins them when it lands.
- **Shape** (illustrative; the builder finalizes names):

  ```toml
  [server]                     # the process
  listen_addr = ":8080"
  log_level   = "info"
  # the database URL, the frps dashboard credentials and the plugin secret come from the environment

  [identity]                   # the Pocket ID issuer and the API the CLI logs in against
  issuer          = "https://idp.layertwo.dev"
  api_resource    = "https://tunnels.layertwo.dev"
  creators_group  = "tunnels-creators"
  cli_client_id   = "..."
  min_cli_version = "0.1.0"

  [tunnels]                    # the tunnel service itself; always on
  service_host         = "tunnels.layertwo.dev"
  sites_domain         = "w.tunnels.layertwo.dev"
  max_tunnels_per_user = 5
  bandwidth_limit      = "10MB"
  reserved_handles     = ["admin", "root", "support", "security"]

  [machines]                   # absent ⇒ machines off
  enabled          = true
  pocket_id_url    = "https://idp.layertwo.dev"
  pocket_id_api_id = "..."

  [metrics]                    # absent ⇒ no /metrics
  enabled = true
  ```

- **Absence is off.** No `[machines]` section, or `enabled = false`, means the machine routes are not
  mounted (404). A disabled section's other keys are ignored.
- **Secrets are not in the file:** `DATABASE_URL`, `POCKET_ID_API_KEY`, `FRPS_DASHBOARD_PASSWORD`,
  `PLUGIN_SECRET` come from the environment. The file schema has no key for them.
- **Precedence:** for each setting, an environment variable of the current name overrides the file
  value; else the file's value; else the built-in default. An **enabling** environment variable
  (`POCKET_ID_URL`, say) with **no section** is a startup error naming both, so a half-migrated config
  is loud, not a silent surprise.

## Flows

**Start-up.** Read the path; parse (a malformed file is an error naming the file and the key); merge
the environment overrides; validate as today; build `Config`. A feature whose section is absent leaves
its dependency `nil` (as `Deps.PocketID` is today when unset).

**A feature off.** Its routes are not mounted, so they answer **404**; the rest of the broker serves
normally. (The machine handlers keep the `noPocketID` 503 for a section that is on but has no Pocket ID
client.)

**Migration.** The homelab's non-secret settings move into a mounted `broker.toml`; the sops Secret
keeps the four secret values. This is one deploy with the release, and the ordering is the usual one.

## Repo changes

| Area | Change |
|------|--------|
| `internal/broker/config.go` | a file loader (TOML) + env override + per-feature structs; the "absent is off" rule |
| `cmd/broker` | read `--config`/`BROKER_CONFIG`, pass the path to the loader |
| `go.mod` | one TOML dependency |
| `AGENTS.md` | the rule already there; add "a feature section absent means the feature is off" |

## Infra changes (homelab)

- A `ConfigMap` holding `broker.toml`, mounted read-only into the broker; the HelmRelease's plain
  `env` shrinks to nothing, and `envFrom` keeps only the sops Secret.
- The `[machines]` and `[metrics]` sections are simply absent until they are wanted.

## Security

- The file carries no secret, so it may be world-readable and committed. Errors name keys, never
  values. The environment remains the only place a secret lives.

## Deferred

- Per-setting command-line flags (overrides).
- A structured `[database]` section (host, name, user) with only the password in the environment,
  instead of the whole `DATABASE_URL` in a secret — nicer, a larger change.
- Hot reload.

## Sections (settled)

`[server]` and `[identity]` are the plumbing (always needed); `[tunnels]` is the tunnel service
(always on); `[machines]` and `[metrics]` are switchable — absent means off; `[ssh]` joins them when it
lands. Everything with a switch gets a section; everything without one is a plain setting.

## Resolved from the builder check (my calls — check these)

- **A missing file is not fatal.** If the resolved path has no file, the broker runs from the
  environment and built-in defaults, exactly as today — a release must not require new configuration
  to keep running (`AGENTS.md`). An explicit `--config PATH` that does not exist **is** an error.
- **The "an env var with no section is an error" rule covers only a feature's *enabling* variables**
  (non-secret ones such as `POCKET_ID_URL`). The core settings (`SERVICE_HOST`, `ISSUER`, …) may live in
  the environment with no section; the file overrides them when present. So a deploy can migrate
  piecemeal.
- **A secret never enables a feature, and `enabled = false` always wins.** A secret mounted with the
  environment (`POCKET_ID_API_KEY`) does not count as enabling — otherwise machines could not be
  turned off without also editing the secret, which is the anti-goal. `[machines] enabled = false`
  with the enabling variables still set means *off*.
- **An enabled feature missing a required input is a startup error** naming the missing environment
  variable — the "grouped, half-set is an error" rule, now spanning file and environment.
- **Decoding is strict.** An unknown key or section (a typo like `[machine]`), or a key that names a
  secret (`pocket_id_api_key`, `database_url`), is a startup error — so a typo cannot silently turn a
  feature off, and a secret cannot quietly sit in a world-readable, committed file.

## Left to the builder

- The exact section and key names, and the TOML library.
- The precise precedence and half-migrated-config error wording.
