# Agent notes

`docs/design.md` is the source of truth for how the service works; read it first. This file records
the conventions that are easy to get wrong.

## Configuration

- **Every new configuration option must be optional.** It can be left unset, or set to a value that
  disables its feature — a missing option is a valid state, never a startup failure. A release must
  not require new configuration to keep running: with the option unset the service still starts and the
  feature's routes are not mounted, so they answer **404** (see `MachinesEnabled`/`MetricsEnabled` in
  `NewHandler`). The `/api/machines` handlers keep their `noPocketID` 503 guard for the
  section-on-but-no-PocketID case, and `/api/shares` its `noSharesStore` guard.
- **Group an option's inputs.** When several variables configure one feature, either all are set or
  none; a half-set group is a startup error naming the variable. Do not let a partial configuration
  read as "feature off".
- **Secrets come from the environment or a file and never reach a log, an error, or a URL.** The
  broker's own errors name the variable, never its value.
- **A config file (v0.4.0).** The broker's settings come from a TOML config file — `--config PATH`, else
  `BROKER_CONFIG`, else `/etc/tunnels/broker.toml` — one section per feature (`[server]`, `[identity]`,
  `[tunnels]`, `[machines]`, `[metrics]`), and **a feature with no section is off** when a file is
  present (its routes are not mounted, so they answer 404); with **no file** the broker behaves as
  before (`/metrics` served, machines follow `POCKET_ID_URL`). Secrets stay in the environment, never
  the file; the environment overrides a file value. See the [broker config
  design](docs/plans/2026-10-12-tunnels-broker-config-design.md).

## Code

- `./internal/...` stays at **100%** test coverage; the CI gate (`go-test-coverage`) enforces it and
  excludes `cmd/` and the tagged `e2e` package.
- **Fail closed** on our own authorization. The broker is the only machine capability boundary; frps
  admission is plumbing.
- **Never log** a token, a private key, the plugin secret, or a run ID.
- Tests: `go test -race ./...`. Store tests read `TEST_DATABASE_URL` and skip without it. The e2e test
  is behind the `e2e` build tag and runs without `-race` (an upstream frp race).
- Work lands as one PR per task against `mainline`; only the human merges.

## Releasing

See the `releasing-tunnels` skill (`.opencode/skills/releasing-tunnels/`): the tag-driven release flow,
what a release's notes must say, and the homelab deploy order.
