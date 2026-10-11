# Tunnels Machines Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace v0.3.0's per-machine Pocket ID client plus `MACHINE_CLIENTS` env map with broker-owned machine principals whose credential is a machine-held key pair.

**Architecture:** A `machines` table holds the principal (handle, owner, Pocket ID client id). The broker mints a Pocket ID client per machine and registers the machine's **public key** as a federated client credential; the machine signs a `client_assertion` to get a token whose subject is `client-<id>`. The broker resolves that subject to the machine in Login, Ping and NewWorkConn, sets the tunnel's user to the machine's handle, and authorizes visitors like any site (shares keyed by the site).

**Tech Stack:** Go 1.27; `github.com/go-jose/go-jose/v4` (already a dependency, via mockidp) for the key pair and the `client_assertion` JWT; `golang.org/x/oauth2` for the token exchange; Postgres (pgx) with the existing migration mechanism.

**Spec:** `docs/plans/2026-10-11-tunnels-machines-design.md` — read it with this plan.

## Global Constraints

- **The 100% coverage gate is live:** every `./internal/...` package stays at 100.0% (`go-test-coverage --config=.testcoverage.yml`). New branches need tests or a commented `// coverage-ignore`.
- **Fail closed on our own authorization; the broker is the only machine capability boundary.** frps admission is plumbing.
- **The machine token's subject is the machine's own client** (`client-<client id>`); a shared subject is forbidden (it drops the work-connection binding).
- **A machine's handle shares one namespace with people** — validation, the reserved list, and uniqueness across both.
- **No secret is stored for a machine:** the CLI generates an ES256 key pair and keeps the private key in a 0600 file (hardware keystores are deferred); only the public JWK leaves the machine.
- **Tokens and private keys are never logged.**
- Tests: `go test -race ./...`; store tests read `TEST_DATABASE_URL` (podman `tunnels-pg`) and skip when unset; the e2e test is tagged `e2e`.
- The default tunnel is `''` (`names.Default`); it never appears as a stored tunnel.
- Pocket ID's client API is `POST /api/oidc/clients` with `credentials.federatedIdentities[{issuer, audience, publicKeys:[jwk], replayProtection:true}]`; API access is granted per client.

## Review Focus

1. **A machine's private key never leaves the machine, and the broker only ever stores a public JWK.** A leak of the broker's DB or its Pocket ID API key must not yield a working machine credential.
2. **Handle uniqueness across people and machines is race-free** — a machine cannot take a handle a person is creating at the same instant, or vice versa.
3. **A share admits exactly one site** — sharing `blog` must never admit `nas-blog`.
4. **A machine resolves to exactly one handle** — a machine token cannot claim a different handle; a disabled or deleted machine is refused at Login and within one heartbeat at Ping.
5. **The work-connection binding holds for machines** — a work connection whose subject is not the control's machine is refused.
6. **Bootstrap is atomic** — a Pocket ID client created before a store failure (or vice versa) does not leave an orphan.

---

### Task 1: `machines` in the store

**Files:** `internal/store/store.go`, `internal/store/migrations/*.sql` (new up/down), `internal/store/store_test.go`

**Interfaces:**
- Produces: `type Machine struct { ID, Handle, OwnerKind, OwnerRef, ClientID string; Disabled bool; CreatedAt time.Time; CreatedBy string }`; `(*Store).CreateMachine(ctx, Machine) error`, `MachineByHandle(ctx, string) (Machine, error)`, `MachineByClientID(ctx, string) (Machine, error)`, `MachinesByOwner(ctx, string) ([]Machine, error)`, `SetMachineDisabled(ctx, clientID string, disabled bool) error`, `DeleteMachine(ctx, clientID string) error`.

- [ ] **Step 1: Write the failing tests.** A migration created the table; `CreateMachine` round-trips (a `MachineByHandle`/`MachineByClientID` return it); a second `CreateMachine` with the same handle errors; **a handle already owned by a `users` row is refused** (insert a user, then create a machine with that handle); concurrently creating a machine and a user with the same handle leaves exactly one owner (a `-race` test with two goroutines, asserting one gets `ErrHandleTaken`); `DeleteMachine` removes it; `SetMachineDisabled` flips the flag; `MachinesByOwner` lists the owner's machines.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.** Migration: `machines(id uuid pk default gen_random_uuid(), handle text not null, owner_kind text not null, owner_ref text not null, client_id text not null unique, disabled boolean not null default false, created_at timestamptz not null default now(), created_by text not null)`; a unique index on `handle`. `CreateMachine` runs in one transaction: `select pg_advisory_xact_lock(hashtext($handle))`, then `select 1 from users where handle = $handle` and `select 1 from machines where handle = $handle`; any hit ⇒ `ErrHandleTaken`; else insert. A new `ErrHandleTaken` sentinel. Add `handle` to the store's user-create path so a machine and a user cannot both claim a handle (the same advisory lock).
- [ ] **Step 4: Run them to verify they pass.** `TEST_DATABASE_URL=… go test -race ./internal/store/ -v`; 100%.
- [ ] **Step 5: Commit.** `feat(store): add machine principals`.

---

### Task 2: shares keyed by the site

**Files:** `internal/store/store.go`, `internal/store/migrations/*.sql`, `internal/store/store_test.go`, `internal/auth/shares.go` (or wherever the CLI wraps shares), `internal/cli/cli.go`, `internal/cli/cli_test.go`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `Share` gains `Handle string`; `PutShare`, `DeleteShare`, `SharesByOwner` carry it; `ShareMatches(ctx, ownerSub, handle, tunnel, username string, groups []string)` (new `handle` parameter).
- Changes: the migration adds `shares.handle`, backfills it from the owner's `users.handle` (label `handle` for the default tunnel), and makes it `NOT NULL`.

- [ ] **Step 1: Write the failing tests.** `ShareMatches` requires the handle: a share stored with `Handle="alice", Tunnel="blog"` matches for `(alice, alice, blog)` and **does not** match for `(alice, nas, blog)`; `SharesByOwner` returns the handle; the migration backfills an existing row's handle from `users` (seed a user + a share without a handle, run migrations, read it back).
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.** Migration (up: add column, `UPDATE shares SET handle = ...`, set `NOT NULL`; down: drop). Thread `handle` through the four store methods and their SQL. Update the CLI's `share`/`unshare`/`list` to pass the site's handle — `share <label> <grantee>` where `<label>` is `<handle>` or `<handle>-<name>` (`names.ParseLabel`); `list` shows the label.
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/store/ ./internal/cli/ -v`; 100%.
- [ ] **Step 5: Commit.** `feat(store): key shares by the site`.

---

### Task 3: the resolver learns machines

**Files:** `internal/broker/account.go`, `internal/broker/hooks.go`, `internal/broker/config.go`, `internal/broker/server.go`, `cmd/broker/main.go`, and their `_test.go`

**Interfaces:**
- Consumes: `store.Machine`, `(*Store).MachineByClientID`.
- Produces: `Resolver.Machines MachineStore` (interface `{ MachineByClientID(ctx, string) (store.Machine, error) }`); `(*Resolver).AccountBySubject(ctx, sub string) (Account, error)` — `client-<id>` → `MachineByClientID` → `Account{Handle: m.Handle}` (disabled ⇒ `ErrDisabled`, not found ⇒ `ErrUnknownMachine`); otherwise `UserBySub` → `Account{Sub, Handle}`. `Resolve` verifies the token then calls `AccountBySubject` for the machine branch and the existing userinfo path for a person.
- Removes: `Resolver.MachineClients`, `Config.MachineClients`, `Deps.MachineClients`, the `MACHINE_CLIENTS` parse.

- [ ] **Step 1: Write the failing tests.** `AccountBySubject("client-abc")` with a store holding that client → the machine's handle; unknown client → `ErrUnknownMachine`; disabled → `ErrDisabled`; a user sub → the user's handle; `Resolve` a machine token → the machine's handle, **no userinfo call**; and the **NewWorkConn** hook: a work connection whose token subject is a machine that is **not** the control's handle → rejected (`AccountBySubject` + handle compare), and the same subject as the control → allowed. `MACHINE_CLIENTS` no longer parses.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.** Add `AccountBySubject`; wire `Resolver.Machines` from a `Deps.Machines` (or read `cfg` — one source of truth, not two); use it in `Resolve` and replace the `UserBySub` lookup in `newWorkConn` with `AccountBySubject`. Delete `MACHINE_CLIENTS` parsing and config. `cmd/broker/main.go` passes the store as `Machines`.
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/ -v`; 100%.
- [ ] **Step 5: Commit.** `feat(broker): resolve machine subjects in login and work connections`.

---

### Task 4: `/authz` resolves machine sites

**Files:** `internal/broker/authz.go`, `internal/broker/authz_test.go`, `internal/broker/server.go`

**Interfaces:**
- Consumes: `MachineByHandle`, `ShareMatches(ctx, ownerSub, handle, tunnel, …)`.
- Produces: `Authz` resolves the site's owner across `users` and `machines`: a user handle → that `users` row; a machine handle → owner `owner_ref` (a `users` row via `UserBySub`), so the owner check is `owner.Ref == visitor.sub` and the share check is `ShareMatches(owner_ref, handle, tunnel, …)`.

- [ ] **Step 1: Write the failing tests.** A machine site (`nas-blog`): the machine's owner (`owner_ref`) is allowed; a stranger is refused; a share keyed by `(owner_ref, nas, blog)` admits the grantee, and a share keyed by `(owner_ref, alice, blog)` does **not** (invariant 10); a disabled owner or machine is refused; a machine handle with no machine row is `unknown_owner`.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.** In `decide`, replace `Users.UserByHandle(handle)` with a helper that returns the site's owner (`{ref, disabled}`) from either table; pass `handle` (from `ParseLabel`) to `ShareMatches`. Keep the cross-owner Origin check keyed on the handle.
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/ -v`; 100%.
- [ ] **Step 5: Commit.** `feat(broker): authorize machine sites`.

---

### Task 5: mint a Pocket ID client with the machine's public key

**Files:** `internal/pocketid/pocketid.go` (new), `internal/pocketid/pocketid_test.go` (new), `internal/broker/machines.go` (new), `internal/broker/machines_test.go` (new), `internal/broker/server.go`, `internal/broker/config.go`, `cmd/broker/main.go`

**Interfaces:**
- Consumes: `store.CreateMachine`, `store.DeleteMachine`.
- Produces: `pocketid.Client` with `New(baseURL, apiKey string, hc *http.Client) *Client` and `CreateClient(ctx, name, issuer, audience string, publicKey json.RawMessage, apiID string) (clientID string, err error)`, `DeleteClient(ctx, clientID string) error`; broker `POST /api/machines` `{handle, publicKey}` → `{handle, clientId}`, `GET /api/machines` → the caller's machines, `DELETE /api/machines/{handle}`.

- [ ] **Step 1: Write the failing tests.** `pocketid.CreateClient` posts `{name, isPublic:false, credentials:{federatedIdentities:[{issuer, audience, publicKeys:[jwk], replayProtection:true}]}}`, reads the created client id, then grants the client access to `apiID`; a non-2xx is an error not a panic; `DeleteClient` deletes. Broker: `POST /api/machines` (authenticated as its owner) validates the handle, calls `CreateClient`, stores the machine, returns the client id; **a Pocket ID failure rolls back** (no machine row); a duplicate handle → the handle error; `DELETE` removes the row then the client; the endpoints refuse a machine subject.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.** `pocketid.Client` with `X-API-KEY`; config `PocketIDURL`, `PocketIDAPIKey`, `PocketIDAPIID`; broker handlers, principal-aware (Task 3's `AccountBySubject`); a failed `CreateClient` after a `CreateMachine` (or the reverse) leaves nothing (create the client first, then the row; delete the client if the row insert fails).
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/pocketid/ ./internal/broker/ -v`; 100%.
- [ ] **Step 5: Commit.** `feat(broker): mint a machine's Pocket ID client and register its key`.

---

### Task 6: the CLI creates a machine and signs assertions

**Files:** `internal/cli/cli.go`, `internal/cli/cli_test.go`, `internal/auth/auth.go`, `internal/auth/store.go`, `internal/auth/auth_test.go`, `internal/auth/store_test.go`, `internal/mockidp/mockidp.go` (federated assertion support)

**Interfaces:**
- Consumes: `POST /api/machines`; `OIDC`.
- Produces: `auth.Tokens` gains `MachineKey string` (a path or the JWK); `auth.ClientAssertion(key jose.JSONWebKey, clientID, issuer, audience string, now time.Time) (string, error)`; `OIDC.ExchangeAssertion(ctx, clientID, assertion string) (Tokens, error)`; `RefreshStored`/`KeepFresh` mint an assertion when `MachineKey != ""`. CLI `machine create NAME`, `machine list`, `machine remove NAME`.

- [ ] **Step 1: Write the failing tests.** `ClientAssertion` produces an ES256 JWT with `iss`/`aud`/`sub`(client id)/`exp`/`jti`; `machine create nas` generates a key (0600 file), posts the public JWK, stores `{clientID, MachineKey}`; `machine list` shows it; `machine remove` deletes. mockidp verifies a federated `client_assertion` (an EC public key registered for a client) and refuses a wrong key or a reused `jti`; **the private key is never in the request body or the log**.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.** ES256 key generation (`go-jose`), stored 0600; `ClientAssertion`; `ExchangeAssertion` (`client_credentials` + `client_assertion_type` + `client_assertion`); the `machine` subcommands; mockidp federated verification (issuer→client→public key, `jti` replay).
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/auth/ ./internal/cli/ ./internal/mockidp/ -v`; 100%.
- [ ] **Step 5: Commit.** `feat(cli): create machines with a key pair`.

---

### Task 7: end to end and docs

**Files:** `e2e/e2e_test.go`, `README.md`, `docs/design.md`, `docs/plans/2026-10-11-tunnels-machines-design.md`

**Interfaces:** consumes every task.

- [ ] **Step 1: e2e tests.** Against a real frps with a mock Pocket ID: a machine publishes as its own handle; **a machine work connection with another control's run ID is refused** (invariant 2, the test present today as the negative); a disabled machine loses its tunnel within a heartbeat; a machine site is reachable by its owner and a sharee, and a share on the owner's own tunnel does not admit the machine's site.
- [ ] **Step 2: Run them to verify they pass.** `TEST_DATABASE_URL=… go test -tags e2e ./e2e/ -v`.
- [ ] **Step 3: Docs.** `README.md`: `machine create/list/remove`, the key file, the new broker env (`POCKET_ID_URL`, `POCKET_ID_API_KEY`, `POCKET_ID_API_ID`), and `MACHINE_CLIENTS` removed. `docs/design.md`: the machine section points at the machines design. Note the `shares` migration and the apex `/api/machines` route.
- [ ] **Step 4: Run the full gate.** `go test -race ./...` and `go-test-coverage --config=.testcoverage.yml` → 100%.
- [ ] **Step 5: Commit.** `docs: record broker-owned machines`.

---

## Self-Review

- **Spec coverage:** machines table (T1); shares keyed by the site (T2); resolver Login/Ping/NewWorkConn (T3); `/authz` (T4); Pocket ID minting + API (T5); CLI + key + assertion (T6); e2e + docs (T7). The design's invariants 1–10 each have a named test in T1–T4/T6/T7; invariant 2 is the e2e negative in T7.
- **Type consistency:** `Machine`, `MachineByClientID`, `AccountBySubject`, `ShareMatches(ownerSub, handle, tunnel, …)`, `pocketid.CreateClient`, `auth.ClientAssertion`, `OIDC.ExchangeAssertion` are used the same way in every task that names them.
- **Review Focus:** each of the six lines has an owning test (1,2 → T5/T6; 2 → T1; 3 → T2/T4; 4 → T3; 5 → T3/T7; 6 → T5).
- **Proportion:** seven tasks for a store, a broker, a CLI and a deploy; no task transcribes a body it does not have to.

## Left open (the builder decides)

- The exact JWK shape the broker posts and the CLI generates (EC P-256), and the assertion's `iss`/`aud`/`sub` values.
- Whether `machine create` runs the Pocket ID call through the broker or the CLI talks to Pocket ID directly (the design has the broker do it).
- Hardware keystores (Secure Enclave / TPM) — v1 uses a 0600 key file.
