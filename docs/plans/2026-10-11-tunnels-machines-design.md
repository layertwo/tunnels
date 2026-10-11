# Tunnels Machines - Design

> Companion to `docs/design.md`, which ships machine clients as one Pocket ID client per machine plus
> a `MACHINE_CLIENTS` map in the broker's environment. This document replaces that with
> **broker-owned machine principals** and a broker-minted per-machine credential. It is the working
> design; an implementation plan follows once it is approved.

## Intent and why

A headless machine — a NAS, a Pi, a VPS — must publish tunnels without a passkey and without a human
present. v0.3.0's machine clients (PR #40, #42) do that, but their shape is wrong for where the
service is going:

- **Identity lives in the identity provider.** One confidential Pocket ID client per machine, and
  Pocket ID only lets *admins* create clients (its API keys are admin-grade). So either an admin
  makes every machine client, or the broker is handed a full-admin key.
- **The mapping lives in an environment variable.** `MACHINE_CLIENTS=id=handle,…` is a
  comma-separated list in a ConfigMap: a broker restart per change, no audit, no per-machine
  metadata, and the owner cannot self-serve.
- **A machine is an alias for a person.** It publishes *as* that human, so revoking one machine means
  editing the shared list, a person's several machines are indistinguishable, and it is
  impersonation — which is why the creators-group check had to be skipped for it.
- **It cannot grow into what SSH and the web terminal need.** "Who owns this machine" and "who may
  reach or shell into it" are authorization questions the broker has nowhere to keep.

We want a **machine to be its own principal with its own handle and FQDN, owned by a person (later a
group), known to the broker** — and the broker to be the identity *and* authorization authority for
it. Then ownership, group ownership, interaction ACLs and revocation are all rows the broker can
answer, and the identity provider never learns about them.

## Goals

- A machine publishes as itself, with its own handle and FQDN, no passkey and no human.
- The owner bootstraps their own machine (self-service); no admin step per machine.
- The broker owns machine identity and authorization — the seam SSH and the web terminal need.
- Every security property we already rely on for users holds for machines too, including the
  **work-connection binding** (below).
- No new standing admin grant.

## Non-goals

- Group ownership now (the columns exist; only a user is implemented).
- SSH or the web terminal (v0.4.0); this is the model they inherit.
- frps HA.
- A browser UI for machine management.

## Anti-goals

- **frps admission treated as a security boundary.** It is plumbing; the broker decides.
- **A machine choosing its own handle** without validation, the reserved list, and uniqueness.
- **A machine credential granting more than the machine** (e.g. its owner's share API).
- **A shared machine subject.** It would silently drop the work-connection binding (see Security).
- **A rogue with the CLI able to publish or reach anything.**

## Constraints

- `frp` has a **single, server-wide `auth.method`** (ours is `oidc` for the human CLI and the browser
  gate too), so the token that gets a client past frps must be an OIDC token.
- A `client_credentials` token's subject is **`client-<client id>`**; Pocket ID releases no
  per-client claim into an access token (custom claims are per user or group and never in the access
  token; `#781`/`#1827` deliberately exclude M2M). So per-machine identity can only come from a
  per-machine client.
- frp's plugin `LoginContent` carries `privilege_key` and `metas`; `NewProxy`/`Ping`/`NewWorkConn`
  carry the control's `User{user, metas, run_id}`; `msg.NewWorkConn` carries **no** `metas`. frps's
  OIDC check on a post-login token only asks that its subject was seen at a login
  (`pkg/auth/oidc.go` `verifyPostLoginToken`). The broker re-verifies the token itself.
- `msg.NewWorkConn.PrivilegeKey` is the *client's* token; a shared client would make it identical
  across machines.
- Broker and frps stay distroless, non-root, read-only root, dropped capabilities, default-deny
  NetworkPolicy. Tokens are 0600 and never logged. Every `./internal/...` package stays at 100%.

## Architecture

```
   machine (owner's box)                     cluster (homelab)
   tunnel CLI  ──wss(+platform token, metas.tunnels_token)──▶ frps :7000
                                                              │ plugin Login
                                                              ▼
                                                          broker ── verify platform token (JWKS)
                                                                 ├─ resolve metas.tunnels_token → machines row → handle
                                                                 └─ set the control's user = machine handle
                                                              │
                                                          Postgres (machines)
```

Visitors are unchanged: they reach a site through the gate and the broker's `/authz`.

## Decisions taken

| # | Decision | Why |
|---|----------|-----|
| 1 | A machine is a **broker-owned principal** (`machines` row): its own handle, an owner, later a group. | Ownership, groups, ACLs and revocation are the broker's to answer; the seam SSH/web-terminal needs. |
| 2 | Its credential is a **per-machine Pocket ID client, minted by the broker** at bootstrap. | Per-machine identity is only obtainable from a per-machine client (Constraints), and the **work-connection binding needs a per-machine subject** (Security). The broker minting it keeps bootstrap self-service. |
| 3 | frpc sends the machine's OIDC token as the frp token and the **machine token in `metas`**; the Login hook resolves it. | The frps door needs a valid OIDC token; the broker is the identity authority and `LoginContent` already exposes `metas` (it reads `tunnel_version` today). |
| 4 | The machine's OIDC **subject is its client id** (`client-<id>`); that subject, not a config map, is what every hook resolves. | It is the only per-machine identifier frps and the broker both see (Constraints). |
| 5 | **Extend the identity resolution to machines in Login, Ping and NewWorkConn** — the hook today is user-only. | Otherwise machines are unbound: a work connection with a machine subject is accepted for any control's run ID (verified; see Security). |
| 6 | The platform/client secret is **handed out at bootstrap, never baked into the CLI**. | It is not the credential; keeping it off a public binary raises the bar from "download the CLI" to "compromise a machine". |
| 7 | A machine's handle shares **one namespace** with people; the reserved list applies; uniqueness is enforced across both. | One FQDN namespace; no land grab. |
| 8 | `owner_kind`/`owner_ref` columns now (user today, group later). | Two columns that save a migration when groups land. |
| 9 | Revocation is **a row** (disable/delete the machine, or delete its client). | The broker is the gate; revocation is instant at Login and within one heartbeat at Ping. |
| 10 | A machine's site is authorised by its **owner** (from `owner_ref`); v1 admits only the owner, sharing a machine's site is deferred. | Matches SSH v1 (owner-only); machine sharing needs the shares key to accept a machine principal, a later change. |
| 11 | Handle uniqueness across people and machines is enforced **in the store**, not by convention. | Two tables cannot share a unique index and a create-path race must not collide; the shape is the builder's. |
| 12 | The broker API is **principal-aware**: `/api/me` accepts a machine to report its handle; `/api/shares` refuses a machine subject. | A machine credential must not carry its owner's share authority (anti-goal). |

## Flows

### Bootstrap (`tunnel machine create NAME`, owner authenticated)

1. The CLI calls the broker as the owner (the existing user login).
2. The broker validates the handle (rules, reserved, unique across people and machines), creates the
   `machines` row with `owner = the caller's sub`, then **mints a Pocket ID client** through Pocket
   ID's REST API (`POST /api/oidc/clients`, `client access` to the API; `POST .../secrets`).
3. It returns, once: the handle, the client id and secret. The CLI stores them 0600 and leaves the
   config dir ready for `up` (no separate `login --machine`).

The command runs **on the target machine** in the common case — a one-time device approval, performed
in any browser, is the only human step — or on a laptop with the credential copied over. Either way
the secret is written locally, never fetched from a public binary.

### Publish (`tunnel up …` on the machine)

1. The CLI mints an access token with `client_credentials` (the machine's client id and secret) and
   writes it to the token file; frpc sends it as the frp token and carries its own identity
   implicitly in the client id.
2. The broker's `Login` verifies the token, resolves `client-<id>` to its `machines` row, checks the
   owner is not disabled, and sets `user = the machine's handle`. The tunnel is the machine's.
3. `KeepFresh` re-mints the token before it expires.

### Work connection (one visitor request)

frps binds a work connection to a control by run ID alone; the broker's `NewWorkConn` hook binds it
to the **subject** as well, and for a machine the subject is the machine's client. The hook resolves
`client-<id>` to the machine row and rejects a mismatch, exactly as it does for a user.

### Revoke / rotate

- **Revoke** a machine by disabling or deleting its **row** — that is the prompt control: Login
  refuses immediately and a live control ends on the next Ping. Deleting its Pocket ID client is
  cleanup (a still-valid token keeps verifying until it expires), **not** the revocation lever.
- **Rotate** its secret by adding a new Pocket ID client secret and removing the old (Pocket ID keeps
  a list of secrets per client), so the identity — and the FQDN — does not change. Rotation is a
  manual Pocket ID action in this change; the broker exposes create/list/remove only.

## Credentials and lifetimes

| Credential | Obtained by | Lifetime | Verified by |
|------------|-------------|----------|-------------|
| machine access token | `client_credentials` (its client) | 1 h, re-minted by `KeepFresh` | frps (JWKS) + broker |
| machine client secret | handed out once at bootstrap | until rotated | Pocket ID |
| Pocket ID API key (broker) | once, by an admin | rotate on schedule | Pocket ID |

The broker's one new grant is the Pocket ID API key that lets it create a client per machine. Keys
are admin-grade (Pocket ID offers no scoped keys), so it is documented, kept in the homelab secret
store, and rotated; the alternative — an admin creating every client by hand — is what we are
removing.

## Names and handles

| Item | Rule |
|------|------|
| machine handle | chosen at bootstrap; `names.ValidHandle`; not reserved; unique across people and machines |
| site FQDN | `<label>.<site domain>`, unchanged; a machine's label is its own handle |
| Pocket ID client id | the machine's — its subject is `client-<id>` |

## Repo changes

| Area | Change |
|------|--------|
| `internal/store` | a `machines` table (`handle`, `owner_kind`, `owner_ref`, `client_id`, `disabled`, `created_at`, `created_by`) and methods |
| `internal/broker` | `Resolver` resolves `client-<id>` to a machine in Login **and** NewWorkConn; `/api/machines` (create/list/delete); a Pocket ID admin client for minting; the API refuses a machine subject for share management |
| `internal/broker` `/authz` | resolves a site's owner across `users` and `machines`; v1 admits only the machine's owner |
| `internal/broker` config | `MACHINE_CLIENTS` and `Deps.MachineClients` removed; a Pocket ID admin key, its URL, and the Tunnels API's id (for the client-access grant) added |
| `internal/cli` | `machine create/list/remove`; `login --machine` keeps working but against the new credential |
| `internal/auth` | unchanged (client-credentials path already exists) |

## Infra changes (homelab repo)

- A Pocket ID API key for the broker, in the secret store. Broker egress to Pocket ID's API is already
  allowed (TCP 443).
- **The apex IngressRoute must route `/api/machines`** (owner bearer; add it beside `/api/me`). The
  broker's `/authz`, `/plugin/` and `/metrics` stay internal: the apex route already routes only
  `/api/me`, `/.well-known/tunnels.json` and `/healthz`, and the broker NetworkPolicy admits only
  Traefik and frps to port 8080.
- The frps plugin `ops` already gains `"NewWorkConn"` with the next release — the machine binding
  depends on it.
- Unrelated but pending: the broker NetworkPolicy must admit the Prometheus namespace to scrape
  `/metrics` (the metrics work, `#40`).

## Security model

Each invariant is a property, not a test name; the plan attaches a test to each. The **first four are
load-bearing** and the model is wrong if any fails.

| # | Invariant | How it is proven |
|---|-----------|------------------|
| 1 | frps defers to the broker: a valid token the broker does not authorise yields no tunnel, no user. | e2e (`TestUnknownMachineClientGetsNoTunnel`, present) |
| 2 | **The work-connection binding holds for a machine**: a work connection whose token subject is not the control's machine is refused. | e2e (verified for users now; must hold for machines after Decision 5) |
| 3 | The broker is the only capability boundary; the client secret is not a credential (it only opens frps). | e2e (rogue with a valid token but no machine → refused) |
| 4 | A machine resolves to exactly one handle; it cannot claim another; disabled/deleted → refused. | unit + e2e (revocation at Login and within one heartbeat at Ping) |
| 5 | The machine subject never resolves through the `users` table; the handle comes only from the `machines` row. | unit |
| 6 | Handle validation, reserved list and cross-namespace uniqueness hold. | unit |
| 7 | The credential is never logged; the hook rejects before setting a user. | unit + e2e (token absent from logs) |
| 8 | Token verification refuses algorithm confusion and wrong issuer/audience/expiry. | unit (`TestVerifyAccessTokenRejectsAlgorithmConfusion`, present) |

Today's code fails invariant 2 for machines: `newWorkConn` resolves the subject through `users`, so a
machine subject is not bound. NewWorkConn is dormant in production (not in `ops`), so this must be
fixed **in the same change that enables it**, not after.

## Threat model

| Threat | Control |
|--------|---------|
| Rogue takes the CLI and connects | frps admits on the OIDC token; the broker refuses without a machine row (invariant 1/3) |
| Rogue steals a machine secret | publish as that machine only, until revoked; rotate the client secret |
| Run-ID thief injects a work connection | the NewWorkConn hook binds the work connection's subject to the control (invariant 2) — the reason for a per-machine subject |
| Handle land grab | validation, reserved list, uniqueness across people and machines (invariant 6) |
| Machine credential over-reaches | the machine's authority is a design item: it should not carry its owner's share API (see Deferred) |
| Broker compromise | it holds hashes and rows, and a Pocket ID admin key — the key is the blast radius; rotate it |
| Enumeration through refusals | refusal text is generic; run IDs and tokens are never logged |

## Failure modes

| Down | Effect |
|------|--------|
| Broker | new logins refused; running tunnels continue until the next Ping |
| Pocket ID | `KeepFresh` cannot re-mint; a machine's tunnel ends when its token expires (~1 h + 90 s) |
| Postgres | logins refused; running tunnels continue |
| frps | all tunnels drop; clients reconnect |

## Testing

- Unit: machine resolution (Login, Ping, NewWorkConn) for the matrix (known/unknown/disabled/other's
  handle); handle validation and uniqueness; `MACHINE_CLIENTS` removal.
- e2e (real frps): a machine publishes as its own handle; **a machine work connection with another
  control's run ID is refused** (invariant 2); a disabled machine loses its tunnel within a
  heartbeat; a rogue with a valid token but no machine gets nothing.
- The two present tests (`TestUnknownMachineClientGetsNoTunnel`, `TestVerifyAccessTokenRejectsAlgorithmConfusion`)
  carry over.

## Migration from the merged machine-client code

- `MACHINE_CLIENTS` and `Deps.MachineClients` are removed; the mapping moves to the `machines` table.
- `tunnel login --machine CLIENT_ID` becomes the credential the bootstrap mints; existing behaviour
  (client-credentials, `TUNNELS_CLIENT_SECRET`) is otherwise unchanged.
- No production machine clients exist yet (v0.3.0 is unreleased), so there is nothing to migrate.

## Deferred

- **Group ownership** — the columns exist; the resolution is not built.
- **Per-machine interaction ACLs** ("who may shell into this machine") — the SSH/web-terminal phase;
  this design only fixes *who a machine is* and *who owns it*.
- **Machine credential scope** — whether a machine token may call the share API (it should not, once
  capability is modelled).
- **`install.sh` / live status / frps HA** — unrelated, tracked in `docs/design.md`.

## Left to the builder

- The `machines` schema and whether `client_id` is the primary key or a separate column.
- The shape of cross-namespace handle uniqueness (a shared claim table, machine rows in `users`, or a
  spanning unique index) — the property is fixed (Decision 11), the mechanism is not.
- The Pocket ID admin client's error handling when minting fails mid-bootstrap (rollback).
- The `Ping` path for a machine: re-check the row by the bound handle, or re-resolve the token.
- Whether a machine counts toward `MAX_TUNNELS_PER_USER` and the bandwidth limit (it should).
- The `tunnel machine …` command surface and its output.
- How the broker stores the admin key (env vs file) and its rotation runbook.
