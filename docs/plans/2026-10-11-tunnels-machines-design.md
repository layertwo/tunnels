# Tunnels Machines - Design

> Companion to `docs/design.md`, which ships machine clients as one Pocket ID client per machine plus
> a `MACHINE_CLIENTS` map in the broker's environment. This document replaces that with
> **broker-owned machine principals**, each holding a **private key** the broker never sees. It is the
> working design; an implementation plan follows once it is approved.

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
- **The credential is a copyable string.** A client secret is a value anyone who reads the machine's
  disk can copy and then use from anywhere.
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
- Pocket ID's `token_endpoint_auth_methods_supported` is `client_secret_basic`, `client_secret_post`,
  `none` — **no `private_key_jwt`** (its client-metadata path rejects it). What it does support is
  **federated client credentials**: a `client_assertion` JWT verified against a JWKS URL or a
  **pasted public key**, with replay protection per `jti`. That is how a machine authenticates with a
  key instead of a secret.
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
   machine (owner's box)                          cluster (homelab)
   private key ─┐
                └─ signs a client_assertion ─▶ Pocket ID ─▶ access token (sub = client-<id>)
   tunnel CLI  ──wss(+access token)──▶ frps :7000
                                        │ plugin Login
                                        ▼
                                    broker ── verify token (JWKS), resolve client-<id> → machines row → handle
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
| 3 | The machine authenticates to Pocket ID with a **key pair** (a signed `client_assertion`, registered as a federated client credential), not a secret. | Its identity becomes proof of possession of a private key — not a copyable string — and the key can live in the system keystore. Per-machine clients keep the subject distinct (Decision 4). |
| 4 | The machine's OIDC **subject is its client id** (`client-<id>`); that subject, not a config map, is what every hook resolves. | It is the only per-machine identifier frps and the broker both see (Constraints). |
| 5 | **Extend the identity resolution to machines in Login, Ping and NewWorkConn** — the hook today is user-only. | Otherwise machines are unbound: a work connection with a machine subject is accepted for any control's run ID (verified; see Security). |
| 6 | **No secret is handed out.** The machine generates a key pair and sends only its **public key** at bootstrap; the private key never leaves the machine (ideally hardware-backed). | There is nothing to leak, copy or bake into a binary. Rotating is swapping the public key (Pocket ID allows several federated credentials per client). |
| 7 | A machine's handle shares **one namespace** with people; the reserved list applies; uniqueness is enforced across both. | One FQDN namespace; no land grab. |
| 8 | `owner_kind`/`owner_ref` columns now (user today, group later). | Two columns that save a migration when groups land. |
| 9 | Revocation is **a row** (disable/delete the machine, or delete its client). | The broker is the gate; revocation is instant at Login and within one heartbeat at Ping. |
| 10 | A machine's site is owned by its **owner** (from `owner_ref`) and is **shareable like any other**: the owner admits, a share admits a viewer. A share is keyed by the **site** (owner sub + the site's handle + tunnel), not the tunnel name alone. | One sharing model for people and machines. Keying by the site stops a share on one of an owner's sites admitting another — a machine's `nas-blog` must not inherit a share on `alice-blog`. |
| 11 | Handle uniqueness across people and machines is enforced **in the store**, not by convention. | Two tables cannot share a unique index and a create-path race must not collide; the shape is the builder's. |
| 12 | The broker API is **principal-aware**: `/api/me` accepts a machine to report its handle; `/api/shares` refuses a machine subject. | A machine credential must not carry its owner's share authority (anti-goal). |

## Flows

### Bootstrap (`tunnel machine create NAME`, owner authenticated)

1. The CLI calls the broker as the owner (the existing user login).
2. The machine generates a **key pair** — in the system keystore where one exists (Secure Enclave,
   TPM 2.0, PKCS#11); the CLI sends only the **public key**.
3. The broker validates the handle (rules, reserved, unique across people and machines), creates the
   `machines` row with `owner = the caller's sub`, then **mints a Pocket ID client** through Pocket
   ID's REST API (`POST /api/oidc/clients`, `client access` to the API) and registers the **public key
   as a federated client credential** (issuer / audience / subject, with the pasted key).
4. It returns the handle and the client id — **never a secret**. The config dir is ready for `up`.

The command runs **on the target machine**: the key is generated there, so it never travels, and a
one-time device approval performed in any browser is the only human step.

### Publish (`tunnel up …` on the machine)

1. The CLI signs a short-lived JWT assertion with the machine's private key and exchanges it at Pocket
   ID's token endpoint (`client_credentials` + `client_assertion`) for an access token, then writes it
   to the token file; frpc sends it as the frp token. The token's subject is `client-<id>`.
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
- **Rotate** by registering a **new public key** as an additional federated credential and removing the
  old one (Pocket ID keeps several per client), so the identity — and the FQDN — does not change.
  Rotation is a manual Pocket ID action in this change; the broker exposes create/list/remove only.

## Credentials and lifetimes

| Credential | Obtained by | Lifetime | Verified by |
|------------|-------------|----------|-------------|
| machine access token | `client_credentials` + a signed `client_assertion` | 1 h, re-minted by `KeepFresh` | frps (JWKS) + broker |
| client assertion | signed per token request with the machine's private key | minutes, single use (`jti`) | Pocket ID (federated credential) |
| machine private key | generated on the machine (keystore where available) | until rotated | never leaves the machine; its **public key** is the credential |
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
| `internal/store` | a `machines` table and methods; the `shares` key gains the site's **handle** (so a share covers one site), with a migration that backfills the owner's handle into existing rows |
| `internal/broker` | `Resolver` resolves `client-<id>` to a machine in Login **and** NewWorkConn; `/api/machines` (create/list/delete); a Pocket ID admin client that registers the machine's **public key** as a federated credential; the API refuses a machine subject for share management |
| `internal/broker` `/authz` | resolves a site's owner across `users` and `machines`; a machine site admits its owner and sharees of **that site** |
| `internal/broker` config | `MACHINE_CLIENTS` and `Deps.MachineClients` removed; a Pocket ID admin key, its URL, and the Tunnels API's id (for the client-access grant) added |
| `internal/cli` | `machine create/list/remove`; generate and store the key pair (system keystore where possible); sign the `client_assertion` |
| `internal/auth` | the client-credentials path gains a key-assertion mode (`client_assertion` in place of a secret) |

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
| 3 | **A machine's identity is possession of its private key**: minting a token (and so reaching frps) requires the key; the client id and subject alone are not a credential. | unit + e2e (a token cannot be minted without a valid assertion) |
| 4 | A machine resolves to exactly one handle; it cannot claim another; disabled/deleted → refused. | unit + e2e (revocation at Login and within one heartbeat at Ping) |
| 5 | The machine subject never resolves through the `users` table; the handle comes only from the `machines` row. | unit |
| 6 | Handle validation, reserved list and cross-namespace uniqueness hold. | unit |
| 7 | The credential is never logged; the hook rejects before setting a user. | unit + e2e (token absent from logs) |
| 8 | Token verification refuses algorithm confusion and wrong issuer/audience/expiry. | unit (`TestVerifyAccessTokenRejectsAlgorithmConfusion`, present) |
| 9 | A client assertion is short-lived and **single-use** (Pocket ID's `jti` replay protection); a captured assertion cannot be replayed. | unit (the CLI never reuses a `jti`; a second exchange with the same assertion is refused) |
| 10 | A share admits exactly one site: a share on one of an owner's tunnels never admits another. | unit (an owner with `blog` shared; the machine's `nas-blog` is refused) |

Today's code fails invariant 2 for machines: `newWorkConn` resolves the subject through `users`, so a
machine subject is not bound. NewWorkConn is dormant in production (not in `ops`), so this must be
fixed **in the same change that enables it**, not after.

## Threat model

| Threat | Control |
|--------|---------|
| Rogue takes the CLI and connects | frps admits on the OIDC token; the broker refuses without a machine row (invariant 1/3) |
| Rogue copies a machine's disk or config | a hardware-backed private key does not copy, so no token can be minted; a copied software key is revoked by swapping the public key |
| Run-ID thief injects a work connection | the NewWorkConn hook binds the work connection's subject to the control (invariant 2) — the reason for a per-machine subject |
| Handle land grab | validation, reserved list, uniqueness across people and machines (invariant 6) |
| A share leaks across an owner's sites | shares are keyed by the site's handle, not the tunnel name (invariant 10) |
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
- Auth: the assertion is signed with the machine's key and exchanged for a token; a token cannot be
  minted without the key; a reused `jti` is refused.
- The two present tests (`TestUnknownMachineClientGetsNoTunnel`, `TestVerifyAccessTokenRejectsAlgorithmConfusion`)
  carry over.

## Migration from the merged machine-client code

- `MACHINE_CLIENTS` and `Deps.MachineClients` are removed; the mapping moves to the `machines` table.
- `tunnel login --machine` is replaced by the key-based credential the bootstrap installs (a machine
  that still holds a client secret is migrated by registering a key and dropping the secret).
- No production machine clients exist yet (v0.3.0 is unreleased), so there is nothing to migrate.

## Deferred

- **Group ownership** — the columns exist; the resolution is not built.
- **Per-machine interaction ACLs** ("who may shell into this machine") — the SSH/web-terminal phase;
  this design only fixes *who a machine is* and *who owns it*.
- **Machine credential scope** — whether a machine token may call the share API (it should not, once
  capability is modelled).
- **Hardware-backed keys** — deferred. v1 stores the machine's key in a 0600 file. The intended future
  shape is a **pluggable keystore** so a hardware backend slots in, chosen per machine with the file
  as the fallback (a Pi or many VPS have no TPM, so it can never be the only path). The constraint:
  the CLI ships `CGO_ENABLED=0` on every target, so the only backend that fits as-is is **Linux TPM
  2.0** (pure-Go `go-tpm`, `/dev/tpmrm0`); macOS Secure Enclave and Windows NCrypt would force cgo
  into the release (or a shell-out to `security`/`ncrypt`) — a deliberate release-pipeline decision to
  make together with the backend, not as a side effect.
- **`install.sh` / live status / frps HA** — unrelated, tracked in `docs/design.md`.

## Left to the builder

- The `machines` schema and whether `client_id` is the primary key or a separate column.
- The shape of cross-namespace handle uniqueness (a shared claim table, machine rows in `users`, or a
  spanning unique index) — the property is fixed (Decision 11), the mechanism is not.
- The key storage backends and their fallback order (Secure Enclave / TPM 2.0 / PKCS#11 / a 0600 key
  file), the key type and curve, and the migration path when a backend appears later.
- The assertion's `iss` / `aud` / `sub`, lifetime and clock skew, and the signing library (reuse the
  module graph).
- Whether the CLI or the broker performs the federated-credential registration call.
- The `shares` migration (backfill the owner's handle) and how `share`/`unshare` name a machine's
  site in the CLI (the label, or a `--machine` flag).
- The Pocket ID admin client's error handling when minting fails mid-bootstrap (rollback).
- The `Ping` path for a machine: re-check the row by the bound handle, or re-resolve the token.
- Whether a machine counts toward `MAX_TUNNELS_PER_USER` and the bandwidth limit (it should).
- The `tunnel machine …` command surface and its output.
- How the broker stores the admin key (env vs file) and its rotation runbook.
