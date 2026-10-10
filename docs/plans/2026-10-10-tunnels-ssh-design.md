# Tunnels SSH - Design

> Companion to `docs/design.md`, which reserves the SSH subtree and lists SSH under "Later".
> This document decides how SSH works. It is the working design for the feature; an
> implementation plan follows once it is approved.

## Intent and why

A creator runs an SSH service on a machine of theirs and reaches its shell from anywhere, over the
one thing that gets out of restrictive networks: HTTPS on 443. The machine may be on their LAN, a
VPS, or a cloud box — location does not matter, because the agent always dials out and the headend
never dials in.

v1 is a **native `ssh` experience**: an `ssh_config` `ProxyCommand` makes `ssh box1` work in any
terminal, authenticated with Pocket ID. No host is exposed directly; no anonymous access.

## Goals

- Publish a local SSH service (default `127.0.0.1:22`, optionally another address the machine can
  reach) through the existing agent, naming it like every other tunnel.
- A native `ssh` experience via `ssh_config`, with the CLI as the `ProxyCommand`.
- Reuse what exists: the frp client embedded in `tunnel`, Pocket ID, the wss control channel, the
  broker's authorization, and the WebSocket path already proven end to end (Phase 0 C4).
- Owner-only in v1; sharing is a later phase, gated by the same authorization the sites use.

## Non-goals

- A browser terminal (deferred; see below).
- Reaching SSH hosts that cannot run the agent (the headend never dials them).
- SSH servers behind an additional jump; a tunnel names one target.
- A general LAN path (a forwarding/SOCKS shape); one tunnel is one address.
- Non-WebSocket transports. Stock `ssh` cannot wrap TLS around a CONNECT, so the CLI is required.

## Anti-goals

- **The headend must never initiate a connection to a target.** `frps` relays between a visitor and
  a publisher that dialed in; it does not dial creators or arbitrary hosts. Anything that lets a
  caller name an arbitrary `host:port` for the cluster to dial turns the service into an open
  relay and is out.
- **The cluster must never carry SSH bytes.** In v1 this is automatic: the browser is not involved.
  It is what ruled out a cluster-relayed browser terminal.
- No unauthenticated path to a shell.
- No anonymous tunnels; no direct exposure of the target port.

## Constraints

- `github.com/fatedier/frp` stays pinned to the frps image version and both bump together.
- Broker and frps stay distroless, non-root, read-only root, dropped capabilities, default-deny
  NetworkPolicy.
- Cloudflare **can** proxy the SSH-over-WebSocket path: WebSockets are supported on all plans, and
  the control channel already proves wss works through the edge. The reason the subtree is a
  **DNS-only** record with its own wildcard certificate, like `*.w.`, is the certificate: the free
  Universal SSL covers only one subdomain level, so `*.ssh.tunnels.layertwo.dev` cannot be proxied
  without Cloudflare's Advanced Certificate Manager add-on (about $10/month per zone), which can
  carry `*.layertwo.dev` and `*.ssh.tunnels.layertwo.dev` on one certificate. (Uploading the
  origin's own cert instead needs the Business plan, $200/month.) DNS-only also keeps TLS end to end (Cloudflare would
  otherwise terminate it and see the SSH bytes) and avoids Cloudflare's 100 s idle WebSocket
  timeout dropping a quiet session.
- `frps` has a single `subDomainHost` (`w.tunnels.layertwo.dev`), so the SSH subtree is expressed
  with frp **custom domains**, not subdomains. frp's README warns custom domains should not be
  subdomains of `subDomainHost`; `ssh.tunnels.layertwo.dev` is not under `w.`, so it is clear.
- The identity provider and the OIDC plugin are used as they are; no new identity system.
- User-private files are 0600; tokens are never logged.

## Architecture

```
                                     cluster (homelab)                         publisher machine
  terminal ──▶ tunnel CLI ──wss(+bearer)──▶ Traefik(forwardAuth) ──▶ frps :8080 ──▶ agent bridge ──▶ target (default 127.0.0.1:22)
                                            broker /authz decides              (frpc work conn)
```

Nothing new listens on frps: the SSH stream rides the existing `vhostHTTPPort` (8080), reached
through the same Traefik that serves sites. The agent runs a small WebSocket bridge on loopback and
registers an ordinary `http` proxy for it with a custom domain under the SSH subtree.

The terminal client presents its **Pocket ID bearer token**. There is one credential and one data
route, and the route runs `forwardAuth` **without** the OIDC plugin (which would answer a bearer
client with an HTML login page).

## Decisions taken

| # | Decision | Why |
|---|----------|-----|
| 1 | SSH is published as an **HTTP proxy with a WebSocket bridge**, not `tcpmux`. | Reuses the proven WebSocket path and the existing Traefik auth; no new frps port, no gateway. |
| 2 | **Native `ssh` is v1; the browser terminal is deferred.** | It reuses the user's own `ssh` for authentication and removes the entire web surface (page, ticket, cluster relay question). |
| 3 | Terminal auth is the **Pocket ID bearer token**; the data route runs **`forwardAuth` only**, never the OIDC plugin. | The terminal has no browser and no cookie; the OIDC plugin would break a bearer client. |
| 4 | The SSH subtree uses frp **custom domains** under `*.ssh.tunnels.layertwo.dev`. | One `subDomainHost`; the SSH subtree must be separate from `w.`. |
| 5 | SSH shares the tunnel-name namespace with HTTP tunnels (`<handle>.<name>`). | frp proxy names are unique per server; a name is one tunnel. |
| 6 | `--target` may name another address the machine can reach; the broker cannot and does not enforce the dial target. | Only the publisher chooses it, and it already runs code on its own machine; a visitor never influences it. |
| 7 | v1 is **owner-only**; SSH inherits sharing when phase 2 lands. | The `shares` table does not exist yet, and `/authz` is owner-only today. |
| 8 | **Machine clients (`client_credentials`) stay phase 3**; v1 uses Pocket ID refresh tokens (30-day window). | A box idle more than 30 days re-logs in once; the never-a-passkey path is phase 3. |

## Flows

### Publish (`tunnel up PORT --ssh`)

1. The CLI starts a WebSocket bridge on `127.0.0.1:<random>`, dialing the target (`127.0.0.1:22`
   by default, or `--target HOST`).
2. It builds the frp client with one `http` proxy: `name=<handle>.<name>`,
   `customDomains=["<label>.<SSH_DOMAIN>"]`, `localIP=127.0.0.1`, `localPort=<bridge>`,
   `requestHeaders.set.x-forwarded-proto="https"`.
3. The broker's `NewProxy` hook accepts `http` **only** when the custom domain is exactly
   `<label>.<SSH_DOMAIN>` for this owner's label, keeps its bandwidth limit, and rejects every
   other protocol or domain.
4. The control channel is the existing wss to `tunnels.layertwo.dev:443`.

### Native `ssh`

```
Host box1
  HostName alice-box1.ssh.tunnels.layertwo.dev
  ProxyCommand tunnel dial %h %p
```

1. `ssh box1` runs `tunnel dial alice-box1.ssh.tunnels.layertwo.dev 22`.
2. The CLI loads its access token, opens TLS to the host, sends an HTTP upgrade with
   `Authorization: Bearer <access token>`, then pipes stdin/stdout.
3. Traefik `forwardAuth` → broker: verify the token (JWKS), authorize (owner or share), allow.
4. frps routes by `Host` to the agent's bridge, which dials the target. Bytes flow.

`tunnel ssh-config [NAME]` prints the `Host` block, so the user does not hand-edit.

## Auth model

| Caller | Credential | Verified by | Route chain |
|--------|-----------|-------------|-------------|
| `tunnel dial` | Pocket ID access token | broker (JWKS) + owner/share | strip-identity → forwardAuth → broker |
| Anyone else | — | 403 | |

## Token lifetimes

Two credentials age here; only the visitor's is new.

**Publisher (`tunnel up --ssh`).** Unchanged from a site. `up` refreshes the stored login once at
start, then runs `auth.KeepFresh` every 30 minutes; the frp client reads its token from the
`access-token` file for every login, ping and work connection, and the file is rewritten atomically
on each refresh. Access tokens last an hour and heartbeats are 30 s against a 90 s timeout, so an
expired or revoked token drops the tunnel within about 90 s and the agent reconnects with the fresh
file token. Nothing here is SSH-specific.

**Visitor (`tunnel dial`).** New, and simpler than it looks:

- `dial` is short-lived — `ssh` runs the `ProxyCommand` once per connection — so it needs a valid
  token only at the WebSocket handshake.
- Traefik's `forwardAuth` runs **once**, at the upgrade. After that there is no further token check
  on the connection, so a token expiring mid-session does **not** drop the session. A dropped
  connection is a new `ssh` and a fresh `dial`, not a re-auth.
- `dial` reads the stored login and refreshes only when the access token is near or past its `exp`
  (or retries once on a 401). Refreshing on every invocation would rotate the refresh token
  needlessly and race a running `tunnel up`; the store's load-then-refresh, plus Pocket ID's 60 s
  rotation grace, already covers concurrent refreshes.
- A failed refresh fails that connection with `run: tunnel login`.

**Headless targets (the remote-box case).** The passkey is needed **once**, at first `tunnel login`
(device flow approved in any browser); the box never does another passkey login. From then on the
**refresh token** is the credential that mints new access tokens with no passkey, and `KeepFresh`
rotates it every 30 minutes. At Pocket ID (v2.18.0, issue #792): access and ID tokens are 1 h and the
refresh token is 30 days, all hardcoded; the refresh chain slides on each use, so a continuously
running agent stays logged in indefinitely. A box left **idle longer than 30 days** loses its
refresh token and needs one more `tunnel login`.

For a permanently unattended publisher the headless mechanism is a **machine client**: Pocket ID's
`client_credentials` grant lets a confidential client with a secret obtain access tokens with no
passkey and no refresh token. That is the phase-3 "machine clients" item in `docs/design.md`; the
broker maps `client_id` to a handle. v1 (owner-only) ships without it, so a box rebooted within 30
days is fine. Note that Pocket ID publishes no revocation endpoint and at least one advisory
(CVE-2026-43983) reports a refresh chain surviving authorization revocation, so ending access for
certain is done in Pocket ID (see `docs/design.md`).

## Names and hostnames

| Item | Rule |
|------|------|
| SSH domain | `SSH_DOMAIN` = `ssh.tunnels.layertwo.dev` (new config) |
| Tunnel label | reused: `<handle>` or `<handle>-<name>` |
| SSH host | `<label>.<SSH_DOMAIN>` = `<label>.ssh.tunnels.layertwo.dev` (frp custom domain) |
| frp proxy name | `<handle>.<name>` (shared namespace with HTTP tunnels) |

## Repo changes

| Area | Change |
|------|--------|
| `internal/names` | a `SiteLabel`-equivalent for the SSH domain, reusing label rules |
| `internal/tunnel` | SSH mode: a WebSocket bridge + an `http` proxy with `customDomains` |
| `internal/cli` | `up PORT --ssh [--target HOST]`, `dial HOST PORT`, `ssh-config [NAME]` |
| `internal/broker` | `NewProxy` allows `http`+custom domain under `*.ssh.`; `/authz` gains a bearer mode; `SSH_DOMAIN` |
| `cmd/broker` | wire `SSH_DOMAIN` |

## Infra changes (homelab repo)

- DNS: `*.ssh.tunnels.layertwo.dev`, DNS-only (no Cloudflare proxy).
- Certificate: a wildcard for `*.ssh.tunnels.layertwo.dev` via the existing DNS-01 issuer.
- Traefik: a `Host(*.ssh.…)` route with `forwardAuth` only (no OIDC plugin), limited per host.
- NetworkPolicy: unchanged in shape (Traefik → frps :8080, frps → broker, broker → Postgres/IdP).
- frps: no new port; the plugin change is in this repo.

## Threat model

| Threat | Control |
|--------|---------|
| Bearer client smuggled through the browser gate | the `*.ssh.` route runs `forwardAuth` only; the OIDC plugin is never in that chain |
| Stolen or forged token | frps/broker verify signature, issuer, expiry and audience; the owner/share check runs per connection |
| Arbitrary `(host, port)` dialed | the target is chosen by the **publisher only**, never a visitor. frp exposes no field for the broker to constrain the dial, so this is trust-by-ownership, not a server guarantee: the publisher already runs code on its own machine. The server enforces the tunnel's *name and domain*, not the dial target. |
| Cluster compromise yields shells | v1 has no cluster-side shell component |
| Revoked user keeps access | short-lived access tokens and the per-connection owner/share check |
| Target port exposed | the bridge binds loopback only; frps's vhost port is internal and Traefik is the only ingress |

## Failure modes

| Down | Effect |
|------|--------|
| Broker | `forwardAuth` refuses; running sessions continue until the connection drops |
| Pocket ID | new terminals cannot authenticate; existing sessions continue until tokens expire |
| frps | all tunnels drop; the agent reconnects |
| Agent | that tunnel's host refuses |

## Testing

- Unit: label/domain rules for the SSH subtree; `NewProxy` accepting only the owner's SSH custom
  domain; `/authz` bearer matrix (owner, share, bad token, wrong host, default deny).
- Integration/e2e: a real frps, an agent bridge, and a client that opens the WebSocket and checks an
  echo through to a local listener; a refused cross-user case.
- Manual smoke: `ssh box1` through `tunnel dial`.

## Deferred: web terminal

Recorded so it is not relitigated from scratch. A browser terminal is an HTTP page plus a
WebSocket, and **xterm.js is not an SSH client** — something must terminate SSH:

- the browser runs an SSH client (WASM/JS) and the user supplies a key or password (one protocol,
  raw SSH, shared with native `ssh`; heavier front-end, keys in the browser); or
- the agent terminates SSH / serves a local PTY (browser only renders bytes; simpler, but it is a
  remote shell, not SSH, and no longer shares the raw-SSH bridge); or
- a cluster relay carries the shell (bigger blast radius; rejected).

A cluster-hosted page needs a **ticket handshake** between the OIDC-cookie-authenticated page and
the data WebSocket, because host-only cookies do not cross hostnames. The chosen shape, if built,
is W1: the cluster serves the page and mints a short-lived ticket; the browser connects straight to
the tunnel; the cluster never touches the shell. It is deferred.

## Left to the builder

- The `dial` mode's mapping of `%h`/`%p` to a tunnel, and `ssh-config` output format.
- WebSocket library choice (reuse the module graph where possible).
- Bridge protocol details, keepalives, and graceful shutdown.
- The exact `--ssh` flag shape and whether `--ssh` and a plain port can coexist in one invocation.
- Whether SSH tunnels count toward `MAX_TUNNELS_PER_USER` and the bandwidth limit (they should).
