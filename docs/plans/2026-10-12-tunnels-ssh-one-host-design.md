# Tunnels SSH: one host, the name in the path - Design

> Companion to `docs/design.md`, which reserves the SSH subtree, and to
> [the SSH design](2026-10-10-tunnels-ssh-design.md), whose decision 4 this document supersedes.
> This is the working design; an implementation plan follows once it is approved.

## Intent and why

Today an SSH tunnel is published at `<label>.<SSH_DOMAIN>` - `alice-box1.ssh.tunnels.layertwo.dev` -
and everything about the name lives in DNS: the wildcard record, the wildcard certificate, the
Traefik `Host(*.ssh.…)` router, and the client's `HostName` line.

That is a lot of machinery for a name, and it puts the service's naming policy in the client: the
CLI builds a hostname out of a label and a domain, which it has no business knowing how to spell.
The visitor wants to name a tunnel; the server wants to decide what that name means.

This design publishes every SSH tunnel at **one host**, `ssh.tunnels.layertwo.dev`, and carries the
tunnel's name as **data in the request path**. The path is the only key besides the host that frps
can route on, so it is the one the design uses.

## Goals

- One SSH hostname, `ssh.tunnels.layertwo.dev`. No `*.ssh.` wildcard DNS record, no wildcard
  certificate, no wildcard Traefik router.
- The client sends the tunnel's name as data and never composes a hostname. The server decides how
  a name maps to a route.
- `ssh_config` needs one block for every tunnel the user will ever make.
- Everything else about SSH is unchanged: the WebSocket bridge, the bearer token, the
  `forwardAuth`-only route, the `[ssh]` config section, owner-only access.

## Non-goals

- Nothing changes about how a target is dialled or which target the machine publishes.
- No change to sites, to the sites subtree, or to their sharing.
- No broker in the data plane: frps still routes, and the cluster still carries no plaintext
  session.
- No client other than `tunnel dial`. Stock `ssh` cannot speak WebSocket over TLS, so it is not a
  visitor; this design makes the *server* route a name, not the *client* invent one.

## Anti-goals

- A request must not be able to name a route it does not own. The broker and frps must agree, on
  the same bytes, about which tunnel a request names.
- No unauthenticated path to a shell; no anonymous access.
- The client must not learn the service's naming policy. `dial` sends a name; if the server later
  changes what a name means, no client changes.

## Decisions taken

| # | Decision | Why |
|---|----------|-----|
| 1 | **One host, no wildcard.** SSH is published at `SSH_DOMAIN` itself, not at `<label>.<SSH_DOMAIN>`. | Removes the wildcard DNS record, the wildcard certificate and the wildcard router. A name is not a place. |
| 2 | **The tunnel's name is the first path segment**: `wss://<SSH_DOMAIN>/<label>/…`. | The host is now a constant, so the path is the only key frps can route on besides it. |
| 3 | **The label is a name the caller sends, and the server owns what it means.** `dial` sends the name; the broker authorizes it; frps routes on it. | Keeps naming policy on the server, so a client is never patched when routing changes. |
| 4 | **An frp location carries a trailing boundary**: `locations = ["/<label>/"]`. | frp matches a location by `strings.HasPrefix`. Without the boundary, `/alice/` would never be written but `/alice` would swallow `/alicex/` and send another user's session to the wrong bridge. |
| 5 | **`NewProxy` accepts an SSH proxy only when its one location is exactly its own label's.** | A publisher could otherwise register another owner's location and receive that owner's session; frps would then conflict on the second registration, but the broker must refuse it first. |
| 6 | **The CLI takes the alias suffix out of the picture**: `Host *.layertwo.lan` + `ProxyCommand tunnel dial %n`, and `dial` treats everything before the first dot as the label. | The alias domain is the user's private convention. The service cannot know it, so the client stops at the first dot and sends the label verbatim, needing no stored handle. |
| 7 | **Sharing, bearer auth, the bridge, the `[ssh]` section and the CLI's `--ssh`/`--target` flags are unchanged.** | This change is about the address, not about what SSH is. |
| 8 | **A clean replacement, no dual acceptance.** The broker accepts only the shared host plus a location, and `/authz` only the exact host; the old per-label shape is refused outright. Broker, CLI and homelab move together. | SSH has no homelab route yet (`docs/design.md`, "SSH"), so no old-style tunnel is live and there is no transition window to serve. Both halves fail closed, so refusing the old shape is safe as well as simpler. |
| 9 | **An `SSH_DOMAIN` that is, or lies under, `SITES_DOMAIN` is a startup error naming the variable.** | The SSH host is now the constant `SSH_DOMAIN`. If the sites domain claimed that name, `decide`'s site-first dispatch would serve it as a site and SSH would be silently dead, with a bearer token denied as a site. The old equality check no longer covers the failure. |
| 10 | **`up --ssh` prints the label and points at `tunnel ssh-config`; neither it nor the server ever learns the alias domain.** | `up` runs on the publishing box; the alias domain belongs to the machine that connects, which is usually a different machine. `ssh-config --alias-domain` runs where that convention is real, and a hint baked from the wrong machine's preference is worse than a pointer. |

## The routing key

frp v0.71.0, `pkg/util/vhost/router.go`:

- `Add(domain, location, httpUser, payload)` returns `ErrRouterConfigConflict` when the triple is
  already registered. Two tunnels therefore cannot claim the same domain and location.
- Registrations are sorted by location, **descending**, so the longest location is tried first and
  `getLocked` returns the first whose location is a prefix of the path.

One domain, one location per tunnel, longest boundary first:

```
domain                        location        tunnel
ssh.tunnels.layertwo.dev      /alice/         alice's default tunnel
ssh.tunnels.layertwo.dev      /alice-box1/    alice's box1
ssh.tunnels.layertwo.dev      /bob/           bob's default tunnel
```

Request `/alice-box1/` matches `/alice-box1/` (longest first), never `/alice/`. Request `/alicex/`
matches neither and frps answers 404. The broker reads the same bytes - the first path segment of
`X-Forwarded-Uri` - so the two always agree on which tunnel a request names.

## Architecture

```
                                  cluster (homelab)                       publisher machine
terminal ─▶ tunnel CLI ─wss(+bearer)─▶ Traefik ──▶ frps :8080 ──▶ agent bridge ──▶ target (127.0.0.1:22)
             dial <label>            Host(ssh…)             (domain +          (frpc work conn)
             path /<label>/          forwardAuth →          location
                                     broker /authz          /<label>/)
```

Nothing new listens. The stream still rides `vhostHTTPPort` (8080) through the same Traefik that
serves sites. frps still has one custom domain for the whole feature; what changed is that every
tunnel shares it and is told apart by the location.

## Flows

### Publish (`tunnel up PORT --ssh`)

1. The CLI starts the WebSocket bridge on `127.0.0.1:<random>`, dialling the target.
2. It builds the frp client with one `http` proxy: `name=<handle>.<name>`,
   `customDomains=["<SSH_DOMAIN>"]`, `locations=["/<label>/"]`, `localIP=127.0.0.1`,
   `localPort=<bridge>`, `requestHeaders.set.x-forwarded-proto="https"`.
3. The broker's `NewProxy` hook accepts `http` when the one custom domain is exactly `SSH_DOMAIN`
   and the one location is exactly `/<label>/` for this publisher's label; it keeps the bandwidth
   limit and rejects every other protocol, domain or location.
4. The control channel is the existing wss to `tunnels.layertwo.dev:443`.
5. It prints the tunnel's label, and points at `tunnel ssh-config` for the block that reaches it.
   It never prints a hostname: the alias domain is the connecting machine's, not this one's.

### Native `ssh`

`tunnel ssh-config --alias-domain layertwo.lan` prints, once:

```
Host *.layertwo.lan
	ProxyCommand tunnel dial %n
```

1. `ssh root@alice-box1.layertwo.lan` runs `tunnel dial alice-box1.layertwo.lan`.
2. `dial` takes the first dotted component as the label (`alice-box1`), validates it as a label,
   loads the access token, opens TLS to `ssh.tunnels.layertwo.dev`, sends an upgrade for
   `/<label>/` with `Authorization: Bearer <access token>`, then pipes stdin/stdout.
3. Traefik `forwardAuth` → broker: the host is exactly `SSH_DOMAIN`, so the label is read from
   `X-Forwarded-Uri`; the token is verified (JWKS) and the owner is checked. Allow.
4. frps routes by host and location to the agent's bridge, which ignores the path and dials the
   target. Bytes flow.

`%n` is OpenSSH's "original remote hostname, as given on the command line" - the name typed, before
any `HostName` substitution. Nothing resolves `alice-box1.layertwo.lan`; the proxy answers instead.

## Auth model

| Caller | Credential | Verified by | Route chain |
|--------|-----------|-------------|-------------|
| `tunnel dial <label>` | Pocket ID access token | broker (JWKS) + owner of the label | strip-identity → forwardAuth → broker → frps |
| Anyone else | - | 403 | |

Unchanged from the previous design apart from where the label comes from. An SSH share is still not
honoured: `decideSSH` consults only the owner.

## Names

| Item | Rule |
|------|------|
| SSH host | `SSH_DOMAIN` exactly, e.g. `ssh.tunnels.layertwo.dev` (the `[ssh]` section's `domain`, env `SSH_DOMAIN` overrides) |
| Request path | `/<label>/…` where `<label> = names.Label(handle, tunnel)` |
| frp proxy name | `<handle>.<name>` (shared namespace with HTTP tunnels) |
| frp custom domain | `SSH_DOMAIN`, the same for every tunnel |
| frp location | `/<label>/`, unique per tunnel |
| Client alias | `*.<alias domain>`, the user's own convention; nothing on the server knows it |

## Repo changes

| Area | Change |
|------|--------|
| `internal/names` | replace `SSHLabel(host, domain)` with a helper that reads the label out of a request path (`/<label>/…`), reusing `ParseLabel` |
| `internal/tunnel` | `Build` publishes `customDomains=[SSH_DOMAIN]` + `locations=["/<label>/"]`; the bridge is unchanged |
| `internal/broker` | `NewProxy` requires the shared domain and the publisher's own location; `/authz` decides SSH from an exact host and reads the label from the URI; `ownsSSHProxy` grows the location argument |
| `internal/cli` | `dial NAME` (was `HOST PORT`): the label is the first dotted component; `ssh-config --alias-domain DOMAIN` prints one wildcard block |
| `docs/design.md` | the names, SSH and bootstrap sections follow the implementation |
| homelab | one DNS record, one certificate, one Traefik router |

## Infra changes (homelab repo)

- DNS: `ssh.tunnels.layertwo.dev`, **DNS-only**, one A record. The `*.ssh.` wildcard is removed.
- Certificate: one certificate for the single host from the existing DNS-01 issuer. No wildcard.
- Traefik: one `Host(ssh.tunnels.layertwo.dev)` router with `forwardAuth` only (no OIDC plugin),
  whose `authRequestHeaders` include `Authorization` so the bearer reaches the broker, and
  `X-Forwarded-Uri` so the broker sees the path. **Confirm Traefik sets that header itself before
  the route goes live** - if it does not, `/authz` sees no label and denies every SSH request,
  and the feature is dark rather than broken open.
- NetworkPolicy: unchanged. frps: unchanged - no new port, and the plugin answers as it does now.

## Threat model

| Threat | Control |
|--------|---------|
| A publisher registers another owner's location and receives their session | `NewProxy` requires the location to be this publisher's own label; frps would also refuse the duplicate `(domain, location)`, but the broker refuses first |
| A path that names a tunnel but routes elsewhere | The broker authorizes the first segment of `X-Forwarded-Uri` and frps routes on the same path, with a trailing boundary on every location; `/alicex/` matches no location at all |
| Bearer client smuggled through the browser gate | the SSH route runs `forwardAuth` only; the OIDC plugin is never in that chain |
| Stolen or forged token | frps/broker verify signature, issuer, expiry and audience; the owner check runs per connection |
| Arbitrary `(host, port)` dialled | unchanged: the target is chosen by the publisher only, and the server enforces the tunnel's name and route, not the dial target |
| Cluster compromise yields shells | unchanged: no cluster-side shell component; the cluster sees the request, not the session |

## Failure modes

| Down | Effect |
|------|--------|
| Broker | `forwardAuth` refuses; running sessions continue until the connection drops |
| Pocket ID | new terminals cannot authenticate; existing sessions continue until tokens expire |
| frps | all tunnels drop; the agent reconnects |
| Agent | that route answers 404 |

## Testing

- Unit: the path helper (label present, absent, an extra segment, a port-like suffix, a
  trailing dot, uppercase, non-ASCII); `NewProxy` accepting exactly the shared domain plus the
  publisher's own location and refusing a sibling's, a missing boundary, a second location, a
  missing domain, a site subdomain; `/authz` on the SSH host reading the label from the URI, and
  continuing to deny a bearer token on a site host and identity headers on the SSH host.
- Integration/e2e: a real frps with **two** proxies on one custom domain and different locations,
  to prove frps picks the right one and the client's path reaches the right bridge.
- Manual smoke: `ssh alice-box1.layertwo.lan` through the printed block.

## Left to the builder

- Whether the bootstrap field and the `[ssh] domain` key should be renamed now that the value is a
  host rather than a suffix. My call: keep both names; the value is documented as the host.
- The exact error text when `--alias-domain` is missing from `ssh-config`. `--alias-domain` is
  required and has no default (decision 10), but the wording is the builder's.
- Whether `ssh-config` is worth keeping at all, now that it prints two static lines.
- How `dial` reports a name that is not a valid label.

## Superseded

In [the SSH design](2026-10-10-tunnels-ssh-design.md): decision 4 (custom domains under
`*.ssh.tunnels.layertwo.dev`), the "Names and hostnames" table, the "Native `ssh`" flow, the SSH
rows of "Repo changes", the DNS/certificate/Traefik bullets of "Infra changes", and the
`/authz`/`NewProxy` wording that keyed on `<label>.<SSH_DOMAIN>`. Everything else stands.
