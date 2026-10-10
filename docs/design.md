> Copied from `layertwo/homelab` `docs/plans/2026-10-07-tunnels-design.md` at `ad1b1a8f` (PR layertwo/homelab#2447). From here on, this copy is the working design for the Go code; the homelab repo keeps the manifests.

# Tunnels - Design

## Overview

Run a multi-user tunnel service on the homelab. People publish an HTTP service from their own
machine under a stable name on `*.w.tunnels.layertwo.dev`, visitors sign in with Pocket ID, and
owners share a tunnel with other users or groups themselves. It is built from stock parts (frps,
the frp client library, Traefik, the OIDC plugin already used for mediabox and Send, Pocket ID,
CNPG) plus two small Go programs: a **broker** (frps plugin, access decisions, sharing API) and a
**CLI**.

Decisions taken during design:

- **Multi-user, enforced on the server.** Membership of `tunnels-creators` only says who may
  connect. The broker's frps plugin binds every name to the verified owner on each Login and
  NewProxy. The CLI is a convenience and gets no trust.
- **Public web, OIDC as the gate, no Tailscale or VPN.** Pocket ID is the only identity provider.
  Every site requires a login. There are no anonymous tunnels.
- **Stock frp transport.** `frps` v0.71.0 from the official image, reached over wss on 443
  through the existing external Traefik. The CLI embeds the frp client library, so end users
  install one static binary.
- **Go for both programs, in a new repo** (`layertwo/tunnels`, the kirocrew-opencode precedent),
  with the naming rules in one shared package. Python/Flask was dropped once the CLI had to be a
  static cross-platform binary.
- **Visitor login is the existing Traefik OIDC plugin.** The broker only decides access, via
  `forwardAuth` behind the plugin. It owns no login, cookie or session code.
- **Self-service sharing.** A tunnel is private to its owner by default. The owner shares it with
  Pocket ID usernames or groups through the CLI.
- **Stateless broker.** Postgres holds users and shares. Run-ID pinning and tunnel caps ask
  frps's dashboard API. Two replicas behind a PodDisruptionBudget; scaling is a manifest change.
- **Short tokens plus explicit heartbeat settings for revocation.** frp's defaults do not revoke.
- **Distroless, non-root, read-only containers.** The broker is a static Go binary on distroless.
  From phase 1, frps is the pinned official binary repackaged onto distroless. See Container
  Hardening for what that does and does not buy.
- **Names.** The service is `tunnels.layertwo.dev`; sites are
  `<handle>[-<name>].w.tunnels.layertwo.dev`. A future SSH subtree would be
  `*.ssh.tunnels.layertwo.dev`.

Facts this design depends on were verified on 2026-10-07 against the frp v0.71.0 source, the
Pocket ID v2.18.0 source and docs, Traefik's `forwardAuth` docs and the traefik-oidc-auth docs. A
spike (see Pocket ID tokens in frps) proved that frps accepts real Pocket ID tokens. Nothing has
been tested on the cluster yet; see Verification.

## Directory Structure

```
clusters/home/apps/network/tunnels/         # homelab repo: manifests only
├── namespace.yml                           # namespace: tunnels
├── kustomization.yml
├── frps/
│   ├── kustomization.yml
│   ├── secrets-frps.sops.yml               # whole frps.toml (dashboard password, plugin path secret)
│   └── release.yml                         # HelmRelease "frps" (app-template): 7000, 8080, 7500
├── broker/
│   ├── kustomization.yml
│   ├── secrets-broker.sops.yml             # plugin path secret, frps dashboard creds
│   └── release.yml                         # HelmRelease "broker"; image pinned by digest
├── postgres/
│   ├── kustomization.yml
│   └── cnpg-tunnels.yml                    # Cluster "cnpg-tunnels"
├── routes/
│   ├── kustomization.yml
│   ├── ingressroute-apex.yml               # tunnels.layertwo.dev
│   ├── ingressroute-sites.yml              # *.w.tunnels.layertwo.dev
│   ├── middlewares.yml                     # strip, oidc, authz, strip-internal, limits
│   ├── certificate.yml                     # *.w.tunnels.layertwo.dev -> tunnels-sites-tls
│   └── secrets-oidc.sops.yml               # gate client id/secret + plugin session secret
└── networkpolicy.yml

github.com/layertwo/tunnels (new repo)
├── go.mod                                  # github.com/fatedier/frp pinned to the frps image version
├── cmd/broker/                             # plugin, /authz, /api, /.well-known, /healthz
├── cmd/tunnel/                             # CLI
├── internal/names/                         # handle, name and label rules, shared by both
├── internal/...                            # hooks, authz, store (pgx + embedded migrations),
│                                           # identity-provider client (internal/idp), frp config builder, token store
├── Dockerfile.broker                       # broker image: distroless static, non-root
├── Dockerfile.frps                         # pinned official frps binary on distroless (phase 1 on)
└── .github/workflows/{ci,image,release}.yml
```

## Architecture Decisions

### Enforcement lives on the server

`tunnels-creators` is coarse: it says who may try to connect, not which names they may take. In
plain frp a creator could claim any free name, including `alice-*` while alice is offline.
Behaviour read from the frp v0.71.0 source that shapes the plugin:

- The Login hook runs before frps verifies the token (`server/service.go` 461 vs 811), and the
  verifier then checks the possibly rewritten message. The broker therefore calls Pocket ID
  itself and never trusts claims it did not fetch.
- The NewProxy hook receives the `user` stored from Login (`server/control.go`
  `loginUserInfo`), not a value re-sent by the client. Setting `user = handle` at Login makes it
  trustworthy at NewProxy.
- A second registration of a taken vhost fails with `router config conflict`, so a live tunnel
  cannot be displaced by name.
- A Login that carries an existing run ID replaces that control connection (`RegisterControl`),
  and the code read has no check that the user matches. The plugin must close this.
- frpc strips its own `user` prefix from `NewProxyResp.ProxyName` to find the proxy
  (`client/control.go:169`). A plugin that renames proxies breaks the client, so the plugin
  enforces names and never rewrites them.

### Pocket ID tokens in frps (spiked)

A throwaway harness (branch `spike/frp-pocket-id`, uncommitted) ran the official frps and frpc
images against idp.layertwo.dev. All nine checks passed.

| Token | Obtained by | `aud` | Identity claims |
|-------|-------------|-------|-----------------|
| access, machine | client_credentials + `resource` | API resource | none (`sub` = `client-<id>`) |
| access, user | device flow + `resource` | API resource, client id, issuer URL | none (`sub` = user id) |
| ID, user | device flow | client id | `preferred_username`, `groups`, `name`, ... |

- frps `auth.oidc.audience` is the API resource `https://tunnels.layertwo.dev`. That accepts
  machine and user access tokens and, from the observed `aud` values, refuses ID tokens. It is
  never empty (frps skips the audience check when it is) and never the issuer URL (every user
  access token carries it).
- User access tokens carry no username or groups, so the broker resolves them with Pocket ID's
  userinfo endpoint.
- Access tokens last one hour. Pocket ID rechecks group membership on every refresh.
- A permission key on the API is not needed; API access on the client is enough.

### Revocation needs explicit settings

By default frp does not revoke. With tcpMux on, frpc sends no heartbeats, frps has no heartbeat
timeout, and a failed ping only returns an error without closing the connection. To end a tunnel
whose token expired or was revoked:

- client `transport.heartbeatInterval = 30`, generated by the CLI;
- server `transport.heartbeatTimeout = 90`, so a client that sends no valid pings is dropped;
- `auth.additionalScopes = ["HeartBeats", "NewWorkConns"]` on both sides.

`NewWorkConns` is there for a different reason than revocation. A work connection is a new TCP
connection, and frps finds its control by run ID alone; without the scope it asks for no token at
all, so anybody who knew a run ID could queue connections into that session and be handed the
owner's visitors' requests, cookies included (reproduced against a real frps in the Tasks 4-8
review). With the scope frps verifies a valid token on every work connection. It does not bind that
token to this control: frp accepts any token whose subject has logged in since frps started, so a
creator who learned another creator's run ID could still inject. Run IDs are therefore kept out
of logs and errors. The broker's `NewWorkConn` hook (implemented) is what binds a work connection
to a control user: it checks the connection's token against the `user.user` Login set, and
enabling it is adding `"NewWorkConn"` to frps's plugin `ops`, exactly as `Ping` is enabled.

Each ping re-reads a file token source, so the CLI keeps the token file fresh. Removing someone
from `tunnels-creators` or disabling the account stops refresh, and the tunnel ends about an hour
plus 90 seconds later.

The broker's Ping hook closes that window to one heartbeat. frps calls the plugin's `Ping` op on
every heartbeat; the broker re-resolves the token and rejects the ping when the account is disabled
or no longer in the creators group, and frpc then closes the session. It rejects only an account
refusal: a token the broker cannot verify (invalid, expired, or Pocket ID unreachable) is allowed
and left to frps, which re-verifies the ping's token itself, so a key we cannot fetch does not tear
down a session frps would have accepted. Enabling it is adding `"Ping"` to `[[httpPlugins]].ops` in
`frps.toml`; `"Ping"` has been in `ops` since v0.2.0 (homelab #2486), and `"NewWorkConn"` is enabled
by adding it to `ops` with the next release.

`tunnel logout` only deletes the token files on that computer. Pocket ID publishes no token
revocation endpoint (its discovery document lists none), so a copied refresh token stays good
until it expires: ending a session for certain is done in Pocket ID (remove the person from
`tunnels-creators`, or disable the account), as above.

### The control channel must verify the server certificate

`pkg/transport/tls.go` (`NewClientTLSConfig`) sets `InsecureSkipVerify = true` whenever no CA file
is given, and both the tls and wss dial paths in `client/connector.go` use it. By default frpc
therefore accepts any certificate, and a man-in-the-middle on the control channel could capture
the bearer token (valid for an hour, long enough to log in as that user). Every client sets
`transport.tls.trustedCaFile`. Phase 0 tester configs point at the operating system's CA bundle.
The CLI embeds a root CA bundle, writes it beside the token file, and sets `trustedCaFile` to it.

### The visitor gate: the plugin authenticates, the broker authorizes

```
strip identity headers -> traefik-oidc-auth -> forwardAuth(broker /authz)
  -> strip internal headers -> rateLimit/inFlightReq -> frps :8080
```

- The OIDC plugin (already trusted for six apps) does login, PKCE, sessions and cookies, and
  passes `sub`, `preferred_username` and `groups` to the next hop as headers.
- The broker's `/authz` answers allow or deny from Host plus those headers. It holds no session
  state and needs no Kubernetes permissions.
- Traefik returns a non-2xx auth response to the client as-is and copies `authResponseHeaders`
  onto the request, replacing existing ones. `trustForwardHeader` stays off, so the Host the
  broker sees is computed by Traefik.

Rejected: generating a Traefik route and middleware per share from the broker. It needs RBAC that
can route any hostname (a compromise could hijack `idp.layertwo.dev`), and one `AssertClaims`
list cannot express "this user or that group". Also rejected: stock forward-auth tools
(traefik-forward-auth v4, OAuth2 Proxy, Tinyauth). Their conditions are static per middleware
and cannot see the host.

### Names, zones and the shared domain

- The apex `tunnels.layertwo.dev` is the service: control channel, API, bootstrap. Sites live
  in their own subtree, `w.tunnels.layertwo.dev`, so users can only ever name things under it
  and the service can add hosts (`status.tunnels...`) without a reserved-name list.
- One subtree per protocol. frps has a single `subDomainHost` (here `w.tunnels.layertwo.dev`)
  and frp's README says custom domains should not be subdomains of it. A future
  `*.ssh.tunnels.layertwo.dev` therefore stays clear of it. SSH carries no hostname, so it needs
  its own routing design (frp tcpmux over HTTP CONNECT, or SNI) and is out of scope here.
- Cloudflare's free certificate covers one level below `layertwo.dev`, so `*.w.tunnels.layertwo.dev`
  is a DNS-only record with its own cert-manager wildcard certificate. The apex is one level
  and can stay proxied. The home IP is already public (`send.layertwo.dev` resolves to it), but
  site traffic bypasses Cloudflare's protection.
- Accepted caveat: sites share the registrable domain `layertwo.dev` with your apps. The
  entrypoint CORS rule `^(.+)\.layertwo\.dev$` matches `x.w.tunnels.layertwo.dev`, so every site
  origin is on every app's cross-origin allow-list (credentials are not allowed by that
  middleware). Pocket ID's session cookies are `__Host-` prefixed (v2.18.0 source); ours are
  `__Secure-` prefixed for now (Verification 5). Other apps' cookies were not audited. The sites domain is one setting
  (`SITES_DOMAIN`); moving to a separate registrable domain, where sites sit one level down and
  can be proxied, is a config, DNS and certificate change.

### Go, with the frp client embedded

- Embedding `github.com/fatedier/frp/client` is common: a GitHub code search (capped at 100 files)
  finds 66 repositories importing it, mostly frp forks. About ten non-fork projects (AlistGo/alist, koho/frpmgr, bilirec, podux, Android wrappers) already use
  the current API, and the maintainer calls it common usage. The web-asset embed that breaks
  building frp from source lives in `web/frpc`, imported only by `cmd/frpc`.
- frp's own release ships 17 OS/arch targets and its Dockerfile builds with `CGO_ENABLED=0`.
  Pangolin's CLI (`fosrl/cli`) is a Go device-login CLI with an embedded tunnel client shipped
  as multi-platform binaries.
- Costs: the client API is not stable (`ServiceOptions` swapped `ProxyCfgs`/`VisitorCfgs` for
  `ConfigSourceAggregator` and `UnsafeFeatures` between v0.65 and v0.68), so the module is pinned
  to the frps image version and both are bumped together. Issue #5557 (filed 2026-10-07) reports
  data races in the client, one a possible nil dereference on shutdown or reconnect; stock frpc
  has the same code. After the first login the service reconnects by itself, so the CLI has no
  restart loop of its own. The library builds auth
  from config only, so tokens still reach it through a file.
- Go 1.25 or newer is required by frp's go.mod. `proxy.golang.org` does not resolve from the
  design machine's network, so local builds there need `GOPROXY=direct`; CI is unaffected.

### Stateless broker

| State | Where it lives |
|-------|----------------|
| users, shares | Postgres (`cnpg-tunnels`) |
| run-ID ownership, per-user tunnel count | frps dashboard API v2 (`/api/v2/clients?runID=`, `/api/v2/proxies?user=`) |
| visitor sessions | the OIDC plugin's cookies |
| share and user cache | none in phase 1: one primary-key lookup per request (a ~5 s per-replica cache if latency asks for it) |

No leader election and no sticky sessions: a ClusterIP Service in front of N replicas serves both
Traefik and frps. Concurrent first logins are safe through the unique-handle constraint and an
upsert. Migrations are embedded and applied under an advisory lock. The deploy runs two replicas
behind a PodDisruptionBudget; raising that, and CNPG to 2-3 instances, is a manifest change. frps
itself cannot be load balanced: a tunnel is a live connection held by one process, so its HA is
fast restart, not replicas.

### Later: frps HA by client fan-out

A tunnel lives inside one frps process, so an frps restart drops every tunnel and the CLI
reconnects. To make frps restarts unobservable, fan the **client** out instead of the server:

- The CLI runs one frp client per frps instance, each dialing a **pinned** control endpoint
  (`frps-N.…`), so every frps holds the route for the tunnel.
- Traefik keeps the single `*.w.…` route to a Service that spans the frps instances; because
  every pod knows the host, a request is served whichever ready pod it reaches.
- A rolling restart then removes one pod's sessions at a time while the others keep serving, and
  the client reconnects to the restarted pod. Zero downtime, with stock frp throughout.

What it costs, and why it is a later, not a now:

- **Pinned endpoints.** The N sessions must land on N distinct pods, so there is one control
  hostname (and IngressRoute) per frps; a load-balanced `/~!frp` does not guarantee coverage.
- **Broker accounting across instances.** `MAX_TUNNELS_PER_USER` and the run-ID ownership check
  query one frps dashboard; with N instances they are per-instance, so the cap multiplies unless
  the broker sums across all dashboards.
- **CLI.** `tunnel.Run` starts N `client.Service`s from an endpoint list in
  `/.well-known/tunnels.json`, sharing one token file, refresher and CA bundle.
- **Spike first.** Whether frp's client runs two `Service`s in one process against two different
  servers without interference is unproven here (the tests run many against one).

It buys nothing for broker restarts (already HA by replicas, see above) and nothing when frps
rarely changes.

## Names and Hostnames

| Item | Rule |
|------|------|
| Handle | the lowercased Pocket ID username, if it then matches `^[a-z0-9]{2,20}$`. Assigned at first login, never changed, unique. Otherwise login is refused with a message. |
| Tunnel name | `^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$` (1-42 characters). `default` is reserved. Omitted means the default tunnel. |
| Site label | `<handle>` (default tunnel) or `<handle>-<name>`, at most 63 characters. The owner is the text before the first dash, which is unambiguous because handles contain no dash. |
| Site FQDN | `<label>.w.tunnels.layertwo.dev` |
| frp proxy name | `<handle>.<name>`; the default tunnel uses `<handle>.default`. The CLI sets `user = <handle>`, so frpc adds the prefix itself. |

Pocket ID usernames may contain `_ . @ -`, which are not valid in a handle (capitals are
lowercased), so such accounts are refused with a message. A small reserved list (`admin`, `root`,
`support`, `security`) blocks look-alike handles. Ownership is matched by `sub`, never by name,
so a rename or a reused username cannot hand a tunnel to someone else.

## frps

Official image `ghcr.io/fatedier/frps:v0.71.0` (upstream pushes the same digest to Docker Hub and
ghcr; we pull from ghcr) pinned by digest in phase 0. From phase 1 the
same binary is repackaged as `ghcr.io/layertwo/tunnels-frps` on distroless (see Container
Hardening). Deployed with app-template.
`frps.toml` lives in a SOPS Secret (it holds the dashboard password and plugin path secret):

```toml
bindPort = 7000                    # control channel; wss arrives here from Traefik
vhostHTTPPort = 8080               # site traffic from Traefik
subDomainHost = "w.tunnels.layertwo.dev"

auth.method = "oidc"
auth.oidc.issuer = "https://idp.layertwo.dev"
auth.oidc.audience = "https://tunnels.layertwo.dev"
auth.additionalScopes = ["HeartBeats", "NewWorkConns"]
transport.heartbeatTimeout = 90

webServer.addr = "0.0.0.0"         # reachable only from the broker (NetworkPolicy)
webServer.port = 7500
webServer.user = "broker"
webServer.password = "<from SOPS>"
enablePrometheus = true

[[httpPlugins]]
name = "broker"
addr = "broker.tunnels.svc:8080"
path = "/plugin/<secret>"
ops = ["Login", "NewProxy", "CloseProxy", "Ping", "NewWorkConn"]
```

Plugin rejections surface in the CLI as the reject reason (`detailedErrorsToClient` stays on).
Non-http proxy types are refused by the plugin, so no TCP or UDP port is ever opened.

## Broker

One Go binary, distroless static image `ghcr.io/layertwo/tunnels-broker` (linux/amd64 and
linux/arm64), signed with cosign.

| Path | Caller | Purpose |
|------|--------|---------|
| `/plugin/<secret>` | frps only | Login, NewProxy, CloseProxy, Ping, NewWorkConn hooks |
| `/authz` | Traefik `forwardAuth` | allow or deny one visitor request |
| `/api/me`; `/api/shares` in phase 2 | CLI, bearer token | ensure user, manage shares |
| `/.well-known/tunnels.json` | anyone | bootstrap: issuer, CLI client id, API resource, service host, sites domain, minimum CLI version |
| `/install.sh` (later), `/healthz` | anyone | installer, probe |

`/plugin` is never routed by Traefik.

**Login hook.** Call Pocket ID userinfo with the token (`sub`, `preferred_username`, `groups`);
invalid tokens fail here and frps then verifies signature, audience and expiry. Require
`tunnels-creators`. Resolve the handle from `users` by `sub`, or derive and insert it; refuse if
disabled or unsuitable. If the Login carries a run ID, ask frps whether that run ID is online
under a different user and reject if so. Return the content with `user` set to the handle. The hook never modifies `privilege_key`: frps
verifies that same token right after, which is what makes any claim the broker reads from it
safe. (Phase 3: a machine token is recognised by its `client-` subject, skips userinfo, and its
`client_id` claim maps to a handle from configuration.)

**NewProxy hook.** The type must be http with no custom domains or locations. `proxy_name` must
be `<handle>.<n>` and `subdomain` must be `<handle>` (n = `default`) or `<handle>-<n>` (n a valid
name). Count the user's proxies on frps and refuse above `MAX_TUNNELS_PER_USER`. Set the
bandwidth limit to `DEFAULT_BANDWIDTH_LIMIT` with mode `server`. **CloseProxy** only logs.

**`/authz`.** Compute the label from `X-Forwarded-Host` (outside the sites domain or malformed:
deny). Find the owner row by handle. Allow if the visitor's `sub` equals the owner's `sub`, or a
`shares(owner, tunnel, kind='user')` row matches the visitor's username (case-insensitive), or a
`kind='group'` row matches one of the visitor's groups. Everything else, including an unknown
owner, is the same 403. On allow, answer 200 with `X-Tunnel-User: <username>`, which the app
sees. A group name containing a comma is unsupported (groups travel comma-separated).

**API.** Bearer access token verified locally against Pocket ID's JWKS (issuer, audience,
expiry). `GET /api/me` repeats the Login hook's userinfo and handle logic, so the CLI learns its
handle at `tunnel login`. `GET`, `PUT` and `DELETE /api/shares` take `{tunnel, kind, grantee}`;
PUT also takes an optional absolute RFC3339 `expires_at`, which must be in the future or the
request is a 400. PUT and DELETE are idempotent.

**Data model.**

```sql
users  (sub text primary key, handle text unique not null, disabled bool not null default false,
        created_at timestamptz not null default now())
shares (owner_sub text references users(sub) on delete cascade,
        tunnel text not null default '',                       -- '' = default tunnel
        kind text check (kind in ('user','group')), grantee text not null,
        created_at timestamptz not null default now(),
        expires_at timestamptz,                                -- null = never
        primary key (owner_sub, tunnel, kind, grantee))
```

Sharing with the group `tunnels-viewers` means every viewer.

**Configuration** (environment): `SERVICE_HOST`, `SITES_DOMAIN`, `ISSUER`, `API_RESOURCE`,
`CREATORS_GROUP`, `DATABASE_URL`, `FRPS_DASHBOARD_URL`, `FRPS_DASHBOARD_USER`,
`FRPS_DASHBOARD_PASSWORD`, `PLUGIN_SECRET`, `MAX_TUNNELS_PER_USER` (5),
`DEFAULT_BANDWIDTH_LIMIT` (10MB per second, frp's format), `RESERVED_HANDLES`, `LOG_LEVEL`. Logs are structured JSON for
logins, proxy registrations, denials and share changes, and never contain tokens. Outbound
requests carry an explicit User-Agent. `DATABASE_URL` comes from the CNPG-generated secret
`cnpg-tunnels-app` (key `uri`); the rest come from `secrets-broker.sops.yml` and the
HelmRelease values.

## CLI

One static Go binary named `tunnel`, with the frp client embedded. The default server is baked in
at build time (`-ldflags`), so users type no URL.

```
tunnel login                       device flow against Pocket ID; tokens stored 0600
tunnel up 3000 [--name blog]       prints https://alice-blog.w.tunnels.layertwo.dev and stays up
tunnel share --name blog bob       --group family shares with a Pocket ID group
tunnel unshare --name blog bob
tunnel list                        your shares
tunnel logout
tunnel version
```

- **login:** reads `/.well-known/tunnels.json`, runs the device flow with the public client
  `tunnels-cli` (scopes `openid profile groups offline_access`, `resource` = the API), then
  calls `/api/me` for the handle.
- **up:** builds the frp client config in memory and loads it in strict mode, as frpc does: wss
  to `tunnels.layertwo.dev:443`, `user = <handle>`, `auth.method = "oidc"` with a file token
  source, `auth.additionalScopes = ["HeartBeats", "NewWorkConns"]`, `transport.heartbeatInterval = 30`,
  `transport.tls.trustedCaFile` (an embedded root bundle written beside the token file), one http
  proxy with `subdomain` and `localIP`/`localPort`. A goroutine refreshes the token every ~30
  minutes and rewrites the token file atomically (temp file plus rename, mode 0600). After the
  first login frp reconnects by itself and reads the latest token from the file; a refused first
  login ends `tunnel up` with the broker's reason.
- **share, unshare, list:** HTTPS calls to `/api/shares` with the access token.
- **Distribution:** GitHub Releases for darwin, linux and windows on amd64 and arm64, plus
  linux/arm. `CGO_ENABLED=0 -trimpath -ldflags "-s -w -X main.version=... -X main.defaultServer=..."`.
  A checksums file and a signed build provenance ship with each release. Later,
  `https://tunnels.layertwo.dev/install.sh` (served by the broker) picks the right binary, verifies
  its SHA-256 and installs it to `~/.local/bin`.
  Binaries fetched with curl avoid macOS quarantine; one downloaded in a browser will show the
  unsigned-binary warning.

## Pocket ID

Manual in the UI, as the rest of the repo does today.

- **API** "Tunnels", resource `https://tunnels.layertwo.dev`. No permission keys.
- **Groups** `tunnels-creators`, `tunnels-viewers`. Signup links can auto-join groups.
- **Client `tunnels-cli`:** public, device flow, user-delegated access to the API, allowed group
  `tunnels-creators`. Skip consent stays off, because it would hide the client and its scopes on
  the device page. PKCE does not apply to the device flow.
- **Client `tunnels-gate`:** confidential, authorization code with PKCE, allowed groups
  `tunnels-viewers` and `tunnels-creators`, callback `https://*.w.tunnels.layertwo.dev/oidc/callback`.
  Used only by the Traefik plugin. Its id and secret go into `secrets-oidc.sops.yml`.
- **Machine clients** (headless servers, phase 3): confidential, client access to the API, with
  a config mapping client id to handle.

## Networking and TLS

```
tunnels.layertwo.dev                      proxied; covered by the existing *.layertwo.dev certificate
  /~!frp                         ->  frps :7000
  everything else                ->  broker
*.w.tunnels.layertwo.dev                  DNS-only wildcard; certificate tunnels-sites-tls
  tunnels-strip-identity -> tunnels-oidc -> tunnels-authz -> tunnels-strip-internal
    -> tunnels-limits -> frps :8080
```

- Both IngressRoutes use class `external`; the OIDC plugin is registered only there.
- **Middlewares** (namespace `tunnels`): `tunnels-strip-identity` blanks `X-Tunnels-Sub`,
  `X-Tunnels-User`, `X-Tunnels-Groups` and `X-Tunnel-User` so a client cannot supply them.
  `tunnels-oidc` is the plugin: `UsePkce`, a `__Secure-` cookie prefix, claims asserted to include
  `tunnels-viewers` or `tunnels-creators`, and `Headers` that set the three `X-Tunnels-*` values.
  `tunnels-authz` is `forwardAuth` to `http://broker.tunnels.svc:8080/authz` with
  `authResponseHeaders: [X-Tunnel-User]`. `tunnels-strip-internal` removes `X-Tunnels-*` again,
  so the creator's app sees only `X-Tunnel-User`. `tunnels-limits` is `rateLimit` keyed on the
  request host plus `inFlightReq`.
- **DNS:** external-dns annotations create the apex (proxied) and the wildcard
  (`cloudflare-proxied: "false"`), the same pattern as send and immich.
- **TLS:** an explicit `Certificate` `tunnels-sites` for `*.w.tunnels.layertwo.dev` with the
  existing DNS-01 issuer. The sites route sets `tls.secretName: tunnels-sites-tls` (same
  namespace, as the garage routes do), which also satisfies `sniStrict`.
- **NetworkPolicy:** default deny ingress in `tunnels`. Allow Traefik to frps 7000 and 8080 and
  to the broker 8080; frps to the broker (`/plugin`); the broker to frps 7500; the broker to
  Postgres. Egress for frps and the broker is limited to DNS, each other, Postgres and Pocket
  ID. frps never dials creators; they dial in.
- **Entrypoint headers** (`secure-headers-middleware`) apply to every site: HSTS preload,
  `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: same-origin`. The strict CSP in that
  middleware is currently not emitted on live responses (checked on idp and send), so it does
  not break sites today. If it ever starts being emitted it would break every tunneled app.
- **Monitoring:** a Gatus check on `https://tunnels.layertwo.dev/healthz`; frps metrics are
  exposed on 7500.

## Container Hardening

- **Broker:** a static Go binary (`CGO_ENABLED=0`) on `gcr.io/distroless/static:nonroot`
  (uid 65532), pinned by digest. No shell, no package manager. The base image carries the CA
  certificates needed for Pocket ID over TLS. Probes are HTTP only, with no exec probes, and
  debugging uses an ephemeral container (`kubectl debug`), not a shell in the image.
- **frps:** the official v0.71.0 image is `alpine:3` plus tzdata, and the Dockerfile sets no
  `USER`, so it runs as root. The binary is built with `CGO_ENABLED=0`, so it runs unchanged on
  distroless. From phase 1 the `tunnels` repo publishes `tunnels-frps`: a short Dockerfile
  that copies `/usr/bin/frps` out of the digest-pinned official image onto
  `gcr.io/distroless/static:nonroot`, signed like the broker. It costs one more image to own, and
  removes the shell and busybox from the pod that parses internet-facing traffic. Phase 0 uses
  the official image with the pod settings below.
- **Pod settings, both workloads:** `runAsNonRoot` with an explicit uid and gid,
  `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]` (every port is above 1024),
  `readOnlyRootFilesystem: true`, `seccompProfile: RuntimeDefault`,
  `automountServiceAccountToken: false`, `hostUsers: false` where the cluster supports it (the
  reticulum design notes it is feasible when no NFS volumes are mounted; only Secrets are mounted
  here), no host networking, resource limits, and the NetworkPolicy above. This extends what the
  oidc-saml-bridge release already sets (read-only root filesystem, dropped capabilities, no
  privilege escalation).
- **What this buys:** distroless removes the tools an attacker would use after code execution
  (shell, curl, package manager). It does not stop a kernel or runtime escape. The pod settings,
  above all the unprivileged user, dropped capabilities, seccomp and the user namespace, are what
  narrow that. Neither helps against the process's own legitimate reach (frps can call the
  broker, the broker holds database credentials); the NetworkPolicy and least-privilege secrets
  cover that.

## Security

| Threat | Control |
|--------|---------|
| Creator claims or squats another user's name | plugin binds `user` to the verified handle; NewProxy enforces the `<handle>.` proxy name and `<handle>[-<name>]` subdomain; duplicates fail in frps |
| Somebody takes a handle before its owner logs in | a handle is the username of whoever logs in with it first, then belongs to that `sub` for good; keep self-service username changes off in Pocket ID, so nobody can rename themselves into a name that is not theirs |
| Creator takes over a live control connection | Login with a run ID is refused if frps shows it online under another user |
| Non-http exposure, custom domains | plugin allows only http proxies with no custom domains or locations |
| Forged or stolen-for-another-audience token | frps verifies signature, issuer, expiry and audience (API resource); userinfo must also succeed |
| Man-in-the-middle on the control channel captures a token | frp skips certificate verification unless `trustedCaFile` is set; every client config sets it and the CLI embeds a CA bundle |
| Revoked creator keeps a tunnel | 1 h tokens, refresh stops, heartbeats (30 s / 90 s) end the tunnel; Ping hook (implemented) rejects a disabled or non-creator account on the next heartbeat once `"Ping"` is added to the plugin `ops` |
| Visitor spoofs identity headers | stripped before the plugin; set only by the plugin; internal ones removed before the app |
| Creator's app steals a visitor session | the plugin's cookie is host-only and not forwarded upstream; the app sees only `X-Tunnel-User` |
| Access to another user's tunnel | `/authz` denies by default; owner by `sub`; shares by username or group |
| Plugin endpoint abused | not routed; NetworkPolicy plus a secret path |
| Broker compromise | no Kubernetes RBAC; a compromise affects tunnels, not other hostnames |
| Abuse, load | per-host rate and in-flight limits; per-proxy bandwidth limit; per-user cap |
| Cross-tunnel same-site requests | `__Secure-` cookies (`__Host-` once the plugin keeps the PKCE verifier out of a cookie); `/authz` refuses a state-changing request whose `Origin` is another owner's sites host (a missing or foreign `Origin` is allowed; `Sec-Fetch-Site` is not used) |
| Supply chain | digest-pinned images, cosign-signed broker and frps images, checksummed CLI releases, frp pinned |
| Code execution inside a pod | distroless images (no shell), non-root, read-only root filesystem, capabilities dropped, seccomp, user namespace, no service-account token, NetworkPolicy; see Container Hardening |

## Failure Modes

All of them fail closed.

| Down | Effect |
|------|--------|
| Broker | New logins and tunnels refused; visitors get a 5xx; running tunnels continue |
| Pocket ID | New logins fail; tunnels run until their token expires (up to an hour), then drop |
| Postgres | `/authz` answers 503 at once (there is no cache); hooks refuse logins |
| frps restart | all tunnels drop; the CLI reconnects with a fresh token |
| Name taken, bad handle | the CLI prints the reject reason |

## Testing

- **Unit tests** (Go, table-driven) on the code where a bug is a security hole: the names
  package, the five plugin ops (Login, NewProxy, CloseProxy, Ping, NewWorkConn), the `/authz`
  matrix (owner, shared user, shared group, case
  folding, default deny), the share API, token refresh.
- **Integration test**, seeded from the spike: the official frps image, the broker and the CLI
  against a mock OIDC issuer. It asserts a stolen name, a wrong audience, an expired token, run-ID
  takeover and revocation by heartbeat.
- **Smoke test** after deploy: a test creator and a test viewer through the real path.

### Verify a deploy

- `kubectl -n tunnels get deploy broker` shows `2/2`, and `kubectl -n tunnels get pdb broker`
  shows `MIN AVAILABLE 1`.
- frps's plugin `ops` includes `"Ping"` (deployed in v0.2.0, homelab #2486) and picks up
  `"NewWorkConn"` with the next release, once this branch's broker image is pinned.
- A user share: a second account reaches the site, and `tunnel unshare` denies that visitor on
  their next request (the share row is gone and `/authz` has no cache).
- A revoked creator's tunnel: remove them from `tunnels-creators` (or disable the account) and
  the tunnel ends within one heartbeat (the Ping hook, backed by the `HeartBeats` scope).
- A group share: a member of the group reaches the site (needs the gate to forward
  `X-Tunnels-Groups`).
- A cross-owner state-changing request: a `POST` to `alice-blog.w.tunnels.layertwo.dev` with
  `Origin: https://bob-x.w.tunnels.layertwo.dev` is refused, while a `GET` or an `Origin`-less
  request is allowed.
- The `NewWorkConn` hook is dormant until `"NewWorkConn"` is added to frps's `ops` with the next
  release, once the broker image containing it is pinned; `"Ping"` is already enabled.

## Phasing

- **Phase 0 (optional, no custom code):** a machine client, stock `frpc`, and the existing OIDC
  plugin as a global gate. It proves the cluster-side unknowns in Verification before any Go.
  Names are trust-based at this stage.
- **Phase 1:** the plugin hooks, owner-only `/authz`, `tunnel login` and `tunnel up`, releases.
  Creators cannot touch each other from here on. The repo also publishes `tunnels-frps`.
- **Phase 2 (implemented):** sharing: the shares table, `/api/shares`, `share`, `unshare`, `list`.
  A group share works only once the gate forwards the visitor's groups to `/authz` as
  `X-Tunnels-Groups` (a deferred homelab change); until then the header is stripped and group
  shares admit no one. User shares work today.
- **Phase 3:** hardening: heartbeat revocation proven end to end, the Ping-hook kill switch
  (implemented; enabling it is the frps `ops` change), tuned limits, Gatus, docs, machine
  clients.
- **Later:** SSH, a web UI, live tunnel status, frps HA by client fan-out.

## Verification

Each item is a build-time check with a stated fallback.

1. wss through Cloudflare and Traefik stays up for an hour across token refresh with 30 s
   heartbeats. Fallback: make the apex DNS-only.
2. external-dns creates the DNS-only wildcard from an annotation. Fallback: create the record by
   hand or with a `DNSEndpoint`.
3. cert-manager issues `*.w.tunnels.layertwo.dev` and Traefik serves it under `sniStrict`.
4. Pocket ID accepts the wildcard callback `https://*.w.tunnels.layertwo.dev/oidc/callback`.
   Fallback: the broker owns login (the earlier design).
5. The plugin accepts a `__Host-` cookie prefix, does not forward its cookie upstream, passes
   its headers to the next middleware, and the claim templating (`sub`, `preferred_username`,
   `groups`) works. Fallback for the prefix: document prefix-less cookies.
   *Answered locally (2026-10-08, real Traefik v3.7.13 + plugin v0.21.0, mock IdP):* everything
   works except the prefix. With PKCE the plugin sets its `CodeVerifier` cookie on
   `Path=/oidc/callback`, so browsers reject it under `__Host-` and login cannot complete.
   Chosen fallback: `__Secure-tunnels` (keeps PKCE, which is the plugin's only binding of a login
   to a browser). Upstream moved the verifier into the OIDC state in
   sevensolutions/traefik-oidc-auth#283 (merged 2026-08-01, unreleased); switch back to
   `__Host-` after that release. Gate cookies are stripped before the app, and two groups arrive
   as two values of one `X-Tunnels-Groups` header.
6. Pocket ID userinfo accepts the device-flow access token. Fallback: the CLI sends the ID
   token and frps's audience becomes the CLI client id.
7. A public-client device flow completes without a secret, and refresh keeps the audience and
   rechecks groups.
8. frps's dashboard API (v0.71.0) answers `/api/clients?runId=` and lists proxies with `user`
   to the broker. Fallback: keep run-ID and cap state in Postgres and drop to a single broker
   replica (the deployed default is two).
9. The embedded client builds with `CGO_ENABLED=0` for every release target and connects to the
   official frps image using a file token source.
10. Cross-user tests pass: a stolen name and a run-ID takeover are both refused.
11. Heartbeat revocation: an expired token ends a tunnel within about 90 s of its last good ping,
    and a refreshed token keeps it alive.
12. A client whose `trustedCaFile` lacks the server's CA refuses to connect (an unrelated bundle
    makes the handshake fail), which proves verification is on. The same client without
    `trustedCaFile` connects unverified.

## Deliberate Simplifications

| Skipped | Add when |
|---------|----------|
| Web UI | people ask for one beyond the CLI |
| Live tunnel status in `tunnel list` | frps dashboard data is worth surfacing |
| Public (login-free) tunnels | webhook receivers are needed |
| Non-browser access to sites (bearer tokens) | CI or scripts must call a tunnel |
| Machine clients | headless servers need to publish (phase 3) |
| Instant kill switch (Ping hook) | implemented; enable by adding `"Ping"` to the plugin `ops` when the hour-long revocation window bites |
| CNPG above one | a Postgres outage matters |
| Sharding frps | one frps is outgrown |
| frps HA (zero-downtime restarts) | an frps restart blip matters; see "Later: frps HA by client fan-out" |
| Admin API or UI | operators outgrow Pocket ID plus SQL |
| Separate registrable domain for sites | cookie or CORS exposure to your apps matters |
| Public Suffix List entry for the sites domain | a separate domain is not wanted and isolation is |

## Alternatives Considered

- **KiroCrew's tunnel.** The open-source build has none: `kiro_crew/tunnel/` is a stub and the
  real provider is in a closed companion. Its docs point to Tailscale, cloudflared or ngrok.
- **Pangolin (PR #2144).** Natively multi-tenant with a UI, but the chart's controller mode
  cannot route a separate Traefik pod to Gerbil's WireGuard network (open upstream issue
  helm-charts#20), it needs UDP 51820/21820 which Cloudflare cannot proxy, its sites are
  admin-created, and the PR commits a plaintext secret. Parked once the wss check passes.
- **pgrok.** Zero custom code and identity-bound subdomains, but SSH on :2222 (not
  Cloudflare-proxyable) plus Postgres, a long-lived token not rechecked against Pocket ID, and
  untested here.
- **Cloudflare Tunnel plus Access.** SaaS, and creators would not authenticate with Pocket ID.
- **Stock tiers.** Machine clients plus stock frpc plus the plugin gate (no code) leave names
  trust-based and sharing admin-edited. Adding only the frps plugin gives ownership but not
  self-service sharing. Neither meets the self-service requirement; the first is phase 0.
- **Per-share Traefik CRDs** and **stock forward-auth tools**: rejected above.
- **Python/Flask broker** (the oidc-saml-bridge layout): rejected for one toolchain with the CLI.

## Open Items for Implementation

- Create the `layertwo/tunnels` repository, its CI, and a Renovate config that bumps the frp
  module and the frps image tag together (separate repos cannot be grouped, so two PRs), and
  that also bumps the digest in `Dockerfile.frps`.
- Create the Pocket ID API, groups and clients above; create the Cloudflare-side records through
  external-dns.
- Pick the CNPG image tag to match the other clusters at implementation time.
- After the wss check passes: park Pangolin PR #2144, and rotate and SOPS-encrypt its
  `SERVER_SECRET` regardless, because it is already in a public repository.
- Clean up the spike: delete the `frp-spike` client, the `tunnel` API and the credentials file
  in Pocket ID and the temp directory, and delete or commit `spikes/`.
- Operational note for a possible upstream PR: Cloudflare returns 403 to Python's default
  `Python-urllib` User-Agent on idp.layertwo.dev; Go's default and other common clients pass.

## Sources

- frp v0.71.0: `server/service.go`, `server/control.go`, `client/service.go`, `client/control.go`,
  `pkg/auth/oidc.go`, `pkg/config/v1/*`, `pkg/plugin/server/types.go`, `doc/server_plugin.md`,
  `conf/frps_full_example.toml`, README (subdomains, tcpmux, authentication), issue #5557, the
  release asset list.
- Pocket ID v2.18.0: `backend/internal/oidc/*`, `backend/internal/utils/cookie/*`,
  `backend/internal/dto/validations.go`; docs for APIs and permissions, allowed groups, user
  management, and authentication proxies.
- Traefik `forwardAuth` docs; traefik-oidc-auth docs (middleware configuration, authorization);
  traefik-forward-auth v4 authorization conditions.
- Repo state read on 2026-10-07: `clusters/home/apps/network/traefik/*` (entrypoint middleware,
  plugin registration), `mediabox/middleware.yml`, `cloud/send/app/oidc.yml`,
  `cloud/kirocrew/*`, `docs/networking.md`.
- Spike notes: branch `spike/frp-pocket-id`, `spikes/frp-oidc/NOTES.md` (uncommitted).
- Prior art: `fosrl/cli` (Pangolin CLI), KiroCrew `src/kiro_crew/tunnel/*`.

## Phase 0 Results

Run on 2026-10-08 (PDT) against the deployed stack (PRs #2449 and #2453, plus the group-name fix `cb315a00`). The test client was `frpc` v0.71.0 from ghcr on a Mac, tunnelling to a `traefik/whoami` container, reaching the apex through the Cloudflare edge. Checks that need `kubectl` were not reported and are marked as such.

| ID | Check | Result | Note |
|----|-------|--------|------|
| C1 | wss through Cloudflare and Traefik, 70+ minutes | PASS | one login at 16:55:41, still connected at 18:06 with one login and no warning; frpc renewed the client-credentials token (1 h, no refresh token) at 17:55 and pings kept being accepted |
| C2 | DNS and certificate | PASS | apex proxied by Cloudflare publicly and 172.31.0.30 on the LAN; wildcard DNS-only to the origin (hairpin from the LAN works); `*.w.tunnels.layertwo.dev` from Let's Encrypt with the right SAN; `/` on the apex is 404 |
| C3 | Browser login on alice, then bob | PASS | Pocket ID accepted the wildcard callback `https://*.w.tunnels.layertwo.dev/oidc/callback`; bob answered with no prompt (the session cookie is host-only, so this was a silent redirect through the existing Pocket ID session) |
| C4 | What the app receives | PASS | no `Cookie` header at all (gate cookies stripped); `X-Tunnels-Sub` and `X-Tunnels-User` carry the claims; `X-Tunnels-Groups` arrives as one header line per group; a WebSocket to `/echo` echoed |
| C5 | Visitor outside the groups | PARTIAL | second line seen live: a Pocket ID-authenticated user whose groups did not match got the gate's 403 and nothing reached the app (`Unauthorized. Expected claim groups to contain any value of [...]` in the Traefik log). Pocket ID's own refusal page was not tested (skipped) |
| C6 | Host with no tunnel | PASS | HTML request 302 to Pocket ID, other requests 401, never 404 |
| C7 | CA verification | PASS | an unrelated bundle makes frpc refuse (`x509: certificate signed by unknown authority`); without `trustedCaFile` it connects, so the default is unverified |
| C8 | Old spike API | SKIPPED | no spike credentials; audience enforcement was shown instead: a token without `resource` (audience = client id) is refused by the production frps config with `expected audience "https://tunnels.layertwo.dev"` |
| C9 | Expired token ends the tunnel | PASS | the token expired at 00:55:24 UTC; the next ping, 18 s later, was rejected (`pong message contains error: invalid OIDC token in ping: oidc: token is expired`) and every reconnect is refused. A well-behaved client ends on the rejected ping; the 90 s heartbeat timeout is the backstop |
| C10 | NetworkPolicy isolation | NOT RUN | needs `kubectl` |

Not reported (need `kubectl`): the HelmRelease `Ready`, `id -u` of the frps pod, and the `heartbeat` lines in the frps log.

Also checked without a cluster: the production frps ConfigMap under the production securityContext accepts a client-credentials login against the live Pocket ID; `allowPorts = [{ single = 7000 }]` rejects TCP proxies on remote ports 7000, 0 and 2222, `https` and `tcpmux` are disabled, and `udp`, `stcp` and `http` with `customDomains` register but are unreachable. A bare `curl` upgrade on `/~!frp` without an `Origin` header gets 403 from frps; with one, 101 through Cloudflare.

### Changes found in Phase 0

- Cookie prefix is `__Secure-tunnels`: with PKCE, plugin v0.21.0 sets its verifier cookie on `Path=/oidc/callback`, which `__Host-` forbids. Switch back after a plugin release that contains sevensolutions/traefik-oidc-auth#283 (Verification 5).
- `Authorization.CheckOnEveryRequest: true` is required, otherwise the groups are checked once and cached while tokens renew.
- The Pocket ID groups are `tunnels-viewers` and `tunnels-creators`. The `groups` claim carries the group Name, and Pocket ID fills Name from the Friendly name with every character outside `a-z0-9_` replaced by `_`.
- `X-Tunnels-Groups` listed every group the visitor has (nine for the test user), so the app saw unrelated internal groups. PR #2454 stops forwarding it.
- frps rewrites `X-Forwarded-Proto` to `http` for the last hop (Traefik sends `https`). `requestHeaders.set.x-forwarded-proto = "https"` on the proxy restores it (tested locally).
- Images come from ghcr.io; upstream pushes identical digests there.

### Changes to plans 2-4

- Plan 2 (CLI): generate the `frpc` config with the embedded CA bundle as `trustedCaFile` (the default is unverified), `requestHeaders.set.x-forwarded-proto = "https"`, and a handle-derived `subdomain`. The token source is client credentials in Phase 0; the device flow replaces it.
- Plan 2 (gate pipeline): re-add the groups header between the plugin and the broker's `/authz` only, and strip every `X-Tunnels-*` header before the app, as the design already says.
- Plan 3 (sharing): decisions use the token's group Names, so document the Name field rule next to the group setup.
- Plan 4 (hardening): the apex `/~!frp` route is unauthenticated and unthrottled (add a Cloudflare rate rule or an allow-list); the gate owns `/oidc/callback` and any `/logout` path on every site (move `LogoutUri`); switch the cookie prefix back to `__Host-` when the plugin allows; per-host rate limits are per replica and sit behind the gate.
- Plan 2b (deploying the broker), from the Tasks 4-8 review:
  - frps `auth.additionalScopes` gets `NewWorkConns` (see "Revocation needs explicit settings"); the Phase 0 clients and frps used `["HeartBeats"]` only.
  - The plugin URL carries the secret and frps writes it to its own log whenever the broker is unreachable (`send Login request to plugin [broker] error: Post "http://...:8080/plugin/<secret>?..."`). The control that matters is a NetworkPolicy that lets only the frps pod reach `/plugin/`; treat frps logs as secret-bearing and rotate the secret if they leak.
  - `/authz` trusts `X-Forwarded-Host`, `X-Tunnels-Sub` and `X-Tunnels-User` completely. The forwardAuth middleware must list `X-Tunnels-Sub` and `X-Tunnels-User` in `authResponseHeaders` (Traefik then deletes any copy the visitor sent before it copies the gate's), must leave `trustForwardHeader` at `false` (with `true` a creator could send `Host: alice.<sites>` with `X-Forwarded-Host: bob.<sites>`, be authorised against their own label and be served alice's site), and `/authz` must be reachable by Traefik only. Leaving `authRequestHeaders` unset is fine; listing only the two identity headers also works, because Traefik sets `X-Forwarded-Host` afterwards.
  - Rate limit `/api/` and the frps route in Traefik. Every Login reaches the broker before frps checks anything, and a token with a key id nobody has seen makes the broker fetch the provider's key set (go-oidc has no limit on that).
  - Cap the proxy count in frps as well if the broker's limit must hold: the dashboard lags the plugin's answer, so many clients started at once can overshoot it.
- Revocation: machine-client tokens last one hour and cannot be refreshed, so deleting a client ends its tunnel within an hour plus one ping (about 30 s); the broker's Ping hook is what makes it immediate.
