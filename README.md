# tunnels

A multi-user tunnel service, in the spirit of ngrok, built on [frp](https://github.com/fatedier/frp).
People publish an HTTP service from their own machine at `https://<handle>[-<name>].w.tunnels.layertwo.dev`,
and visitors sign in with Pocket ID before they reach it. An owner shares a site with other users and
groups (see the [design](docs/design.md)).

## Use

You need a Pocket ID account in `tunnels-creators`. Your handle is your Pocket ID username in lower
case, and it has to be 2 to 20 letters and digits. Download the archive for your system from
[Releases](https://github.com/layertwo/tunnels/releases), check it (below), and put `tunnel` on your `PATH`.

```sh
tunnel login                    # shows a URL and a code to approve in your browser
tunnel up 3000                  # https://<handle>.w.tunnels.layertwo.dev serves http://127.0.0.1:3000
tunnel up 3000 --name blog      # https://<handle>-blog.w.tunnels.layertwo.dev
tunnel share <label> <grantee>  # lets a user or --group reach one site, named by its label
tunnel share --for 7d <label> <grantee>   # the share ends after a duration (7d, 24h, ...)
tunnel unshare <label> <grantee>          # stops sharing it
tunnel list                     # shows the shares you set
tunnel machine create NAME      # make a machine publish as itself, no passkey (run it on the machine)
tunnel machine list             # show your machines
tunnel machine remove NAME      # revoke a machine
tunnel logout                   # forgets the login on this computer
tunnel version
```

`tunnel machine create NAME` runs once on the target machine: it generates a key pair there and asks
the broker (as you, the owner) to register the public half. The private key never leaves that machine;
it is kept in `machine-key.json` in the config dir, mode 0600. A machine then publishes as itself —
`tunnel up` on that machine serves `https://<machine>.w.tunnels.layertwo.dev` — and you, and anyone
you share that site with, may reach it. `tunnel machine remove NAME` is the revocation lever.

A site's label is `<handle>` for the default tunnel, `<handle>-<name>` for a named one (`alice-blog`).

`--group` shares take effect once the site gate forwards the visitor's groups (a deferred change);
user shares work today.

Removing someone from `tunnels-creators`, or disabling their account in Pocket ID, ends their
tunnel within one heartbeat: the Ping hook (in frps's `ops` since v0.2.0) rejects the next heartbeat.
Disabling or removing a machine's row ends its tunnel the same way. A machine is its own principal,
so removing its owner from `tunnels-creators` does not stop it.

`tunnel up` runs until you stop it. A name is 1 to 42 lowercase letters, digits and inner dashes,
and not `default` (that is the tunnel without a name).
The login is kept in `tunnels/` in your config directory (`~/Library/Application Support` on macOS,
`~/.config` on Linux, `%AppData%` on Windows), or in `$TUNNELS_CONFIG_DIR`.

## Verify a release

Every archive of a release comes with a signed build provenance. It says which workflow built
the archive from which commit of this repository:

```sh
gh attestation verify tunnel_0.1.0_darwin_arm64.tar.gz --repo layertwo/tunnels
grep ' tunnel_0.1.0_darwin_arm64.tar.gz$' checksums.txt | shasum -a 256 -c -   # the release's checksums.txt
```

The images are signed by digest with cosign (keyless, from the `image` workflow):

```sh
cosign verify ghcr.io/layertwo/tunnels-broker:latest \
  --certificate-identity-regexp '^https://github.com/layertwo/tunnels/\.github/workflows/image\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Run the broker

The images are `ghcr.io/layertwo/tunnels-broker` and `ghcr.io/layertwo/tunnels-frps` (linux/amd64
and linux/arm64, distroless, uid 65532). The broker reads its settings from a TOML configuration file —
`--config PATH`, else `$BROKER_CONFIG`, else `/etc/tunnels/broker.toml` — and from the environment, and
when one is missing or wrong, refuses to start with an error that names every such variable.

| Section | Keys |
|---------|------|
| `[server]` | `listen_addr`, `log_level` |
| `[identity]` | `issuer`, `api_resource`, `creators_group`, `cli_client_id`, `min_cli_version`, `username_claim`, `groups_claim` |
| `[tunnels]` | `service_host`, `sites_domain`, `max_tunnels_per_user`, `bandwidth_limit`, `reserved_handles` |
| `[machines]` | `enabled`, `pocket_id_url`, `pocket_id_api_id` |
| `[metrics]` | `enabled` |

A **feature with no section is off when a configuration file is present**: with no `[machines]` the
`/api/machines` endpoints answer 404, and with no `[metrics]` `GET /metrics` answers 404 (`enabled = false`
is off the same way). The file is optional — the default path may be absent — and with **no file at all**
the broker behaves as before: `/metrics` is served and the machine endpoints follow `POCKET_ID_URL`. The
environment **overrides** a file value and keeps every setting's name; the four
secrets (`DATABASE_URL`, `POCKET_ID_API_KEY`, `FRPS_DASHBOARD_PASSWORD`, `PLUGIN_SECRET`) come from the
environment only and must not appear in the file.

| Variable | Default | Meaning |
|----------|---------|---------|
| `SERVICE_HOST` | required | where the CLI connects, e.g. `tunnels.layertwo.dev` |
| `SITES_DOMAIN` | required | the domain sites live under, e.g. `w.tunnels.layertwo.dev` |
| `ISSUER` | required | the OIDC issuer, e.g. `https://idp.layertwo.dev` |
| `API_RESOURCE` | required | the audience the CLI's access tokens carry |
| `CREATORS_GROUP` | required | the group whose members may publish |
| `CLI_CLIENT_ID` | required | the public OIDC client the CLI logs in with (device flow) |
| `DATABASE_URL` | required | Postgres; the schema is migrated at start |
| `POCKET_ID_URL` | required for `[machines]` | the Pocket ID instance whose admin API mints a machine's client; an http(s) URL without credentials |
| `POCKET_ID_API_KEY` | required for `[machines]` | the admin API key the broker creates machine clients with (admin-grade; rotate it); never logged |
| `POCKET_ID_API_ID` | required for `[machines]` | the Tunnels API a machine's client is granted access to |
| `FRPS_DASHBOARD_URL`, `FRPS_DASHBOARD_USER`, `FRPS_DASHBOARD_PASSWORD` | required | frps's dashboard; an http(s) URL without credentials |
| `PLUGIN_SECRET` | required | 32 or more of `A-Z a-z 0-9 - _`; frps calls `/plugin/<secret>` |
| `USERNAME_CLAIM`, `GROUPS_CLAIM` | `preferred_username`, `groups` | the userinfo claims for the username and the groups |
| `MAX_TUNNELS_PER_USER` | `5` | tunnels one person may have up at once |
| `DEFAULT_BANDWIDTH_LIMIT` | `10MB` | per tunnel, enforced by frps |
| `RESERVED_HANDLES` | `admin,root,support,security` | handles nobody gets |
| `MIN_CLI_VERSION` | `0.0.0` | served in `/.well-known/tunnels.json`, not enforced |
| `LISTEN_ADDR`, `LOG_LEVEL` | `:8080`, `info` | |

It serves `/plugin/<secret>` (frps's HTTP plugin for Login, NewProxy, CloseProxy, Ping and
NewWorkConn), `/authz` (Traefik's forwardAuth), `GET /api/me`, `GET|POST|DELETE /api/machines` (when
`[machines]` is on, or with no config file and `POCKET_ID_URL` set), `GET|PUT|DELETE /api/shares`,
`GET /.well-known/tunnels.json`, `GET /healthz` and `GET /metrics` (Prometheus, with bounded and
secret-free labels; when `[metrics]` is on, or with no config file). frps needs
OIDC auth with `additionalScopes = ["HeartBeats", "NewWorkConns"]` and
the broker as its plugin; the [design](docs/design.md#frps) has its configuration and what the
deployment must set around it.

## Versions

- `tunnel version` prints the CLI's version and its default server. Every request it makes carries
  `User-Agent: tunnels/<version>`, and every tunnel login carries the version to the broker, which logs
  it as `cli_version` with each login decision.
- `broker --version` prints the broker's; it also logs it when it starts (`"msg":"broker listening"`).
- Images from a `vX.Y.Z` tag are tagged `vX.Y.Z` and `sha-<commit>`; images from `mainline` are
  tagged `latest` and `sha-<commit>`.
- The frps image runs upstream frps: `--version` prints frp's version.

## Layout

One Go module and one repository for everything this project ships:

- `cmd/<name>/`: one directory per binary. The broker (the frps plugin, the access decisions behind
  `/authz`, the API) is `cmd/broker`; the CLI, which embeds the frp client library, is `cmd/tunnel`.
- `internal/`: code the binaries share, one package per concern (`names`, `store`, `httpx`, `idp`,
  `frpsapi`, `broker`, `auth`, `tunnel`, `cli`); `mockidp` stands in for Pocket ID in tests. `e2e/` runs
  all of it against a real frps.
- `Dockerfile.<component>`: one per container image (`Dockerfile.broker`, `Dockerfile.frps`), built from
  prebuilt binaries.
- `.github/workflows/`: `ci.yml` checks the whole module; `image.yml` builds the images on pull
  requests and pushes and signs them from `mainline` and tags; `release.yml` publishes the CLI on a
  `v*` tag; `codeql.yml` scans the code.
- Releases: one `vX.Y.Z` tag releases the CLI archives and tags the images together. Component-prefixed
  tags wait until a component needs its own cadence.
- Cluster manifests live in [`layertwo/homelab`](https://github.com/layertwo/homelab), not here.

## Build

```sh
go build -o broker ./cmd/broker
go build -o tunnel ./cmd/tunnel
```

A plain build reports its version as `dev`. Releases set it with `-ldflags "-X main.version=<version>"`,
and the CLI's default server with `-X main.defaultServer=<host>`.

## Test

```sh
go test ./...        # the Postgres tests skip unless TEST_DATABASE_URL is set
export TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable'
go test -race ./...
go test -tags e2e ./e2e/   # builds frps from the pinned module and runs the whole stack
```

CI runs gofmt, `go vet -tags e2e ./...`, `go test -race ./...` against Postgres 18, the end-to-end
test, govulncheck, a GoReleaser dry run and CodeQL.

## Docs

- [Design](docs/design.md)
- [Plans](docs/plans/)
