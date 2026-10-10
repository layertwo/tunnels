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
tunnel share --name blog bob    # lets bob reach the blog tunnel
tunnel share --for 7d bob       # the share ends after a duration (7d, 24h, ...)
tunnel share --group family     # --group shares with a Pocket ID group instead of a username
tunnel unshare --name blog bob  # stops sharing it
tunnel list                     # shows the shares you set
tunnel logout                   # forgets the login on this computer
tunnel version
```

`--group` shares take effect once the site gate forwards the visitor's groups (a deferred change);
user shares work today.

Removing someone from `tunnels-creators`, or disabling their account in Pocket ID, ends their
tunnel within one heartbeat once the Ping hook is enabled (a deferred change); until then it ends
when their token expires, about an hour later.

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
and linux/arm64, distroless, uid 65532). The broker reads its settings from the environment and, when
one is missing or wrong, refuses to start with an error that names every such variable.

| Variable | Default | Meaning |
|----------|---------|---------|
| `SERVICE_HOST` | required | where the CLI connects, e.g. `tunnels.layertwo.dev` |
| `SITES_DOMAIN` | required | the domain sites live under, e.g. `w.tunnels.layertwo.dev` |
| `ISSUER` | required | the OIDC issuer, e.g. `https://idp.layertwo.dev` |
| `API_RESOURCE` | required | the audience the CLI's access tokens carry |
| `CREATORS_GROUP` | required | the group whose members may publish |
| `CLI_CLIENT_ID` | required | the public OIDC client the CLI logs in with (device flow) |
| `DATABASE_URL` | required | Postgres; the schema is migrated at start |
| `FRPS_DASHBOARD_URL`, `FRPS_DASHBOARD_USER`, `FRPS_DASHBOARD_PASSWORD` | required | frps's dashboard; an http(s) URL without credentials |
| `PLUGIN_SECRET` | required | 32 or more of `A-Z a-z 0-9 - _`; frps calls `/plugin/<secret>` |
| `USERNAME_CLAIM`, `GROUPS_CLAIM` | `preferred_username`, `groups` | the userinfo claims for the username and the groups |
| `MAX_TUNNELS_PER_USER` | `5` | tunnels one person may have up at once |
| `DEFAULT_BANDWIDTH_LIMIT` | `10MB` | per tunnel, enforced by frps |
| `RESERVED_HANDLES` | `admin,root,support,security` | handles nobody gets |
| `MIN_CLI_VERSION` | `0.0.0` | served in `/.well-known/tunnels.json`, not enforced |
| `LISTEN_ADDR`, `LOG_LEVEL` | `:8080`, `info` | |

It serves `/plugin/<secret>` (frps's HTTP plugin for Login, NewProxy and CloseProxy), `/authz`
(Traefik's forwardAuth), `GET /api/me`, `GET /.well-known/tunnels.json` and `GET /healthz`. frps needs
OIDC auth with `additionalScopes = ["HeartBeats", "NewWorkConns"]` and the broker as its plugin; the
[design](docs/design.md#frps) has its configuration and what the deployment must set around it.

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
