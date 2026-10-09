# Tunnels Phase 1 Implementation Plan: broker, CLI, images, releases

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build design phase 1 in this repo: a broker that binds every frp name to its verified owner and lets only the owner open a site, a `tunnel` CLI (`login`, `up`, `logout`, `version`) with the frp client embedded, signed broker and distroless frps images, and CLI release binaries, proven by an end-to-end test against a real frps.

**Architecture:** One Go module, two commands. The broker is plain `net/http`: frps posts Login, NewProxy and CloseProxy to `/plugin/<secret>`, Traefik's forwardAuth calls `/authz`, the CLI calls `/.well-known/tunnels.json` and `/api/me`. State is one Postgres table (`users`) plus frps's dashboard API. The CLI runs Pocket ID's device flow, keeps an access-token file fresh, and runs the embedded frp client from a JSON config loaded in strict mode.

**Tech Stack:** Go 1.26 (the CA-roots module sets the floor; frp needs 1.25), `github.com/fatedier/frp` v0.71.0 (client library and plugin types), `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`, `github.com/jackc/pgx/v5`, `github.com/spf13/pflag`, `golang.org/x/crypto/x509roots/fallback`, GoReleaser, GitHub Actions, cosign.

**Spec:** `docs/design.md` (copied from `layertwo/homelab` `docs/plans/2026-10-07-tunnels-design.md` at `ad1b1a8f`; its last sections are the Phase 0 results). Read it first: this plan only decides what the spec leaves open.

**Series:** plan 1 (Phase 0) ran in the homelab repo. This is plan 2. Next, written when its inputs exist: plan 2b deploys this to the homelab (broker HelmRelease and secrets, CNPG, routes and middlewares, NetworkPolicy, frps plugin config; it pins the image digests Task 13 publishes), plan 3 = sharing, plan 4 = hardening and `/install.sh`.

## Decisions that amend the spec

Each was checked against the frp v0.71.0 and Pocket ID v2.18.0 source or by a spike, and is cheap to reverse.

1. **Dashboard API v2.** `/api/v2/clients?runID=&status=online` and `/api/v2/proxies?type=http&user=&status=online` filter on the server and return `total`; v1 lists every proxy ever seen, online or not. Responses are wrapped as `{"code":200,"msg":"success","data":{...}}`.
2. **Broker env gains `CLI_CLIENT_ID` and `MIN_CLI_VERSION`** (the bootstrap document needs them). `MIN_CLI_VERSION` is served but not enforced yet.
3. **No restart loop in the CLI.** `client.Service.Run` already reconnects forever after the first login (`keepControllerWorking`); a failed first login returns the server's reject reason, and the CLI prints it and exits 1.
4. **No `/authz` cache.** A primary-key lookup per request; Postgres down means 503 at once instead of serving a 5 s cache. Add the cache when latency or Postgres blips show up.
5. **`/install.sh` moves to plan 4.** Phase 1 ships GitHub Releases.
6. **The CLI builds its frp config as JSON**, not TOML: `config.LoadConfigure` accepts JSON, strict mode rejects unknown keys, and nothing needs path escaping (Windows paths).
7. **The CA bundle comes from `x509roots/fallback`** (Go team, Mozilla roots, 120 certificates) instead of a committed PEM, and Renovate bumps it monthly.
8. **The e2e test builds frps from the pinned module** (`go build -tags noweb`, via a `tool` directive that keeps its dependencies in `go.sum`), not from the container. Same source as the image; no Docker needed.
9. **Phase 1 `/authz` uses only `X-Tunnels-Sub` and `X-Tunnels-User`.** The groups header returns with sharing (plan 3).
10. **Dockerfiles are named per component** (`Dockerfile.broker`, `Dockerfile.frps`): the repo holds several deliverables, so a bare `Dockerfile` should not mean "the broker".

## Global Constraints

Every task's requirements include this section.

- Module `github.com/layertwo/tunnels`, `go 1.26.0`, default branch `mainline`, commits `feat(scope): ...`, work lands through pull requests the human partner merges. Three PRs: Tasks 1-8 (broker), 9-11 (CLI), 12-13 (e2e, images, releases). Open each as a draft against `mainline`; keep working on the same branch until the previous PR is squash-merged, then `git rebase --onto origin/mainline <old tip>` and retarget, so the diff and CI show only the new work.
- `github.com/fatedier/frp v0.71.0` always equals the frps image `ghcr.io/fatedier/frps:v0.71.0@sha256:cd8b947ba61678b200baa4f71ccc33f3c52e4e2cc0059700ba3b8354e36af7c3`; bump them together.
- Hosts: service `tunnels.layertwo.dev`; sites `<label>.w.tunnels.layertwo.dev` (`SITES_DOMAIN=w.tunnels.layertwo.dev`).
- Pocket ID: issuer `https://idp.layertwo.dev` (no trailing slash); API resource `https://tunnels.layertwo.dev`; groups `tunnels-creators` (may connect) and `tunnels-viewers`; the `groups` claim carries group *Names*; CLI client `tunnels-cli` (public, device flow), scopes `openid profile groups offline_access`, `resource` = the API.
- Names: handle = the lowercased username, only if the **original** matches `^[A-Za-z0-9]{2,20}$` (ASCII check before lowercasing, so U+212A never becomes `k`); reserved `admin`, `root`, `support`, `security`. Tunnel name `^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$`, `default` reserved. Label = `<handle>` or `<handle>-<name>` (at most 63 characters; owner = text before the first dash). Proxy name `<handle>.<name>`, default tunnel `<handle>.default`. Host matching is case-insensitive; a port, a trailing dot, an extra label or a comma is malformed.
- Plugin protocol: frps sends `POST <addr>/plugin/<secret>?version=0.1.0&op=<Op>` with `{"version","op","content"}`. Every decision is HTTP 200 with `{"reject","reject_reason","unchange","content"}`; any other status reaches the client as an opaque "send Login request to plugin error". A hook that changes content returns the **whole** content with `unchange:false`. The hook never changes `privilege_key`. Fail closed: a dependency error rejects.
- Broker env (name = default): `SERVICE_HOST`, `SITES_DOMAIN`, `ISSUER`, `API_RESOURCE`, `CREATORS_GROUP`, `CLI_CLIENT_ID`, `MIN_CLI_VERSION` = `0.0.0`, `DATABASE_URL`, `FRPS_DASHBOARD_URL`, `FRPS_DASHBOARD_USER`, `FRPS_DASHBOARD_PASSWORD`, `PLUGIN_SECRET`, `MAX_TUNNELS_PER_USER` = `5`, `DEFAULT_BANDWIDTH_LIMIT` = `10MB` (mode `server`), `RESERVED_HANDLES` = `admin,root,support,security`, `LISTEN_ADDR` = `:8080`, `LOG_LEVEL` = `info`. Everything without a default is required.
- `/authz` reads `X-Forwarded-Host`, `X-Tunnels-Sub`, `X-Tunnels-User`; allow = 200 plus `X-Tunnel-User: <username>`; every other outcome is the same empty 403 (503 on an infrastructure error).
- Client config: `transport.protocol = wss` to `tunnels.layertwo.dev:443`, `user = <handle>`, `auth.method = oidc`, `auth.additionalScopes = ["HeartBeats"]`, `auth.oidc.tokenSource` type `file`, `transport.heartbeatInterval = 30`, `transport.tls.trustedCaFile` always set for `wss`, the only production protocol (frp skips certificate verification otherwise), proxy `requestHeaders.set.x-forwarded-proto = "https"` (frps rewrites it to `http`).
- Files: user-private files 0600; token files are written atomically (temp file in the same directory, then rename). Logs: `log/slog` JSON, never a token, the plugin secret or `privilege_key`. Every outbound request has a 10 s deadline and `User-Agent: tunnels/<version>`.
- Build: `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=<v> -X main.defaultServer=tunnels.layertwo.dev"`. CLI targets: darwin/amd64, darwin/arm64, linux/amd64, linux/arm64, linux/armv7, windows/amd64, windows/arm64; archives `tunnel_<version>_<os>_<arch>` (`.zip` on windows) plus `checksums.txt`.
- Images: `ghcr.io/layertwo/tunnels-broker` and `ghcr.io/layertwo/tunnels-frps`, linux/amd64 and linux/arm64, on `gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3` (uid 65532), cosign-signed by digest. Prefer ghcr.io wherever a publisher offers it.
- Tests: `go test -race ./...`, table-driven. Postgres tests read `TEST_DATABASE_URL` and skip when it is unset. The end-to-end test sits behind the `e2e` build tag. After adding imports run `go mod tidy` and commit `go.mod` and `go.sum` with the task.
- Local network: if `proxy.golang.org` does not resolve, `export GOPROXY=https://goproxy.io,direct` (`sum.golang.org` still verifies hashes). Plain `GOPROXY=direct` fails `go mod tidy` on a gvisor test dependency.

## Review Focus

1. Usernames and hosts that nearly look valid: `Alice`, `alice_b`, `alice-`, 21 characters, U+212A, a host with a port, a trailing dot, an extra label or uppercase. They must be refused or normalised exactly as the table says, never panic, and never create a row (Tasks 1, 5, 7).
2. A dependency down or slow while deciding (Pocket ID userinfo, Postgres, the frps dashboard): every hook and `/authz` refuses; nothing is allowed by default (Tasks 6, 7, 8).
3. Run-ID takeover and honest reconnects: a Login whose run ID is online under another user is refused, the same user's reconnect is not (Tasks 6, 12).
4. `/authz` default deny: missing, empty or duplicated identity headers, an unknown or disabled owner, a label that parses to someone else. All give the same empty 403, so nothing reveals whether a name exists (Task 7).
5. CLI token files: refresh-token rotation shared by two running `tunnel up` processes, 0600 permissions, atomic replacement, and a failed refresh that must not destroy good tokens (Task 9).

## File Structure

| Path | Responsibility |
|------|----------------|
| `internal/names` | handle, tunnel name, label, proxy name and site-host rules (both programs) |
| `internal/store` | pgx pool, embedded migrations, `users` |
| `internal/httpx` | HTTP client with deadline and `User-Agent` |
| `internal/mockidp` | Pocket ID test double mirroring v2.18.0 behaviour (tests only) |
| `internal/pocketid` | discovery, userinfo, access-token verification |
| `internal/frpsapi` | frps dashboard v2 client |
| `internal/broker` | `account.go` (resolver), `hooks.go`, `authz.go`, `config.go`, `server.go` (routes, `/api/me`, well-known, healthz) |
| `internal/auth` | CLI: bootstrap, device login, token files, refresh |
| `internal/tunnel` | CLI: frp config builder, runner, CA bundle |
| `internal/cli` | CLI: commands |
| `cmd/broker`, `cmd/tunnel` | `main` packages, a few lines each |
| `e2e/` | end-to-end test (`e2e` tag) |
| `Dockerfile.broker`, `Dockerfile.frps`, `.dockerignore`, `.goreleaser.yaml`, `.github/workflows/{ci,image,release}.yml`, `renovate.json`, `README.md` | packaging and CI |

---

### Task 0: Pocket ID `tunnels-cli` client and live token check

Settles design Verification 6 and 7 against the real service before code depends on them. No code.

**Files:**
- Modify: `docs/design.md` (append `## Phase 1 Results`)

**Interfaces:**
- Produces: the `tunnels-cli` client id, used as `CLI_CLIENT_ID` by Tasks 8 and 12.

- [ ] **Step 1: Create the client (manual, Pocket ID UI).** `tunnels-cli`: public (no secret), device authorization on, user-delegated access to the API "Tunnels", allowed group `tunnels-creators`, **skip consent off** (the device page must show the client and its scopes). Add your own user to `tunnels-creators`. Copy the client id.
- [ ] **Step 2: Run the device flow and read the claims.** Tokens are never printed.

  ```bash
  IDP=https://idp.layertwo.dev; API=https://tunnels.layertwo.dev; CID=<client id>
  claims() { python3 -c "import sys,json,base64;t=sys.stdin.read().strip().split('.')[1];print(json.dumps(json.loads(base64.urlsafe_b64decode(t+'='*(-len(t)%4)))))" | jq '{iss,aud,scope,sub,exp}'; }
  DA=$(curl -s -d client_id=$CID --data-urlencode 'scope=openid profile groups offline_access' -d resource=$API $IDP/api/oidc/device/authorize)
  echo "$DA" | jq '{verification_uri_complete,user_code,interval,expires_in}'   # open the URL, sign in, approve
  TOK=$(curl -s -d grant_type=urn:ietf:params:oauth:grant-type:device_code -d device_code=$(echo "$DA" | jq -r .device_code) -d client_id=$CID $IDP/api/oidc/token)
  echo "$TOK" | jq 'keys'; AT=$(echo "$TOK" | jq -r .access_token); RT=$(echo "$TOK" | jq -r .refresh_token)
  echo "$AT" | claims
  curl -s -H "Authorization: Bearer $AT" $IDP/api/oidc/userinfo | jq '{preferred_username,groups}'
  NEW=$(curl -s -d grant_type=refresh_token -d refresh_token=$RT -d client_id=$CID $IDP/api/oidc/token)
  echo "$NEW" | jq -r .access_token | claims; [ "$(echo "$NEW" | jq -r .refresh_token)" != "$RT" ] && echo "refresh token rotated"
  ```

  Expected: the access token's `aud` holds `https://tunnels.layertwo.dev`, the client id and `https://idp.layertwo.dev`, and `scope` includes `openid`; userinfo returns `preferred_username` and `groups` containing `tunnels-creators`; the refreshed token has the same `aud` and `scope`, and `refresh token rotated` prints.
- [ ] **Step 3 (manual, optional): group recheck.** Remove yourself from `tunnels-creators`, repeat the refresh with the newest refresh token: expect an error (`access_denied` or `invalid_grant`). Add yourself back.
- [ ] **Step 4: Record and decide.** If userinfo is refused or the audience lacks the API resource, stop: the fallback is design Verification 6 (the CLI sends the ID token and frps's audience becomes the CLI client id), which changes Tasks 3, 6 and 9; tell the human partner before continuing. Otherwise append the outcomes (not tokens) to `docs/design.md` as `## Phase 1 Results` and commit: `git commit -am "docs: record pocket id device flow checks"`.

### Task 1: Repo scaffold and `internal/names`

**Files:**
- Create: `go.mod`, `README.md`, `renovate.json`, `.github/workflows/ci.yml`, `internal/names/names.go`, `internal/names/names_test.go`
- Modify: `.gitignore` (add `/dist/`)

**Interfaces:**
- Produces (`package names`):

  ```go
  const Default = "default"
  func HandleFromUsername(username string, reserved []string) (string, error)
  func ValidTunnelName(name string) bool            // "default" and "" are not valid names
  func Label(handle, tunnel string) string          // tunnel "" or Default -> handle; else handle+"-"+tunnel
  func ProxyName(handle, tunnel string) string      // handle+"."+(tunnel, or Default when "")
  func ParseLabel(label string) (handle, tunnel string, ok bool)   // tunnel "" for the default tunnel
  func SiteLabel(host, sitesDomain string) (label string, ok bool) // from X-Forwarded-Host
  ```

- [ ] **Step 1: Write the failing tests** in `internal/names/names_test.go`, table-driven, one test per function:

  ```go
  // TestHandleFromUsername (reserved = admin, root, support, security)
  {"Alice", "alice", true}, {"al", "al", true}, {strings.Repeat("a", 20), strings.Repeat("a", 20), true},
  {"a", "", false}, {strings.Repeat("a", 21), "", false}, {"", "", false},
  {"alice_b", "", false}, {"alice.b", "", false}, {"alice@x", "", false}, {"alice-b", "", false},
  {"\u212Aevin", "", false}, {"ünal", "", false}, {"Admin", "", false}, {"ROOT", "", false},
  ```

  - `TestValidTunnelName`: valid `blog`, `a`, `a-b`, `a--b`, 42 characters; invalid `default`, ``, `-a`, `a-`, `Blog`, `a_b`, 43 characters.
  - `TestLabelAndProxyName`: `Label("alice","")` = `alice`, `Label("alice","default")` = `alice`, `Label("alice","blog")` = `alice-blog`; `ProxyName("alice","")` = `alice.default`, `ProxyName("alice","blog")` = `alice.blog`.
  - `TestParseLabel`: `alice` -> (`alice`, ``, true); `alice-blog` -> (`alice`, `blog`, true); `alice-a-b` -> (`alice`, `a-b`, true); a 20-character handle plus `-` plus a 42-character name (63 total) is ok; invalid: `alice-`, `-blog`, `alice-default`, `Alice`, `a`, `alice--x`, `alice-Blog`, 64 characters, ``.
  - `TestSiteLabel` (domain `w.tunnels.layertwo.dev`): `alice-blog.w.tunnels.layertwo.dev` -> (`alice-blog`, true); `Alice.W.Tunnels.Layertwo.Dev` -> (`alice`, true); invalid: with `:443`, with a trailing dot, `x.alice.w.tunnels.layertwo.dev`, `w.tunnels.layertwo.dev`, `alice.tunnels.layertwo.dev`, `alice.w.tunnels.layertwo.dev.evil.com`, `a.com, b.com`, ``.
- [ ] **Step 2: Run to verify they fail.** `go test ./internal/names/ -v`. Expected: build failure, `undefined: HandleFromUsername` (and the other functions).
- [ ] **Step 3: Implement** the six signatures in `internal/names/names.go`. Compile the three regexps once; the error text of `HandleFromUsername` is shown to the user on a refused login, so it names the rule ("use 2 to 20 letters and digits") and, for reserved names, says the handle is reserved.
- [ ] **Step 4: Run to verify they pass.** `go test -race ./internal/names/ -v`. Expected: PASS.
- [ ] **Step 5: Scaffold.** `go mod init github.com/layertwo/tunnels`, set `go 1.26.0`. `README.md`: what the repo is, `go test ./...`, how to build, link to `docs/design.md` and `docs/plans/`. `renovate.json`:

  ```json
  {
    "$schema": "https://docs.renovatebot.com/renovate-schema.json",
    "extends": ["github>layertwo/renovate-config", "helpers:pinGitHubActionDigests"],
    "packageRules": [
      {"description": "frp library and frps image move together", "matchPackageNames": ["github.com/fatedier/frp", "ghcr.io/fatedier/frps"], "groupName": "frp"},
      {"description": "CA roots, monthly", "matchPackageNames": ["golang.org/x/crypto/x509roots/fallback"], "schedule": ["before 6am on the first day of the month"]}
    ]
  }
  ```

  `.github/workflows/ci.yml`, triggered on pull requests and pushes to `mainline`, `permissions: contents: read`, `actions/setup-go` with `go-version: '1.26'`: job `lint` (`test -z "$(gofmt -l .)"` and `go vet ./...`), job `test` (`go test -race ./...`), job `vuln` (`golang/govulncheck-action` on `./...`).
- [ ] **Step 6: Commit.** `git add -A && git commit -m "feat(names): add handle, tunnel and site label rules"`; open PR 1; wait for `lint`, `test` and `vuln` to pass.

### Task 2: Postgres store

**Files:**
- Create: `internal/store/store.go`, `internal/store/migrations/001_users.sql`, `internal/store/store_test.go`
- Modify: `.github/workflows/ci.yml` (Postgres for the `test` job)

**Interfaces:**
- Consumes: nothing.
- Produces (`package store`):

  ```go
  type User struct { Sub, Handle string; Disabled bool; CreatedAt time.Time }
  var ErrNotFound, ErrHandleTaken error
  func Open(ctx context.Context, databaseURL string) (*Store, error)   // pool + Migrate
  func (s *Store) Close()
  func (s *Store) UserBySub(ctx context.Context, sub string) (User, error)        // ErrNotFound
  func (s *Store) UserByHandle(ctx context.Context, handle string) (User, error)  // ErrNotFound
  func (s *Store) CreateUser(ctx context.Context, sub, handle string) (User, error) // idempotent per sub; another sub owns the handle: ErrHandleTaken
  ```

  Migration `001_users.sql` is the design's `users` table: `sub text primary key, handle text unique not null, disabled bool not null default false, created_at timestamptz not null default now()`.

- [ ] **Step 1: Write the failing tests.** A helper `newStore(t)` skips when `TEST_DATABASE_URL` is unset, creates schema `t_<random hex>`, opens the store with `search_path=<schema>` in the URL, and drops the schema in `t.Cleanup`. Tests: `TestOpenIsIdempotent` (second `Open` on the same schema succeeds, one `schema_migrations` row per file); `TestOpenConcurrently` (five `Open` calls at once all succeed: the advisory lock); `TestCreateUserAndLookups`; `TestCreateUserIsIdempotentPerSub` (same sub twice returns the first row, handle unchanged even if the second call passes another handle); `TestHandleTaken` (second sub with the same handle gets `ErrHandleTaken`, no row inserted); `TestConcurrentFirstLogins` (20 goroutines, same sub and handle: all succeed, one row; 20 goroutines with different subs and one handle: exactly one wins, 19 get `ErrHandleTaken`); `TestNotFound`.
- [ ] **Step 2: Run to verify they fail.** Start Postgres (`podman run -d --name pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 public.ecr.aws/docker/library/postgres:17`), then `TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' go test ./internal/store/ -v`. Expected: build failure, `undefined: Open`.
- [ ] **Step 3: Implement** with `pgxpool`. `Migrate` runs inside `Open`: take `pg_advisory_lock` on a fixed key, create `schema_migrations(version int primary key)`, apply each embedded file (`//go:embed migrations/*.sql`) that is not recorded, in order, one transaction per file. `CreateUser` is `insert ... on conflict (sub) do nothing`, then select by sub; a unique violation on the handle (SQLSTATE 23505) re-selects by sub first (a concurrent insert of the same sub is not a conflict) and returns `ErrHandleTaken` only if no row for that sub exists.
- [ ] **Step 4: Run to verify they pass** with the same command plus `-race`. Expected: PASS, no skips. Leave the `pg` container running; Task 12 needs it, and `podman rm -f pg` ends it.
- [ ] **Step 5: CI.** In the `test` job add `services.postgres` (`image: public.ecr.aws/docker/library/postgres:17`, `POSTGRES_PASSWORD: postgres`, port 5432, a `pg_isready` health check) and `TEST_DATABASE_URL` as above. No plain Postgres image exists on ghcr; this is the ECR Public mirror of the official image.
- [ ] **Step 6: Commit.** `feat(store): add users table with idempotent creation`.

### Task 3: `httpx`, `mockidp` and `pocketid`

**Files:**
- Create: `internal/httpx/httpx.go`, `internal/mockidp/mockidp.go`, `internal/pocketid/pocketid.go`, `internal/pocketid/pocketid_test.go`

**Interfaces:**
- Produces:

  ```go
  // package httpx
  func Client(userAgent string, timeout time.Duration) *http.Client   // sets User-Agent on every request

  // package pocketid
  type Identity struct { Sub, Username string; Groups []string }
  var ErrInvalidToken error                             // the IdP answered 401 or 403 for the token
  func New(ctx context.Context, issuer, apiResource, userAgent string) (*Client, error)   // OIDC discovery
  func (c *Client) UserInfo(ctx context.Context, accessToken string) (Identity, error)    // other failures are plain errors
  func (c *Client) VerifyAccessToken(ctx context.Context, raw string) (sub string, err error) // signature, issuer, exp, aud contains apiResource

  // package mockidp (tests only; mirrors Pocket ID v2.18.0)
  const APIResource = "https://tunnels.layertwo.dev"; const ClientID = "tunnels-cli-test"
  type User struct { Sub, Username string; Groups []string }
  type IssueOpts struct { Audience []string; Scope string; TTL time.Duration }
  func New(t testing.TB) *Server                        // httptest server; field URL is the issuer
  func (s *Server) AddUser(u User)
  func (s *Server) SetTTL(d time.Duration)                // default lifetime of every token the server issues, refreshes included
  func (s *Server) Issue(sub string, o IssueOpts) string  // RS256 JWT; defaults: aud [API, client, issuer], scope "openid profile groups", TTL 1h
  func (s *Server) Approve(userCode, sub string)          // approves a pending device code
  func (s *Server) RevokeUser(sub string)                 // later refreshes fail with invalid_grant
  ```

  `mockidp` serves `/.well-known/openid-configuration` (issuer, token, userinfo, jwks and device endpoints, RS256), `/jwks`, `/userinfo`, `/device/authorize`, `/token`. It must reproduce the rules that matter: userinfo answers 403 unless the token's `aud` contains the issuer **and** `scope` contains `openid`, and 401 for expired or badly signed tokens; the device authorize call takes `client_id`, `scope`, `resource` (public client, no secret) and stamps `aud = [resource, client_id, issuer]`; the token endpoint supports the device-code grant (`authorization_pending` until `Approve`) and the refresh grant (keeps `aud` and `scope`, rotates the refresh token, the old one stays valid for 60 s, `invalid_grant` after `RevokeUser`). It records the `User-Agent` of every request in `s.UserAgents []string`.

- [ ] **Step 1: Write the failing tests** in `pocketid_test.go` against `mockidp`: `TestUserInfo` (username and groups returned); `TestUserInfoRejectsTokenWithoutIssuerAudience` and `...WithoutOpenidScope` (`errors.Is(err, ErrInvalidToken)`); `TestUserInfoRejectsExpiredAndGarbage` (same); `TestUserInfoServerErrorIsNotInvalidToken` (a 500 is a plain error, so callers can tell "your token is bad" from "the IdP is down"); `TestVerifyAccessToken` (ok returns the `sub`); `TestVerifyAccessTokenRefuses` (table: audience lacks the API resource, wrong issuer, expired, signed by another key); `TestSendsUserAgent` (every request the client made carries `tunnels-test/1`).
- [ ] **Step 2: Run to verify they fail.** `go test ./internal/pocketid/ -v`. Expected: build failure, `undefined: mockidp.New`.
- [ ] **Step 3: Implement** `httpx.Client` (a `RoundTripper` that sets the header), then `mockidp` (JWTs with `github.com/go-jose/go-jose/v4/jwt`, already in the module graph through go-oidc), then `pocketid.Client`: `oidc.NewProvider` for discovery (pass the `httpx` client with `oidc.ClientContext`); `UserInfo` is a plain `GET` of `provider.UserInfoEndpoint()` with the bearer token through the `httpx` client (go-oidc's own `UserInfo` hides the status code), 401 and 403 -> `ErrInvalidToken`; `VerifyAccessToken` uses `provider.Verifier(&oidc.Config{ClientID: apiResource})` (go-oidc checks that `aud` contains it).
- [ ] **Step 4: Run to verify they pass.** `go test -race ./internal/... -v`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(pocketid): add userinfo and access token verification`.

### Task 4: frps dashboard client

**Files:**
- Create: `internal/frpsapi/frpsapi.go`, `internal/frpsapi/frpsapi_test.go`

**Interfaces:**
- Produces (`package frpsapi`):

  ```go
  func New(baseURL, user, password, userAgent string) *Client
  func (c *Client) OnlineRunIDUser(ctx context.Context, runID string) (user string, online bool, err error)
  func (c *Client) OnlineProxyCount(ctx context.Context, user string) (int, error)
  ```

  Calls (basic auth): `GET /api/v2/clients?runID=<id>&status=online&pageSize=1` (user of `data.items[0]`, offline when `data.total` is 0) and `GET /api/v2/proxies?type=http&user=<user>&status=online&pageSize=1` (`data.total`). Decode with frp's own types, `model.V2PageResp[model.ClientInfoResp]` and `model.V2PageResp[model.V2ProxyResp]` from `github.com/fatedier/frp/server/http/model`, inside an envelope `struct{Code int; Msg string; Data T}`. A non-200 status, a `code` other than 200 or bad JSON is an error.

- [ ] **Step 1: Write the failing tests** with `httptest`: `TestOnlineRunIDUser` (asserts path, the `runID`, `status` and `pageSize` query values and the basic-auth header; online, offline with `total: 0`); `TestOnlineProxyCount` (asserts `type=http`, `user`, `status=online`; returns `total`); `TestErrors` (table: 401, 500, `{"code":500}`, truncated JSON, connection refused, a hang longer than the context deadline: all return an error, never a zero value that reads as "nobody").
- [ ] **Step 2: Run to verify they fail.** `go test ./internal/frpsapi/ -v`. Expected: `undefined: New`.
- [ ] **Step 3: Implement** with `httpx.Client(userAgent, 10*time.Second)` and `url.Values` for the query.
- [ ] **Step 4: Run to verify they pass.** `go test -race ./internal/frpsapi/ -v`. Expected: PASS. (The shapes were checked against a live frps v0.71.0; Task 12 asserts them again against the real server.)
- [ ] **Step 5: Commit.** `feat(frpsapi): query online clients and proxies`.

### Task 5: Account resolution

**Files:**
- Create: `internal/broker/account.go`, `internal/broker/account_test.go`

**Interfaces:**
- Consumes: `names.HandleFromUsername`, `store.User`, `store.ErrNotFound`, `store.ErrHandleTaken`, `pocketid.Identity`.
- Produces (`package broker`):

  ```go
  type IdP interface { UserInfo(ctx context.Context, accessToken string) (pocketid.Identity, error) }
  type Users interface {
      UserBySub(ctx context.Context, sub string) (store.User, error)
      UserByHandle(ctx context.Context, handle string) (store.User, error)
      CreateUser(ctx context.Context, sub, handle string) (store.User, error)
  }
  type Account struct { Sub, Username, Handle string }
  var ErrNotCreator, ErrDisabled, ErrBadHandle error   // a bad or expired token surfaces as pocketid.ErrInvalidToken
  type Resolver struct { IdP IdP; Users Users; CreatorsGroup string; Reserved []string }
  func (r Resolver) Resolve(ctx context.Context, accessToken string) (Account, error)
  func Reason(err error) string   // user-facing text for a refusal; "login unavailable, try again" for anything else
  ```

  `Resolve`: userinfo; the identity must include `CreatorsGroup` (else `ErrNotCreator`); look the user up by `sub`; if unknown, derive the handle with `names.HandleFromUsername` (failure wraps `ErrBadHandle`) and `CreateUser`; a stored user keeps their stored handle even if the username changed or is no longer a valid handle; `Disabled` gives `ErrDisabled`. `Reason` maps `pocketid.ErrInvalidToken` to "your session is not valid; run: tunnel login".

- [ ] **Step 1: Write the failing tests** with fakes: `TestResolveNewUser` (row created with the lowercased handle); `TestResolveExistingUserKeepsHandle` (username changed to `Bob_Smith`, stored handle `bob` still resolves); `TestResolveRefusals` (table: no creators group -> `ErrNotCreator`; disabled -> `ErrDisabled`; username `alice_b`, `a`, `Admin` and `\u212Aevin` -> `ErrBadHandle` and `CreateUser` never called; handle owned by another sub -> `store.ErrHandleTaken`); `TestResolveFailsClosed` (IdP error and store error each return an error that `Reason` maps to "login unavailable, try again"; `pocketid.ErrInvalidToken` maps to the "run: tunnel login" text); `TestReasonMessages` (each refusal's text names what the person can do, e.g. "ask an admin to add you to tunnels-creators").
- [ ] **Step 2: Run to verify they fail.** `go test ./internal/broker/ -run 'Resolve|Reason' -v`. Expected: `undefined: Resolver`.
- [ ] **Step 3: Implement** `Resolver.Resolve` and `Reason` (`errors.Is` on the sentinel errors).
- [ ] **Step 4: Run to verify they pass.** `go test -race ./internal/broker/ -v`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(broker): resolve a token to an account and handle`.

### Task 6: frps plugin hooks

The security core. Pinned by Review Focus 2 and 3.

**Files:**
- Create: `internal/broker/hooks.go`, `internal/broker/hooks_test.go`

**Interfaces:**
- Consumes: `Resolver` (Task 5), `frpsapi` method set, frp's `plugin "github.com/fatedier/frp/pkg/plugin/server"` types (`Request`, `Response`, `LoginContent`, `NewProxyContent`, `CloseProxyContent`, `OpLogin`, `OpNewProxy`, `OpCloseProxy`).
- Produces:

  ```go
  type Frps interface {
      OnlineRunIDUser(ctx context.Context, runID string) (user string, online bool, err error)
      OnlineProxyCount(ctx context.Context, user string) (int, error)
  }
  type Hooks struct {
      Resolver Resolver; Frps Frps; Secret string
      MaxTunnelsPerUser int; BandwidthLimit string; Log *slog.Logger
  }
  func (h *Hooks) ServeHTTP(w http.ResponseWriter, r *http.Request)   // path /plugin/<secret>
  ```

  Behaviour. A wrong or missing secret is 404 (constant-time compare). Unknown op, bad JSON or a non-POST is 400. Every decision is 200.
  - **Login:** `privilege_key` is the access token (empty: reject "missing token"); `Resolve` it (errors -> reject with `Reason`); if `run_id` is set, `OnlineRunIDUser`: an error rejects, online under a different handle rejects "run id belongs to another session", offline or the same handle passes; set `user` to the handle and return the whole `LoginContent` with `unchange:false`.
  - **NewProxy:** `user.user` is the handle stored at Login. The type must be `http` with no `custom_domains` and no `locations`; `proxy_name` must equal `ProxyName(handle, n)` for some `n` that is `default` or a valid tunnel name, and `subdomain` must equal `Label(handle, n)`; `OnlineProxyCount(handle)` at or above `MaxTunnelsPerUser` rejects ("tunnel limit of N reached"), an error rejects; set `bandwidth_limit` to `BandwidthLimit` and `bandwidth_limit_mode` to `server`; return the whole content with `unchange:false`.
  - **CloseProxy:** log, answer `unchange:true`.
  - Each decision logs op, handle, sub, result and reason (never the token).

- [ ] **Step 1: Write the failing tests** with fake `IdP`/`Users`/`Frps` and `httptest`:
  - `TestLoginRewritesUserAndKeepsEverythingElse`: a request with `hostname`, `os`, `arch`, `version`, `timestamp`, `run_id` (empty), `metas`, `pool_count` and `privilege_key=tok` comes back with `user` = the handle and every other field identical; `unchange` is false.
  - `TestLoginClaimedUserIsIgnored`: the request says `user=victim`; the response says the caller's handle.
  - `TestLoginRefusals`: missing token, not a creator, disabled, bad username, handle taken, IdP error, store error: each `reject:true` with the `Reason` text and HTTP 200.
  - `TestLoginRunID`: online under another handle -> reject; online under the same handle -> accept; offline -> accept; dashboard error -> reject; empty run ID -> the dashboard is not called.
  - `TestNewProxy` table (handle `alice`, stored user `alice`): accept `alice.default`/`alice`, `alice.blog`/`alice-blog`; reject `bob.default`/`alice`, `alice.default`/`bob`, `Alice.default`/`alice`, `alice.Default`/`alice`, `alice.default`/`alice-default`, `alice.blog`/`alice`, `alice.a_b`/`alice-a_b`, `alice.`/`alice`, type `tcp`, `https`, `tcpmux`, `udp`, `stcp`, custom domains set, locations set, count at the cap, count error. The accepted responses carry `bandwidth_limit=10MB` and `bandwidth_limit_mode=server`.
  - `TestSecret`: wrong secret and empty secret give 404, and the body leaks nothing.
  - `TestCloseProxy` and `TestLogsNeverContainTheToken` (capture the slog output of a Login and assert the token string is absent).
- [ ] **Step 2: Run to verify they fail.** `go test ./internal/broker/ -run 'Login|NewProxy|Secret|CloseProxy|Logs' -v`. Expected: `undefined: Hooks`.
- [ ] **Step 3: Implement** `Hooks.ServeHTTP`: decode `plugin.Request` with `Content json.RawMessage`, switch on `op`, decode the matching content type, build `plugin.Response`.
- [ ] **Step 4: Run to verify they pass.** `go test -race ./internal/broker/ -v`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(broker): enforce names and ownership in the frps plugin`.

### Task 7: `/authz`

Pinned by Review Focus 1 and 4.

**Files:**
- Create: `internal/broker/authz.go`, `internal/broker/authz_test.go`

**Interfaces:**
- Consumes: `Users` (Task 5), `names.SiteLabel`, `names.ParseLabel`.
- Produces: `type Authz struct { Users Users; SitesDomain string; Log *slog.Logger }` and `func (a Authz) ServeHTTP(w http.ResponseWriter, r *http.Request)` for any method.

  Algorithm: `SiteLabel(X-Forwarded-Host)` -> `ParseLabel` -> `UserByHandle(handle)`; allow only if the owner exists, is not disabled, `X-Tunnels-Sub` has exactly one non-empty value equal to the owner's `sub`, and `X-Tunnels-User` has exactly one non-empty value; the answer is 200 with `X-Tunnel-User` set to that username and an empty body. Any other result is 403 with an empty body and no distinguishing header. `UserByHandle` failing with anything but `ErrNotFound` is 503. Traefik's forwardAuth sends the original request headers unless `authRequestHeaders` is set, so plan 2b either leaves it unset or lists the two `X-Tunnels-*` headers. Log every decision once (allow or deny, the label, a reason class, the visitor's `sub`); no other header values.

- [ ] **Step 1: Write the failing tests:** `TestOwnerAllowed` (200, `X-Tunnel-User: alice`, empty body); `TestDeniedCases` table, every row asserting status 403, an empty body and identical response headers to the unknown-owner row: another user's sub; unknown owner label; disabled owner; host outside the sites domain; host with port, trailing dot, extra label or comma; label `alice-default`; missing `X-Tunnels-Sub`; empty `X-Tunnels-Sub`; two `X-Tunnels-Sub` values (one matching); missing or duplicated `X-Tunnels-User`; owner's sub in the wrong case. `TestUppercaseHostIsNormalised` (`Alice-Blog.W.Tunnels.Layertwo.Dev` for owner `alice` is allowed). `TestStoreErrorIs503` (error from `UserByHandle` -> 503, empty body).
- [ ] **Step 2: Run to verify they fail.** `go test ./internal/broker/ -run 'Owner|Denied|Uppercase|StoreError' -v`. Expected: `undefined: Authz`.
- [ ] **Step 3: Implement** `Authz.ServeHTTP` (read headers with `r.Header.Values`).
- [ ] **Step 4: Run to verify they pass.** `go test -race ./internal/broker/ -v`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(broker): owner-only forwardAuth decision`.

### Task 8: Broker HTTP surface and `cmd/broker`

**Files:**
- Create: `internal/broker/config.go`, `internal/broker/server.go`, `internal/broker/server_test.go`, `internal/broker/config_test.go`, `cmd/broker/main.go`

**Interfaces:**
- Consumes: everything above, `pocketid.Client`, `store.Store`, `frpsapi.Client`.
- Produces:

  ```go
  type Config struct { /* one field per env variable in Global Constraints */ }
  func LoadConfig(getenv func(string) string) (Config, error)   // error names the variable
  type TokenVerifier interface { VerifyAccessToken(ctx context.Context, raw string) (sub string, err error) }
  type Deps struct { IdP IdP; Verifier TokenVerifier; Users Users; Frps Frps; Log *slog.Logger }
  func NewHandler(cfg Config, d Deps) http.Handler
  ```

  Routes: `POST /plugin/` -> `Hooks`; `/authz` -> `Authz`; `GET /api/me` -> bearer token, `VerifyAccessToken` (401 `{"error":"invalid token"}` on failure), then `Resolver.Resolve` (refusals 403 `{"error":"<Reason>"}`, infrastructure errors 503) and `200 {"sub","username","handle"}`; `GET /.well-known/tunnels.json` -> `{"issuer","cli_client_id","api_resource","service_host","sites_domain","min_cli_version"}`; `GET /healthz` -> 200 `ok` (no dependency calls); anything else 404. `cmd/broker/main.go` loads the config, builds the clients, wires `NewHandler`, serves with `ReadHeaderTimeout: 10s`, shuts down on SIGTERM, and `--version` prints `version` (set by `-ldflags -X main.version`).

- [ ] **Step 1: Write the failing tests:** `TestLoadConfig` (all variables set -> struct; each required one missing -> error naming it; defaults for the optional ones; `MAX_TUNNELS_PER_USER=x` -> error; `RESERVED_HANDLES` split on commas, trimmed, lowercased); `TestRoutes` with `httptest` and fakes (`/plugin/<secret>` reaches the hooks and `/plugin/wrong` is 404; `/authz` reaches authz; unknown path 404; `healthz` 200 with the fakes erroring); `TestAPIMe` (no header 401; garbage token 401; token for the wrong audience 401; valid token for a non-creator 403 with the reason; valid creator 200 with the handle; store down 503); `TestWellKnown` (exact JSON keys and values from config).
- [ ] **Step 2: Run to verify they fail.** `go test ./internal/broker/ -run 'LoadConfig|Routes|APIMe|WellKnown' -v`. Expected: `undefined: LoadConfig`.
- [ ] **Step 3: Implement** `config.go`, `server.go` (Go 1.22 `ServeMux` patterns), `cmd/broker/main.go`.
- [ ] **Step 4: Run to verify they pass.** `go test -race ./... -v` and `go build ./cmd/broker`. Expected: PASS, binary builds.
- [ ] **Step 5: Commit** `feat(broker): serve hooks, authz, me and bootstrap`, push, finish PR 1 (Tasks 1-8).

### Task 9: CLI authentication

Pinned by Review Focus 5.

**Files:**
- Create: `internal/auth/auth.go`, `internal/auth/store.go`, `internal/auth/auth_test.go`, `internal/auth/store_test.go`

**Interfaces:**
- Consumes: `mockidp` (tests), `httpx`, `go-oidc` discovery, `oauth2`.
- Produces (`package auth`):

  ```go
  type Bootstrap struct { Issuer, CLIClientID, APIResource, ServiceHost, SitesDomain, MinCLIVersion string } // json: issuer, cli_client_id, api_resource, service_host, sites_domain, min_cli_version
  func Discover(ctx context.Context, hc *http.Client, baseURL string) (Bootstrap, error)  // GET <baseURL>/.well-known/tunnels.json
  type Me struct { Sub, Username, Handle string }
  func GetMe(ctx context.Context, hc *http.Client, baseURL, accessToken string) (Me, error) // error text = the server's {"error"} message

  type Tokens struct { AccessToken, RefreshToken, Handle, Server string }
  var ErrNotLoggedIn error
  type Store struct{ Dir string }   // tokens.json and access-token, both 0600
  func (s Store) Load() (Tokens, error)
  func (s Store) Save(t Tokens) error        // tokens.json first, then access-token; both atomic
  func (s Store) Clear() error
  func (s Store) AccessTokenPath() string

  type OIDC struct { Issuer, ClientID, Resource string; HTTP *http.Client }
  func (o OIDC) DeviceLogin(ctx context.Context, out io.Writer) (Tokens, error)  // prints the URL and code, polls until approved
  func (o OIDC) Refresh(ctx context.Context, refreshToken string) (Tokens, error) // returns the rotated refresh token
  func RefreshStored(ctx context.Context, s Store, o OIDC) (Tokens, error)        // Load, Refresh, Save
  func KeepFresh(ctx context.Context, s Store, o OIDC, every time.Duration, onErr func(error))
  ```

  `DeviceLogin` uses `oauth2.Config.DeviceAuth` with `oauth2.SetAuthURLParam("resource", o.Resource)` and `DeviceAccessToken`; `Refresh` uses an `oauth2.Config` token source seeded with only the refresh token and no `resource` (Pocket ID keeps the original audience on refresh); endpoints come from `oidc.NewProvider` (the device endpoint from `provider.Claims`); `AuthStyleInParams`, no secret. `RefreshStored` always `Load`s first so a token rotated by another running process is the one used. A failed refresh leaves the stored files untouched.

- [ ] **Step 1: Write the failing tests** (`mockidp`, temp dirs):
  - `TestDiscover` (ok; 404; bad JSON), `TestGetMe` (ok; 403 body `{"error":"..."}` surfaces as the error text).
  - `TestDeviceLogin`: the mock approves the code after two polls; tokens returned; the output contains the verification URL and user code; `TestDeviceLoginDenied` and `...Expired` return errors; the request carried `resource` and `client_id` and no secret.
  - `TestRefreshRotates`: returns a different refresh token, same audience; `TestRefreshFailureKeepsFiles` (after `RevokeUser`, `RefreshStored` errors and `tokens.json` and `access-token` are byte-identical to before).
  - `TestStoreFiles` (skip the mode assertion on windows): after `Save`, both files exist with mode 0600, the directory holds nothing else (no temp leftovers), `Load` round-trips, `Load` on an empty dir is `ErrNotLoggedIn`, `Clear` removes both.
  - `TestTwoProcessesShareRotation`: with a mock that invalidates the old refresh token at once, two `RefreshStored` calls in a row both succeed (the second used the first's saved token).
  - `TestKeepFreshRewritesAccessToken`: with `mock.SetTTL(time.Second)` and `every = 50ms`, the `access-token` file content changes at least twice within 500 ms and always equals a token the mock issued; cancelling the context stops it; `onErr` is called (not fatal) when a refresh fails.
- [ ] **Step 2: Run to verify they fail.** `go test ./internal/auth/ -v`. Expected: `undefined: Discover`.
- [ ] **Step 3: Implement.** Atomic write helper: `os.CreateTemp` in the same directory, `Chmod 0600`, write, `Sync`, `os.Rename`.
- [ ] **Step 4: Run to verify they pass.** `go test -race ./internal/auth/ -v`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(auth): device login, token files and refresh`.

### Task 10: frp client config and runner

**Files:**
- Create: `internal/tunnel/tunnel.go`, `internal/tunnel/cabundle.go`, `internal/tunnel/tunnel_test.go`

**Interfaces:**
- Consumes: `names`, frp `client`, `config`, `config/source`, `config/v1`, `config/v1/validation`, `policy/security`, `x509roots/fallback/bundle`.
- Produces (`package tunnel`):

  ```go
  type Options struct {
      ServerHost string; ServerPort int; Protocol string   // "tunnels.layertwo.dev", 443, "wss" ("tcp" in tests)
      Handle, Name string                                    // Name "" = default tunnel
      LocalPort int; TokenFile, CAFile string
      HeartbeatInterval int                                  // 0 means 30
  }
  func Build(o Options) (*v1.ClientCommonConfig, []v1.ProxyConfigurer, error)
  type Status struct { Phase, Err string }                   // frp's proxy phase: "running", "start error", ...
  func Run(ctx context.Context, o Options, onStatus func(Status)) error
  func WriteCABundle(dir string) (path string, err error)    // PEM of the Mozilla roots, 0600
  ```

  `Build` marshals a nested map to JSON with exactly the keys of Global Constraints (`serverAddr`, `serverPort`, `user`, `transport.{protocol,heartbeatInterval,tls.trustedCaFile}`, `auth.{method,additionalScopes,oidc.tokenSource.{type,file.path}}`, one `proxies` entry `{name, type:"http", localIP:"127.0.0.1", localPort, subdomain: names.Label(handle,name), requestHeaders.set.x-forwarded-proto:"https"}`; proxy `name` is the tunnel name or `default`), loads it with `config.LoadConfigure(b, &v1.ClientConfig{}, true)`, then `Complete`, `config.CompleteProxyConfigurers` and `validation.ValidateAllClientConfig(..., security.NewUnsafeFeatures(nil))`. It refuses an invalid tunnel name, a bad port, an empty handle, and a `wss` run without `CAFile`. `Run` follows `cmd/frpc/sub/root.go`: `source.NewConfigSource().ReplaceAll`, `source.NewAggregator`, `client.NewService(client.ServiceOptions{Common, ConfigSourceAggregator, UnsafeFeatures})`, a goroutine that calls `GracefulClose(500ms)` when `ctx` ends, a poller on `svr.StatusExporter().GetProxyStatus(<proxy name without the user prefix>)` that reports each change of `Phase`/`Err` (so a reject arrives as `Status{"start error", "name alice.default is not yours"}`), and `svr.Run(ctx)`; `frp/pkg/util/log.InitLogger("console", "warn", 1, true)` first.

- [ ] **Step 1: Write the failing tests:** `TestBuildFields` (loaded config has `User=alice`, `Transport.Protocol=wss`, `HeartbeatInterval=30`, `TLS.TrustedCaFile=<path>`, `Auth.Method=oidc`, scopes `[HeartBeats]`, `Auth.OIDC.TokenSource.File.Path`, proxy `*v1.HTTPProxyConfig` with `SubDomain=alice-blog`, `LocalPort`, `RequestHeaders.Set["x-forwarded-proto"]=="https"`, `Name=="blog"`); `TestBuildDefaultTunnel` (`Name==""` gives proxy name `default` and subdomain `alice`); `TestBuildWindowsPaths` (`C:\Users\a b\AppData\Roaming\tunnels\cacert.pem` survives); `TestBuildRefuses` (table: `wss` without CAFile, name `default`, name `Blog`, port 0 and 65536, empty handle); `TestWriteCABundle` (file is 0600, parses as PEM with at least 100 certificates, includes a subject containing `ISRG Root X1`, and a second call rewrites nothing).
- [ ] **Step 2: Run to verify they fail.** `go test ./internal/tunnel/ -v`. Expected: `undefined: Build`.
- [ ] **Step 3: Implement** `Build`, `Run` and `WriteCABundle` (iterate `bundle.Roots()`, PEM-encode each `Certificate`). `go get golang.org/x/crypto/x509roots/fallback github.com/fatedier/frp@v0.71.0 && go mod tidy`.
- [ ] **Step 4: Run to verify they pass.** `go test -race ./internal/tunnel/ -v`, then cross-compile once: `for t in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 linux/arm windows/amd64 windows/arm64; do CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} go build -trimpath -o /dev/null ./internal/tunnel || echo FAIL $t; done`. Expected: PASS and no `FAIL` lines (design Verification 9).
- [ ] **Step 5: Commit.** `feat(tunnel): build and run the embedded frp client`.

### Task 11: CLI commands and `cmd/tunnel`

**Files:**
- Create: `internal/cli/cli.go`, `internal/cli/cli_test.go`, `cmd/tunnel/main.go`

**Interfaces:**
- Consumes: `auth`, `tunnel`, `names`, `httpx`, `github.com/spf13/pflag`.
- Produces:

  ```go
  type Env struct {
      Stdout, Stderr io.Writer
      ConfigDir, DefaultServer, Version string   // ConfigDir "" -> os.UserConfigDir()/tunnels, TUNNELS_CONFIG_DIR overrides
      HTTP *http.Client
  }
  func Main(args []string, env Env) int          // exit code: 0 ok, 1 runtime error, 2 usage
  ```

  A `--server` value that starts with `http://` or `https://` is used as the base URL, otherwise `https://<value>`. Commands: `login`, `up PORT [--name NAME]`, `logout`, `version`. `login`: `Discover`, `OIDC.DeviceLogin`, `GetMe`, `Store.Save` with `Handle` and `Server`; prints `Logged in as <username> (<handle>)`. `up`: validate the port and `names.ValidTunnelName`; `Store.Load` (not logged in: `not logged in; run: tunnel login`); `RefreshStored` (on failure print `could not refresh your session (<error>); run: tunnel login` and exit 1); `WriteCABundle(ConfigDir)`; `go KeepFresh(..., 30*time.Minute, ...)`; `tunnel.Run` with `Options` from the bootstrap (`ServerHost` = `service_host`, 443, `wss`, `TokenFile` = `Store.AccessTokenPath()`, `CAFile` = the `WriteCABundle` path; the `auth.OIDC` for refresh takes `Issuer`, `CLIClientID` and `APIResource` from the same document); print `https://<Label>.<sites_domain>` when the status becomes `running`; print each `start error` once on stderr; SIGINT or SIGTERM cancels. When `tunnel.Run` returns an error (a refused first login: `login to the server failed: <the broker's reason>`), print it on stderr and exit 1; there is no retry loop (amendment 3). `logout`: `Store.Clear`. `version`: `tunnel <Version> (server <DefaultServer>)`. `cmd/tunnel/main.go` has `var version = "dev"`, `var defaultServer = "tunnels.layertwo.dev"` (both set by `-ldflags -X`) and calls `os.Exit(cli.Main(os.Args[1:], cli.Env{...}))`.

- [ ] **Step 1: Write the failing tests** (stub `httptest` servers for the bootstrap and `/api/me`, `mockidp` for Pocket ID, temp config dir): `TestLoginWritesTokens` (output contains the verification URL, `Logged in as alice (alice)`, files 0600, `tokens.json` has the handle); `TestLoginShowsServerRefusal` (`/api/me` 403 `{"error":"ask an admin to add you to tunnels-creators"}` -> exit 1 and that text on stderr, no tokens saved); `TestUpArgumentErrors` (table, all exit 2 with a usage line: no port, port `abc`, `0`, `65536`, `--name Blog`, `--name default`); `TestUpNotLoggedIn` (exit 1, `run: tunnel login`); `TestLogoutClears`; `TestVersion` (`tunnel 1.2.3 (server tunnels.layertwo.dev)`); `TestUnknownCommand` (exit 2).
- [ ] **Step 2: Run to verify they fail.** `go test ./internal/cli/ -v`. Expected: `undefined: Main`.
- [ ] **Step 3: Implement** `cli.Main` with `pflag.NewFlagSet` per command (interspersed flags: `tunnel up 3000 --name blog`), and `cmd/tunnel/main.go`.
- [ ] **Step 4: Run to verify they pass.** `go test -race ./... -v`; `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=0.0.0-test" -o /tmp/tunnel ./cmd/tunnel && /tmp/tunnel version`. Expected: PASS and `tunnel 0.0.0-test (server tunnels.layertwo.dev)`.
- [ ] **Step 5: Commit** `feat(cli): add login, up, logout and version`, push, finish PR 2 (Tasks 9-11).

### Task 12: End-to-end test

Pinned by Review Focus 3. Design Verification 10.

**Files:**
- Create: `e2e/e2e_test.go` (`//go:build e2e`)
- Modify: `go.mod` (`go get -tool github.com/fatedier/frp/cmd/frps@v0.71.0`), `.github/workflows/ci.yml` (job `e2e`: Postgres service, `go test -tags e2e ./e2e/ -timeout 10m -v`)

**Interfaces:**
- Consumes: `broker.NewHandler`, `store`, `pocketid`, `frpsapi`, `mockidp`, `tunnel.Run`, `auth.KeepFresh`.

  `TestMain` skips unless `TEST_DATABASE_URL` is set, then builds frps once: `go build -tags noweb -o <tmp>/frps github.com/fatedier/frp/cmd/frps`. `newStack(t)` starts: `mockidp` with users `alice` and `bob` (both in `tunnels-creators`) and `carol` (no group); the store on a fresh schema; the broker handler on `httptest` with its real `pocketid`, `store` and `frpsapi`; frps on free ports with `auth.method="oidc"`, `auth.oidc.issuer=<mock URL>`, `auth.oidc.audience="https://tunnels.layertwo.dev"`, `auth.additionalScopes=["HeartBeats"]`, `transport.heartbeatTimeout=90`, `subDomainHost="w.test"`, the dashboard on a free port with a user and password, and `[[httpPlugins]]` pointing at the broker's `/plugin/<secret>` for Login, NewProxy and CloseProxy; and a backend `httptest` server that answers `hello`. A helper starts `tunnel.Run` with `Protocol:"tcp"`, `HeartbeatInterval:1` and a token file, returns a channel of `Status`, and stops it at cleanup.

- [ ] **Step 1: Write the failing tests:**
  - `TestOwnerTunnelServesTraffic`: alice's token, status `running`; `GET http://127.0.0.1:<vhost>/` with `Host: alice.w.test` returns `hello`; `Host: bob.w.test` returns 404.
  - `TestCannotTakeAnotherUsersName`: bob's token with `Options.Handle="alice"` (a modified client): status `start error` containing `not yours`; alice's own tunnel, started first, keeps serving.
  - `TestRefusedLogins` (table, each `Run` returns an error): token from `mock.Issue(sub, IssueOpts{Audience: []string{mock.URL}})` (lacks the API resource: the broker lets it through, frps refuses, error mentions `audience`); expired token (`IssueOpts{TTL: -time.Minute}`) and garbage token (the broker refuses: error mentions `tunnel login`); carol, not a creator (error mentions `tunnels-creators`).
  - `TestRunIDTakeover`: with alice's tunnel online, read her run ID from the dashboard (`/api/v2/clients?user=alice&status=online`); `frpsapi.OnlineRunIDUser` returns (`alice`, true); a Login posted to the broker's `/plugin/<secret>` for bob carrying that run ID is rejected, and the same Login for alice is accepted.
  - `TestTokenRefreshKeepsTunnelAlive`: `mock.SetTTL(6*time.Second)`, `auth.KeepFresh` runs every 2 s against a store holding alice's tokens; after 15 s the tunnel still serves traffic and its status never left `running`.
  - `TestTunnelLimit`: `MAX_TUNNELS_PER_USER=2`; alice's third distinct tunnel name gets `start error` containing `limit`.
- [ ] **Step 2: Run to verify they fail.** `TEST_DATABASE_URL=... go test -tags e2e ./e2e/ -v`. Expected: build failure from the missing helpers, then (after the stack helper exists) FAIL on the first assertion.
- [ ] **Step 3: Implement** `newStack` and the helpers; fix whatever the tests find in Tasks 2-10 (a failing e2e is a defect in an earlier task: fix it there, with a unit test that failed first).
- [ ] **Step 4: Run to verify they pass.** Same command. Expected: PASS.
- [ ] **Step 5: Commit.** `test(e2e): prove ownership, refusals and refresh against a real frps`.

### Task 13: Images, releases and CI

Design Verification 9 (every release target) and the supply-chain controls.

**Files:**
- Create: `Dockerfile.broker`, `Dockerfile.frps`, `.dockerignore`, `.goreleaser.yaml`, `.github/workflows/image.yml`, `.github/workflows/release.yml`
- Modify: `.github/workflows/ci.yml` (job `release-check`)

- [ ] **Step 1: `Dockerfile.broker`** (the broker; the binary is built in the workflow, so no Go image is needed):

  ```dockerfile
  FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
  ARG TARGETARCH
  COPY dist/broker-linux-${TARGETARCH} /broker
  USER 65532:65532
  ENTRYPOINT ["/broker"]
  ```

  `.dockerignore`: `*` then `!dist`. **`Dockerfile.frps`** (checked locally with podman: builds, `--version` prints `0.71.0`, no shell, runs as 65532, starts under `--read-only --cap-drop ALL` with the production ConfigMap):

  ```dockerfile
  FROM ghcr.io/fatedier/frps:v0.71.0@sha256:cd8b947ba61678b200baa4f71ccc33f3c52e4e2cc0059700ba3b8354e36af7c3 AS frps

  FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
  COPY --from=frps /usr/bin/frps /usr/bin/frps
  ENTRYPOINT ["/usr/bin/frps"]
  ```

- [ ] **Step 2: `.goreleaser.yaml`** (checked with GoReleaser v2.18.3: seven archives plus `checksums.txt`, ldflags injected):

  ```yaml
  version: 2
  builds:
    - id: tunnel
      main: ./cmd/tunnel
      binary: tunnel
      env: [CGO_ENABLED=0]
      flags: [-trimpath]
      ldflags:
        - -s -w -X main.version={{ .Version }} -X main.defaultServer=tunnels.layertwo.dev
      goos: [darwin, linux, windows]
      goarch: [amd64, arm64, arm]
      goarm: ["7"]
      ignore:
        - {goos: darwin, goarch: arm}
        - {goos: windows, goarch: arm}
  archives:
    - id: tunnel
      formats: [tar.gz]
      format_overrides:
        - {goos: windows, formats: [zip]}
      name_template: "tunnel_{{ .Version }}_{{ .Os }}_{{ .Arch }}{{ if .Arm }}v{{ .Arm }}{{ end }}"
  checksum:
    name_template: checksums.txt
  changelog:
    use: github
  ```

- [ ] **Step 3: Workflows.** `ci.yml` job `release-check`: `goreleaser/goreleaser-action` with `args: check` then `args: release --snapshot --clean --skip=publish`, and assert `ls dist/*.tar.gz dist/*.zip | wc -l` is 7. `release.yml`: on tags `v*`, `permissions: contents: write`, `fetch-depth: 0`, `goreleaser release --clean`. `image.yml`: start from `layertwo/homelab` `.github/workflows/oidc-saml-bridge-docker-image.yml` (pinned action digests, buildx, GHCR login, cosign) with these changes: a matrix over `{broker, frps}`; for `broker`, a step before the build runs `CGO_ENABLED=0 GOOS=linux GOARCH=$a go build -trimpath -ldflags "-s -w -X main.version=${GITHUB_SHA::7}" -o dist/broker-linux-$a ./cmd/broker` for `a` in `amd64 arm64`; `file: Dockerfile.broker` or `Dockerfile.frps`; `platforms: linux/amd64,linux/arm64`; tags `latest`, `sha-<short>` and `v*` tags on release; push and sign by digest only outside pull requests; a smoke step on pull requests (single platform, `load: true`) runs the image with `--version` (broker prints its version, frps prints `0.71.0`).
- [ ] **Step 4: Verify locally what can be.** `docker build` or `podman build -f Dockerfile.frps .` then `run --rm <image> --version` prints `0.71.0`; build the broker binary for linux/arm64 into `dist/` and `podman build -f Dockerfile.broker .` (add `--build-arg TARGETARCH=arm64` if the builder leaves it empty) then `run --rm <image> --version` prints a version. Expected: both succeed.
- [ ] **Step 5: Commit and open PR 3** (Tasks 12-13) `build: add images, release and e2e`. After the human partner merges and `image` has run on `mainline`: make both GHCR packages public (package settings, so the cluster can pull without credentials) and check `curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $(curl -s 'https://ghcr.io/token?service=ghcr.io&scope=repository:layertwo/tunnels-broker:pull' | jq -r .token)" https://ghcr.io/v2/layertwo/tunnels-broker/manifests/latest` returns 200.
- [ ] **Step 6: First release.** Tag `v0.1.0` (human partner), wait for `release`; `gh release view v0.1.0 --json assets -q '.assets[].name'` lists seven archives and `checksums.txt`; download the darwin/arm64 archive, check its hash against `checksums.txt`, and `./tunnel version` prints `tunnel 0.1.0 (server tunnels.layertwo.dev)`. Hand the two image digests (`gh api /users/layertwo/packages/container/tunnels-broker/versions` or the `image` run summary) to plan 2b.

---

## Not in this plan

Sharing (`shares` table, `/api/shares`, `share`, `unshare`, `list`) is plan 3. `/install.sh`, the Ping-hook kill switch, heartbeat revocation proven end to end, machine clients, rate limits and Gatus are plan 4. The homelab manifests are plan 2b. `MIN_CLI_VERSION` is served and not enforced.
