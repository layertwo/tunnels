# Tunnels Phase 2 Implementation Plan: sharing

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a creator share a tunnel with a Pocket ID username or group, and let `/authz` admit a visitor who is the owner or has been shared with.

**Architecture:** A new `shares` table in Postgres, a `Shares` interface the broker's `/authz` consults, `GET`/`PUT`/`DELETE /api/shares` on the broker, and `share`/`unshare`/`list` in the CLI. Group shares need the visitor's groups forwarded to `/authz`, which is a homelab middleware change.

**Tech Stack:** Go 1.26, `github.com/jackc/pgx/v5`, Postgres, `github.com/spf13/pflag`, the standard library.

**Spec:** `docs/design.md` (the sections "Broker" — the `/api/shares` and `/authz` paragraphs and the data model — and "Phase 2" under Phasing).

## Global Constraints

- Module `github.com/layertwo/tunnels`, `go 1.26.0`, default branch `mainline`, commits `feat(scope): ...`, one pull request per task.
- The `shares` table is exactly the design's:
  `owner_sub text references users(sub) on delete cascade`, `tunnel text not null default ''`, `kind text check (kind in ('user','group'))`, `grantee text not null`, `created_at timestamptz not null default now()`, primary key `(owner_sub, tunnel, kind, grantee)`.
- The default tunnel is `''` in the store and on the wire; `names.Default` ("default") never appears as a stored tunnel.
- `/authz` allows when: the visitor's `sub` equals the owner's; **or** a `kind='user'` share's `grantee` equals the visitor's username, case-insensitively; **or** a `kind='group'` share's `grantee` equals one of the visitor's group Names exactly. Everything else is the same empty 403. A store error is 503.
- Groups travel as the `X-Tunnels-Groups` header: possibly several values, each possibly comma-separated; a group name containing a comma is unsupported. Names are matched exactly.
- `PUT` and `DELETE /api/shares` are idempotent. Bodies take `{"tunnel","kind","grantee"}`; `tunnel` is `""` or a `names.ValidTunnelName`; `kind` is `user` or `group`; `grantee` is non-empty and, for `group`, contains no comma.
- `/api/shares` acts only on the caller's own rows (`owner_sub` = the caller's `sub`); a bearer token is verified by `Resolver.Resolve` exactly as `/api/me` does.
- Tests: `go test -race ./...`, table-driven. Postgres tests read `TEST_DATABASE_URL` and skip when unset. The end-to-end test is behind the `e2e` tag.

## Review Focus

1. A username shared in one case must be admitted in any case, and must **not** admit a name that only shares a prefix (`bob` must not admit `bobby`).
2. Group grants match **exactly** — a group whose name is a substring of another must not match it, and a comma inside a `grantee` must never split into two groups.
3. Idempotency: `PUT` twice and `DELETE` a missing row are both non-errors.
4. The default tunnel is `''` everywhere — never `"default"` — or the share never matches the label that `/authz` derives.
5. Fail closed: any store error in the `/authz` share lookup is 503, never an allow.

---

### Task 1: The `shares` table and store methods

**Files:**
- Create: `internal/store/migrations/002_shares.sql`
- Modify: `internal/store/store.go`
- Modify: `internal/store/store_test.go`

**Interfaces:**
- Produces:

  ```go
  type Share struct {
      Tunnel  string `json:"tunnel"`  // "" is the default tunnel
      Kind    string `json:"kind"`    // "user" or "group"
      Grantee string `json:"grantee"`
  }
  func (s *Store) PutShare(ctx context.Context, ownerSub string, sh Share) error
  func (s *Store) DeleteShare(ctx context.Context, ownerSub string, sh Share) error
  func (s *Store) SharesByOwner(ctx context.Context, ownerSub string) ([]Share, error) // ordered tunnel, kind, grantee
  func (s *Store) ShareMatches(ctx context.Context, ownerSub, tunnel, username string, groups []string) (bool, error)
  ```

- [ ] **Step 1: Write the failing tests** in `internal/store/store_test.go` (same `newStore(t)` helper, Postgres-gated): `TestPutShareIsIdempotent` (twice, one row); `TestDeleteShareIsIdempotent` (delete a row that is not there is nil); `TestSharesByOwnerOrders` (three rows come back ordered by tunnel, kind, grantee; another owner's row is absent); `TestShareMatchesUserIsCaseInsensitive` (`grantee "Bob"` matches username `bob`); `TestShareMatchesIsExact` (`grantee "bob"` does not match `bobby`); `TestShareMatchesGroupIsExact` (`grantee "family"` matches groups `{"work","family"}`, not `{"family-admins"}`); `TestShareMatchesWrongTunnel` (`tunnel "blog"` does not match `""`); `TestShareMatchesError` (a closed store returns an error, not false).

- [ ] **Step 2: Run them to verify they fail.** `TEST_DATABASE_URL=... go test ./internal/store/ -run Share -v`. Expected: build failure, `undefined: PutShare`.

- [ ] **Step 3: Implement.** Migration `002_shares.sql` is the design's `create table shares (...)` exactly. `PutShare` runs `insert into shares (owner_sub, tunnel, kind, grantee) values ($1,$2,$3,$4) on conflict (owner_sub, tunnel, kind, grantee) do nothing`. `DeleteShare` runs `delete from shares where owner_sub=$1 and tunnel=$2 and kind=$3 and grantee=$4`. `SharesByOwner` selects and scans the three columns. `ShareMatches` runs one query:

  ```sql
  select exists (
      select 1 from shares
      where owner_sub = $1 and tunnel = $2
        and ((kind = 'user' and lower(grantee) = lower($3))
          or (kind = 'group' and grantee = any($4)))
  )
  ```

  scanning into a `bool`; a query error is wrapped, never turned into `false`.

- [ ] **Step 4: Run them to verify they pass.** `TEST_DATABASE_URL=... go test -race ./internal/store/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `feat(store): keep tunnel shares`.

---

### Task 2: `/authz` admits a shared visitor

**Files:**
- Modify: `internal/broker/authz.go`, `internal/broker/authz_test.go`
- Modify: `internal/broker/server.go` (pass `Shares` to `Authz`)

**Interfaces:**
- Consumes: `store.Share` (Task 1).
- Produces:

  ```go
  type Shares interface {
      ShareMatches(ctx context.Context, ownerSub, tunnel, username string, groups []string) (bool, error)
  }
  ```
  `Authz.Shares Shares`; `Authz.decideSite` admits the owner, a shared user, or a shared group.

- [ ] **Step 1: Write the failing tests.** In `authz_test.go`, with `SitesDomain = "w.tunnels.example"` and a fake `Shares`: `TestSharedUserAllowed` (`alice-blog.w.tunnels.example`, `X-Tunnels-Sub` a stranger, `X-Tunnels-User: bob`, fake says `bob` is shared → 200); `TestSharedUserCaseInsensitive` (`Bob`); `TestSharedGroupAllowed` (groups header `work,family`, fake matches `family` → 200); `TestGroupsAcrossHeaderValues` (two `X-Tunnels-Groups` values); `TestNotSharedDenied` (fake false → 403); `TestShareLookupErrorIs503`; and `TestOwnerStillAllowed` (the owner path does not call `Shares`).

- [ ] **Step 2: Run them to verify they fail.** `go test ./internal/broker/ -run 'Shared\|Groups\|Share' -v`. Expected: FAIL.

- [ ] **Step 3: Implement.** Add the `Shares` field. In `decideSite`, after the owner is found and not disabled, replace the `owner.Sub != o.sub` case with: if the sub matches, allow `owner`; otherwise call `a.Shares.ShareMatches(ctx, owner.Sub, tunnel, users[0], groupsOf(r))` (the `tunnel` comes from `names.ParseLabel`), allow `shared` on true, deny `not_owner` on false, and `status 503` on error. Add `groupsOf(r) []string` that reads `r.Header.Values("X-Tunnels-Groups")`, splits each on `,`, trims spaces, and drops empties.

- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `feat(broker): authorize a shared visitor`.

---

### Task 3: `GET`/`PUT`/`DELETE /api/shares`

**Files:**
- Modify: `internal/broker/server.go`, `internal/broker/server_test.go`

**Interfaces:**
- Consumes: `Shares` (Task 2), `Resolver` (existing).
- Produces: `Deps.Shares Shares`; handlers for the three methods; response `{"shares":[{"tunnel","kind","grantee"}]}` on `GET`; `204` on `PUT`/`DELETE`.

- [ ] **Step 1: Write the failing tests.** In `server_test.go` with a fake `Shares` and a bearer-authenticated resolver: `TestSharesGet` (returns the caller's rows); `TestSharesPutValidates` (table: kind `admin` → 400, tunnel `Blog` → 400, `default` → 400, empty grantee → 400, group grantee `a,b` → 400, good `{"blog","user","bob"}` → 204 and the fake recorded `(sub-alice, {blog user bob})`); `TestSharesPutIsIdempotent` (a fake that allows duplicates → still 204); `TestSharesDelete` (204, fake recorded); `TestSharesNeedsToken` (no `Authorization` → 401); `TestSharesNotCreator` (resolver refusal → 403); `TestSharesStoreError` (fake error → 503).

- [ ] **Step 2: Run them to verify they fail.** `go test ./internal/broker/ -run Shares -v`. Expected: FAIL.

- [ ] **Step 3: Implement.** Add `Shares` to `Deps` and wire it in `NewHandler` (`mux.HandleFunc("GET /api/shares", s.sharesGet)`, and the `PUT`/`DELETE` variants). Each handler: `bearerToken` → 401; `resolver.Resolve` → 401/403/503 by the same mapping as `me`; for `PUT`/`DELETE` decode `store.Share`, validate per Global Constraints (400 on bad input), call the store, `204` on success; for `GET`, `writeJSON(200, {"shares": ...})`.

- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `feat(broker): manage shares over the API`.

---

### Task 4: CLI `share`, `unshare`, `list`

**Files:**
- Modify: `internal/auth/auth.go` (or a new `internal/auth/shares.go`), `internal/auth/auth_test.go`
- Modify: `internal/cli/cli.go`, `internal/cli/cli_test.go`

**Interfaces:**
- Consumes: `auth.Store`, `auth.Discover`, `auth.RefreshStored`.
- Produces:

  ```go
  // package auth
  type Share struct {
      Tunnel  string `json:"tunnel"`
      Kind    string `json:"kind"`
      Grantee string `json:"grantee"`
  }
  func PutShare(ctx context.Context, hc *http.Client, baseURL, accessToken string, sh Share) error
  func DeleteShare(ctx context.Context, hc *http.Client, baseURL, accessToken string, sh Share) error
  func ListShares(ctx context.Context, hc *http.Client, baseURL, accessToken string) ([]Share, error)
  ```
  CLI: `tunnel share [--name NAME] [--group] GRANTEE`, `tunnel unshare ...`, `tunnel list`.

- [ ] **Step 1: Write the failing tests.** In `auth_test.go` (with the existing service fake): `TestPutShare` (asserts method `PUT`, path `/api/shares`, bearer header, JSON body; 204 → nil; a `{"error":...}` body surfaces as the error text). `TestDeleteShare` and `TestListShares` likewise. In `cli_test.go`: `TestShareCommand` (`share --name blog bob` → the fake service sees `{"tunnel":"blog","kind":"user","grantee":"bob"}`); `TestShareGroup` (`--group family` → kind `group`); `TestShareDefaultTunnel` (`share bob` → tunnel `""`); `TestUnshare`; `TestListPrints` (prints each share; the default tunnel prints as `(default)`); `TestShareNotLoggedIn` (exit 1, `tunnel login`).

- [ ] **Step 2: Run them to verify they fail.** `go test ./internal/auth/ ./internal/cli/ -run 'Share\|List\|Unshare' -v`. Expected: FAIL.

- [ ] **Step 3: Implement.** The three `auth` functions do the HTTP call with the bearer header and, like `GetMe`, surface the server's `{"error"}` text. Add the commands to `cli.Main`: parse `--name`, `--group`, one positional grantee; `Load` the store (`ErrNotLoggedIn` → `not logged in; run: tunnel login`); `RefreshStored` (failure → the `up` message); `auth.Discover` for the base; call the function; `list` prints the rows. Add all three to `usage`.

- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/auth/ ./internal/cli/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `feat(cli): share, unshare and list`.

---

### Task 5: Forward the visitor's groups to `/authz`

Out of this repo: the manifests live in `layertwo/homelab`. Group shares do not work until this lands; user shares do.

**Files:**
- Modify (homelab): `clusters/home/apps/network/tunnels/routes/middlewares.yml`

- [ ] **Step 1: Change the OIDC middleware's `X-Tunnels-Groups`.** Today `tunnels-oidc` sets `X-Tunnels-Groups` to `[]` (removing it). It must instead carry the groups claim, as a single comma-separated value or several values — match whatever form Phase 0 used before the header was removed. Leave `tunnels-strip-internal` as it is, so the header is removed before the app.
- [ ] **Step 2: Verify against the deployed plugin.** With a test viewer who has two groups, a request to a shared group site reaches the broker's `/authz` with the groups present (the broker logs the decision `shared`), and the app never sees `X-Tunnels-Groups`.
- [ ] **Step 3: Commit.** `feat(tunnels): forward visitor groups to authz`.

---

### Task 6: Sharing end to end

**Files:**
- Modify: `e2e/e2e_test.go`

- [ ] **Step 1: Write the failing test.** `TestSharing`: bring up the broker, store and a real frps; a creator publishes; a second mock user is a viewer; call `/api/shares` `PUT` as the owner to share with the viewer's username; call `/authz` with the viewer's `X-Tunnels-Sub`/`X-Tunnels-User` and the owner's host → 200; `DELETE` and call `/authz` again → 403. Add a group case with `X-Tunnels-Groups`.
- [ ] **Step 2: Run it to verify it fails.** `TEST_DATABASE_URL=... go test -tags e2e ./e2e/ -run Sharing -v`. Expected: FAIL (endpoint missing).
- [ ] **Step 3: Implement** with the existing e2e helpers.
- [ ] **Step 4: Run it to verify it passes.** `TEST_DATABASE_URL=... go test -race -tags e2e ./e2e/ -run Sharing -v`. Expected: PASS.
- [ ] **Step 5: Commit.** `test(e2e): prove sharing end to end`.

---

### Task 7: Document the commands

**Files:**
- Modify: `README.md`
- Modify: `docs/design.md`

- [ ] **Step 1:** Add `tunnel share`, `tunnel unshare` and `tunnel list` to the README's Use section.
- [ ] **Step 2:** Note in `docs/design.md` that Phase 2 (sharing) is implemented and that group shares depend on the visitor's groups reaching `/authz`.
- [ ] **Step 3: Commit.** `docs: record the sharing commands`.

---

## Self-Review

- **Spec coverage:** `shares` table (Task 1) ✔; `/authz` owner/user/group (Task 2) ✔; `/api/shares` GET/PUT/DELETE idempotent (Task 3) ✔; `share`/`unshare`/`list` (Task 4) ✔; groups to `/authz` (Task 5) ✔; e2e (Task 6) ✔; docs (Task 7) ✔.
- **Type consistency:** `store.Share{Tunnel,Kind,Grantee}` used by the store, the broker and the CLI's `auth.Share` (same JSON); `Shares` interface is `PutShare`/`DeleteShare`/`SharesByOwner`/`ShareMatches` throughout; `ShareMatches(ownerSub, tunnel, username, groups)` matches between Task 2 and Task 1.
- **Review Focus:** each line names its owning test — case-insensitivity and exactness in Task 1 (`TestShareMatches…`) and Task 3's validation, group exactness in Task 1, idempotency in Tasks 1 and 3, the default-tunnel rule in Tasks 1 and 4, and fail-closed in Tasks 1 and 2.
- **Proportion:** seven tasks for one migration, one interface, three endpoints and three commands; no step transcribes a body its signature and tests already determine.
