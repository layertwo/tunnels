# Tunnels Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Five follow-ups after the v0.2.0 deploy: the broker survives a slow Postgres start; a `NewWorkConn` hook closes the run-ID work-connection hole; shares can expire; cross-owner state-changing browser requests are refused; and the deploy gets a smoke-test checklist.

**Architecture:** Small, independent changes to the broker, the store and the CLI, plus one homelab `ops` line. No new dependencies.

**Spec:** `docs/design.md` — the "Revocation needs explicit settings" note on `NewWorkConn`, the `shares` data model, and the "Cross-owner CSRF hardening" simplification.

## Global Constraints

- Module `github.com/layertwo/tunnels`, `go 1.27`, default branch `mainline`, commits `feat(scope): ...`, one pull request per task.
- **The coverage gate is live: every `./internal/...` package must stay at 100.0%** (`go-test-coverage`, `.testcoverage.yml`). New code needs full tests, or a commented `// coverage-ignore` for a provably unreachable line.
- Fail open on our own failures (a dependency down), fail closed on theirs (a bad token, a disabled account, a refusal). frps re-verifies the control token itself after a plugin allows, so a hook may allow an unverifiable token.
- The default tunnel is `''`; `names.Default` never appears as a stored tunnel.
- Tests: `go test -race ./...`; Postgres tests read `TEST_DATABASE_URL` and skip when unset; the e2e test is behind the `e2e` tag.

## Review Focus

1. The DB retry is bounded and stops on `ctx`; it must not spin forever or hide the error past the window.
2. `NewWorkConn` rejects a token whose handle is not the control connection's user, and **allows** when the broker cannot verify (frps backstops) — it must not fail closed on our own outage.
3. An expired share is invisible to `/authz` on the first request after its time, and never blocks the owner.
4. The CSRF rule refuses only a *cross-owner, state-changing, browser-originated* request; it must not break same-owner, safe-method, or origin-less requests.
5. Every package stays at 100% under the gate.

---

### Task 1: Broker retries the database at startup

**Files:** `internal/store/store.go`, `internal/store/store_test.go`, `cmd/broker/main.go`

**Interfaces:** produces `func OpenRetry(ctx context.Context, databaseURL string, wait time.Duration) (*Store, error)`.

- [ ] **Step 1: Write the failing tests** in `store_test.go`: `TestOpenRetrySucceeds` (a real database → a `*Store`); `TestOpenRetryGivesUp` (an unreachable URL and a 200 ms `wait` → the last error, in well under the context deadline); `TestOpenRetryStopsOnContext` (a cancelled context → returns promptly).
- [ ] **Step 2: Run them to verify they fail.** `TEST_DATABASE_URL=... go test ./internal/store/ -run OpenRetry -v`. Expected: `undefined: OpenRetry`.
- [ ] **Step 3: Implement.** `OpenRetry` calls `Open`; on error it logs nothing (the caller logs), sleeps a capped backoff (1 s, 2 s, 4 s, … capped at 10 s), and retries until `ctx` ends or `wait` elapses; it returns the last error. In `cmd/broker/main.go`, replace `store.Open` with `store.OpenRetry(ctx, cfg.DatabaseURL, 2*time.Minute)`.
- [ ] **Step 4: Run them to verify they pass.** `TEST_DATABASE_URL=... go test -race ./internal/store/ -v`. PASS; `internal/store` at 100%.
- [ ] **Step 5: Commit.** `feat(broker): wait for the database at startup`.

---

### Task 2: `NewWorkConn` plugin op

**Files:** `internal/broker/hooks.go`, `internal/broker/hooks_test.go`

**Interfaces:** consumes `Resolver.Verifier` (`VerifyAccessToken`), `Resolver.Users` (`UserBySub`), `plugin.NewWorkConnContent`.

- [ ] **Step 1: Write the failing tests:** `TestNewWorkConnAllowsTheControlUser` (a token whose `sub` maps to the same handle as `user.user` → reject false, unchange true); `TestNewWorkConnRejectsAnotherUser` (token handle `bob`, `user.user` `alice` → reject); `TestNewWorkConnAllowsWhenUnverifiable` (verifier error → allow, logged at debug); `TestNewWorkConnRejectsAMissingToken` (`privilege_key:""` → reject); `TestNewWorkConnAllowsWhenTheStoreIsDown` (store error → allow).
- [ ] **Step 2: Run them to verify they fail.** `go test ./internal/broker/ -run NewWorkConn -v`. FAIL.
- [ ] **Step 3: Implement** `case plugin.OpNewWorkConn` dispatching to `h.newWorkConn`: empty token → reject "missing token"; `sub, err := h.Resolver.Verifier.VerifyAccessToken(ctx, key)` — on error log debug and **allow**; else `h.Resolver.Users.UserBySub(ctx, sub)` — on error allow, else if `handle != c.User.User` reject "token does not belong to this session", else `plugin.Response{Unchange: true}` with no accepted log.
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/ -v`. PASS; 100%.
- [ ] **Step 5: Commit.** `feat(broker): bind every work connection to its control user`.

---

### Task 3: Share expiry

**Files:** `internal/store/migrations/003_share_expiry.sql` (new), `internal/store/store.go`, `internal/store/store_test.go`, `internal/broker/server.go`, `internal/broker/server_test.go`, `internal/broker/authz_test.go`, `internal/auth/shares.go`, `internal/auth/auth_test.go`, `internal/cli/cli.go`, `internal/cli/cli_test.go`

**Interfaces:** `store.Share` gains `ExpiresAt time.Time` (json `expires_at`, zero = never); `ShareMatches` ignores expired rows; `/api/shares` accepts an optional absolute `expires_at`; `tunnel share --for 7d` computes it; `tunnel list` prints it.

- [ ] **Step 1: Write the failing tests.** store: `TestPutAndListShareWithExpiry`, `TestShareMatchesIgnoresExpired`. broker: `TestSharesPutAcceptsExpiry` (RFC3339 accepted; a past time → 400), `TestAuthzIgnoresExpiredShare` (an expired share → 403). cli: `TestShareForADuration` (`--for 7d` → an `expires_at` ~7 days out), `TestShareForRejectsGarbage`, `TestListShowsExpiry`.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement.** `003_share_expiry.sql` is `alter table shares add column expires_at timestamptz;`. `PutShare` writes it; `SharesByOwner` selects it; `ShareMatches` adds `and (expires_at is null or expires_at > now())`. `validShare` requires a set `expires_at` to be in the future. The CLI parses `--for` as a Go duration with `d` meaning 24 h and sends an RFC3339 `expires_at`; `list` prints `never` or the time.
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/store/ ./internal/broker/ ./internal/auth/ ./internal/cli/ -v`. PASS; all at 100%.
- [ ] **Step 5: Commit.** `feat: let a share expire`.

---

### Task 4: Cross-owner CSRF hardening in `/authz`

**Files:** `internal/broker/authz.go`, `internal/broker/authz_test.go`

**Interfaces:** `names.SiteLabel(originHost, SitesDomain)` reused.

- [ ] **Step 1: Write the failing tests:** `TestCrossOwnerStateChangeRefused` (`POST` to `alice-blog…` with `Origin: https://bob-x.w.tunnels.example` → 403); `TestCrossOwnerSafeMethodAllowed` (`GET`, same → 200); `TestSameOwnerOriginAllowed` (`Origin` is another tunnel of `alice` → 200); `TestForeignOriginAllowed` (`Origin: https://example.com` → 200); `TestOriginAbsentAllowed` → 200; `TestMalformedOriginAllowed` (`Origin: https://alice-blog.w.tunnels.example.evil` → 200 for a `POST`).
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement** in `decide`/`decideSite`: when `r.Method` is not `GET`, `HEAD` or `OPTIONS`, parse `Origin`; if it is present and is a *valid* sites host under `SitesDomain`, derive its owner with `SiteLabel`+`ParseLabel`; if the owner differs from the target's, deny with reason `cross_owner`. A foreign or look-alike `Origin` (not a valid sites host — Traefik never routes it) is allowed; an absent `Origin` allows. `SiteLabel` requires an exact domain suffix, so a look-alike cannot slip in.
- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/ -v`. PASS; 100%.
- [ ] **Step 5: Commit.** `feat(broker): refuse cross-owner state-changing requests`.

---

### Task 5: Enable `NewWorkConn` in frps `ops`

Out of this repo: `layertwo/homelab`.

**Files:** `clusters/home/apps/network/tunnels/frps/configmap.yml`

- [ ] **Step 1:** `ops = ["Login", "NewProxy", "CloseProxy", "Ping", "NewWorkConn"]`.
- [ ] **Step 2: Verify** (with Task 4's broker deployed): a visitor request to a live site still works; a work connection whose token belongs to another user is refused.
- [ ] **Step 3: Commit** (homelab): `feat(tunnels): bind work connections to their control user`.

---

### Task 6: Deploy smoke test and docs

**Files:** `README.md`, `docs/design.md`

- [ ] **Step 1:** Add a short "Verify a deploy" checklist to `docs/design.md`: broker `2/2` and PDB `MIN AVAILABLE 1`; frps `ops` includes `Ping`/`NewWorkConn`; a user share admits the user and `unshare` denies within a heartbeat; a group share admits a member; a cross-owner `POST` from another tunnel is refused.
- [ ] **Step 2:** Note in `README.md` that `tunnel share --for DURATION` exists.
- [ ] **Step 3: Commit.** `docs: the deploy smoke test and share expiry`.

---

## Self-Review

- **Spec coverage:** DB retry (Task 1), `NewWorkConn` (Task 2, enabled in Task 5), share expiry (Task 3), CSRF (Task 4), smoke test + docs (Task 6).
- **Type consistency:** `OpenRetry(ctx, url, wait)`; `store.Share.ExpiresAt`; `share --for`; the `newWorkConn` op mirrors `ping` (refusal-only reject, else allow).
- **Review Focus:** each line names its owning test.
- **Proportion:** six tasks for four small features, one ops line and docs; no bodies transcribed.
