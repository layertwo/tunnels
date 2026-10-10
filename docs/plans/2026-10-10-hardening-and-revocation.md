# Tunnels Hardening + Instant Revocation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clean up the Phase 2 review's minor findings, and add a Ping-hook kill switch so a revoked creator's tunnel ends within one heartbeat instead of up to an hour.

**Architecture:** A small set of defensive guards in the broker's HTTP surface, and a new `Ping` op in the frps plugin hooks that re-resolves the token carried on every heartbeat. A rejected ping makes frpc `closeSession()`; a ping the broker allows still passes frps's own `VerifyPing`.

**Tech Stack:** Go 1.26, frp v0.71.0 plugin types (`plugin.PingContent`, `msg.Ping.PrivilegeKey`), `net/http`.

**Spec:** `docs/design.md` — the "Revocation needs explicit settings" section and the `Ping`-hook kill switch in Phase 3.

## Global Constraints

- The plugin's `Ping` hook receives `{user, privilege_key, timestamp}`; `privilege_key` is the client's current access token (frpc re-reads the file every heartbeat).
- A rejected ping is a decision, HTTP 200 with `reject:true`; the reason reaches the client and frpc closes the session. frps additionally does not update `lastPing` on a rejection, so a client that ignores the pong is dropped by the 90 s server-side heartbeat timeout.
- **The ping fails closed only on an identity refusal.** A ping is rejected only when `Resolve` returns a `*refusal` — the account is disabled, out of the creators group, or has a handle the store refuses. Every other failure (an invalid or expired token, or Pocket ID or Postgres being *down*) is **allowed**: the tunnel survives, and frps re-verifies the ping token itself (`VerifyPing`, HeartBeats scope), so a genuinely bad token still fails end-to-end without this hook tearing down a session frps would accept.
- The `/plugin/<secret>` handler never logs an accepted ping (they arrive every 30 s per client); a rejected ping is logged.
- The share API hardening must not change any successful response shape: `GET /api/shares` still returns `{"shares":[…]}` (never `null`); `PUT`/`DELETE` still 204; a bad body is still 400.
- Tests: `go test -race ./...`, table-driven. Postgres tests read `TEST_DATABASE_URL` and skip when unset.

## Review Focus

1. A ping is rejected **only** on an identity refusal (the account is disabled or out of the creators group, or has a handle the store refuses), and **allowed** on every other failure — an invalid, expired or locally unverifiable token, or the identity provider or store being down — where frps re-verifies the ping token itself (`VerifyPing`, HeartBeats scope).
2. `GET /api/shares` returns `[]`, never `null`, for an owner with no shares.
3. A share request body over the cap, or with trailing JSON after the object, is refused (400), not silently accepted.
4. A missing dependency (`Deps.Shares`) yields 503, not a 500 from a panic.
5. The CLI usage string warns that `--group` shares require the gate to forward groups.

---

### Task 1: Harden the broker's HTTP surface

**Files:**
- Modify: `internal/broker/server.go`, `internal/broker/server_test.go`
- Modify: `internal/broker/authz.go`, `internal/broker/authz_test.go`
- Modify: `internal/cli/cli.go`

**Interfaces:**
- Consumes: the existing `maxBody` const (`hooks.go`), `writeJSON`, `errorBody`.
- Produces: nil-safe `GET /api/shares`; a capped, trailing-JSON-rejecting `changeShare`; a nil-`Shares` 503 in both `Authz` and the share handlers.

- [ ] **Step 1: Write the failing tests.** In `server_test.go`: `TestSharesGetEmptyIsArray` (an owner with no shares → body exactly `{"shares":[]}`, not `null`); `TestSharesBodyTooLarge` (a body over 1 MiB → 400); `TestSharesTrailingJSON` (`{"tunnel":"","kind":"user","grantee":"bob"}{}` → 400, and the store is not called); `TestSharesNilSharesIs503` (a `Deps` with a nil `Shares`, a valid creator token, `PUT /api/shares` → 503, not 500). In `authz_test.go`: `TestAuthzNilSharesIs503` (a request that reaches the share lookup with a nil `Shares` → 503, empty body). In `cli_test.go`: `TestUsageMentionsGroupPrerequisite` (the usage string contains the group caveat).

- [ ] **Step 2: Run them to verify they fail.** `go test ./internal/broker/ ./internal/cli/ -run 'SharesGetEmpty|SharesBody|SharesTrailing|SharesNil|AuthzNil|UsageMention' -v`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `sharesGet`: `if shares == nil { shares = []store.Share{} }` before `writeJSON`.
  - `changeShare`: first `if s.d.Shares == nil { writeJSON(503, errorBody("sharing is unavailable, try again")); return }`; wrap the body with `http.MaxBytesReader(w, r.Body, maxBody)`; after decoding, decode a second time into `struct{}{}` and require `io.EOF` (else 400).
  - `Authz.decideSite`: before touching `a.Shares`, `if a.Shares == nil { return outcome{reason: "store", err: errors.New("authz: no shares store"), status: 503} }`.
  - `cli.go` usage: add "(group shares need the gate to forward groups)" to the `share` line.

- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/ ./internal/cli/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `feat(broker): harden the shares surface`.

---

### Task 2: Ping-hook kill switch

**Files:**
- Modify: `internal/broker/hooks.go`, `internal/broker/hooks_test.go`
- Modify: `internal/broker/server.go` only if the op needs registering (it does not; `Hooks` already owns `/plugin/`)

**Interfaces:**
- Consumes: `Resolver.Resolve` (existing), `*refusal` via `errors.As` (existing), `plugin.OpPing` / `plugin.PingContent` / `msg.Ping`.
- Produces: `case plugin.OpPing` in `Hooks.ServeHTTP` dispatching to `func (h *Hooks) ping(ctx, raw json.RawMessage) (plugin.Response, error)`.

- [ ] **Step 1: Write the failing tests.** In `hooks_test.go` with fakes: `TestPingAllowsAValidCreator` (a `PingContent` with the owner's `privilege_key` and `user.user = alice` → `reject` false, `unchange` true, and the accept is not logged at info); `TestPingRejectsAMissingToken` (`privilege_key:""` → reject); `TestPingRejectsANonCreator` (resolver `ErrNotCreator` → reject with the refusal text); `TestPingRejectsADisabledAccount` (`ErrDisabled` → reject); `TestPingAllowsAnInvalidTokenLocally` (`idp.ErrInvalidToken` → **allow**, `reject` false: frps re-verifies the token itself); `TestPingAllowsWhenTheIdentityProviderIsDown` (resolver returns a plain infrastructure error → **allow**, `reject` false; the failure is logged at **debug**); `TestPingIsNotLoggedWhenAccepted` (capture slog; a successful ping emits no `info` line).

- [ ] **Step 2: Run them to verify they fail.** `go test ./internal/broker/ -run Ping -v`. Expected: `unknown op "Ping"` / FAIL.

- [ ] **Step 3: Implement.** Add `case plugin.OpPing: res, err = h.ping(ctx, req.Content)`. In `ping`: unmarshal `plugin.PingContent`; empty `PrivilegeKey` → `h.reject(..., "missing token", ...)`; `acct, err := h.Resolver.Resolve(ctx, c.PrivilegeKey)`; on error reject **only** when `errors.As(err, &(*refusal))` (a disabled or non-creator account, or a handle the store refuses) using the refusal's own text; for every other failure (an invalid or expired token, or a dependency down) log at **debug** and **allow** (return the content unchanged) — frps re-verifies the ping token itself (`VerifyPing`, HeartBeats scope), so this hook must not duplicate or second-guess that check. On success, if `c.User.User != "" && c.User.User != acct.Handle` reject with the handle-mismatch sentence; otherwise return `plugin.Response{Unchange: true}` with no accepted-ping log line.

- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `feat(broker): end a revoked tunnel on its next heartbeat`.

---

### Task 3: Enable the Ping hook and document it

Out of this repo: the manifests live in `layertwo/homelab`.

**Files:**
- Modify (homelab): `clusters/home/apps/network/tunnels/frps/configmap.yml` — add `"Ping"` to the `[[httpPlugins]]` `ops` list.
- Modify: `README.md`, `docs/design.md`.

**Interfaces:** none.

- [ ] **Step 1:** In `frps.toml`, `ops = ["Login", "NewProxy", "CloseProxy", "Ping"]`.
- [ ] **Step 2:** Note in `docs/design.md` that the Ping kill switch is implemented and that enabling it is the `ops` change; note in `README.md` that removing someone ends their tunnel within one heartbeat.
- [ ] **Step 3: Commit.** `docs: record the ping kill switch`.

---

## Self-Review

- **Spec coverage:** the review's minors — nil→null (Task 1), nil-`Shares` 503 (Task 1), body cap + trailing JSON (Task 1), usage caveat (Task 1), `ListShares` test omitted deliberately (low value; can ride with Task 1 if the implementer adds it); the Ping kill switch (Task 2); the frps `ops` enablement (Task 3).
- **Type consistency:** `ping(ctx, raw) (plugin.Response, error)` mirrors `login`/`newProxy`/`closeProxy`; `plugin.PingContent` is used as defined, and a ping's failure is classified with `refusalOf` (a refusal rejects; anything else is allowed, since frps re-verifies the token).
- **Review Focus:** each line names its owning test — fail-open on outage (Task 2 `TestPingAllowsWhenTheIdentityProviderIsDown`), `[]` not `null` (Task 1), body cap/trailing (Task 1), nil 503 (Task 1), usage caveat (Task 1).
- **Proportion:** two broker tasks and one docs/manifest task for a small hardening pass and one hook; no task transcribes a body its signature and tests already determine.
