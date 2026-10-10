# Tunnels 100% Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring every package under `./internal/...` to 100% statement coverage and enforce it in CI, with `cmd/` and `e2e/` excluded.

**Architecture:** Test-only work per package (plus a rare, documented `// coverage-ignore` for a provably unreachable line), then a `.testcoverage.yml` and a `go-test-coverage` step in the `test` job.

**Tech Stack:** Go 1.27, `go test -covermode=atomic`, `vladopajic/go-test-coverage/v2`.

**Spec:** none — the acceptance criterion is the metric itself, `go test -cover` = 100.0% for each `internal` package.

## Global Constraints

- Scope: `./internal/...` only. `./cmd/...` and `./e2e/` are excluded from the gate and must not be measured.
- Measure with `TEST_DATABASE_URL=… go test -covermode=atomic -coverprofile=… ./internal/...`; the store tests need Postgres.
- **Every new test asserts real behavior** — an assertion, an observable side effect, or an error identity. A test that only calls a function to touch lines is not coverage and is a review defect.
- Reaching a line by fault injection is preferred (a failing `http.Client`, a bad `DATABASE_URL`, a closed pool, a read-only directory). Do **not** add production seams that change behavior.
- `// coverage-ignore` is allowed **only** for a line no test can reach and that is not worth reshaping the code for; it must carry a comment saying why, and the config sets `force-annotation-comment: true`. Report every one in the task's report so the controller can ledger it.
- `go test -race ./...` and `go vet -tags e2e ./...` stay green; no test may slow the suite materially or depend on the network.
- The gate excludes `^cmd/`; `e2e` is not in the profile (no tag).

## Review Focus

1. A new test that asserts nothing (call-only) does not count as coverage — flag it Important.
2. Every `// coverage-ignore` names a genuinely unreachable line and says why; a reachable line hidden behind one is Important.
3. OS-specific branches (`runtime.GOOS`) and error paths reachable only by fault injection are handled by injection or a documented ignore, never by deleting the branch.
4. The final gate enforces 100% on `internal` and excludes only `cmd`; it must fail on a real regression (prove it by checking a lowered threshold locally).
5. The suite stays deterministic and reasonably fast.

---

### Task 1: `internal/store` to 100%

**Files:** `internal/store/store_test.go` (and `store.go` only if a seam is unavoidable)

**Interfaces:** consumes the existing `newStore(t)`/`openStore` helpers.

Current gaps: `Open` 57.1%, `migrate` 69.0%, `apply` 80.0%, `CreateUser` 90.0%, `PutShare` 66.7%, `DeleteShare` 66.7%, `SharesByOwner` 76.9%.

- [ ] **Step 1:** `TEST_DATABASE_URL=… go test -covermode=atomic -coverprofile=/tmp/c.out ./internal/store/ && go tool cover -func=/tmp/c.out | grep -v 100.0%` to list the exact uncovered lines.
- [ ] **Step 2:** Add tests that fault-inject each branch: `Open` with an unreachable/invalid `DATABASE_URL` (pool open and migrate errors), `migrate` with a cancelled context and with a locked/again connection, `apply` with a failing statement, `CreateUser`/`PutShare`/`DeleteShare`/`SharesByOwner` with a closed pool (error, not zero value). Each asserts the error (identity where one exists) and that no row changed.
- [ ] **Step 3:** Repeat Step 1 until `internal/store` reports 100.0% (or annotate a truly unreachable line with a commented `// coverage-ignore`).
- [ ] **Step 4:** `go test -race ./internal/store/`. Expected: PASS.
- [ ] **Step 5:** Commit `test(store): cover the error paths`.

---

### Task 2: `internal/tunnel` to 100%

**Files:** `internal/tunnel/tunnel_test.go`, `internal/tunnel/bridge_test.go` (and the package only if a seam is unavoidable)

Gaps: `WriteCABundle` 90.9%, `Build` 85.7%, `Run` 73.1%, `watch` 0.0%.

- [ ] **Step 1:** List the uncovered lines as in Task 1.
- [ ] **Step 2:** Cover `watch` (the status poller) by driving `Run` against a real frps in the existing style, or by calling `watch` with a client service whose proxy reaches `running`; cover `Run`'s error and context paths, `Build`'s remaining refusal branch, and `WriteCABundle`'s error branches (a read-only or missing directory).
- [ ] **Step 3:** Repeat until 100.0%.
- [ ] **Step 4:** `go test -race ./internal/tunnel/`. PASS.
- [ ] **Step 5:** Commit `test(tunnel): cover run, watch and the ca bundle`.

---

### Task 3: `internal/auth` to 100%

**Files:** `internal/auth/auth_test.go`, `internal/auth/store_test.go`, `internal/auth/shares_test.go`

Gaps: `GetMe` 88.9%, `send` 85.7%, `DeviceLogin` 81.0%, `Refresh` 91.7%, `RefreshStored` 90.0%, `changeShare` 83.3%, `ListShares` 72.7%, `Load` 88.9%, `Save` 70.0%, `Clear` 75.0%, `WriteFileAtomic` 68.8%.

- [ ] **Step 1:** List the uncovered lines.
- [ ] **Step 2:** Cover each error branch with the `mockidp` double and temp dirs: a device flow that is denied/expires, a refresh that fails, `send`/`GetMe`/`changeShare`/`ListShares` against a service that returns a non-JSON body and a 5xx, `Load` on a damaged file, `Save`/`WriteFileAtomic`/`Clear` with an unwritable directory (mode 0500) and a missing file.
- [ ] **Step 3:** Repeat until 100.0%.
- [ ] **Step 4:** `go test -race ./internal/auth/`. PASS.
- [ ] **Step 5:** Commit `test(auth): cover the token and API error paths`.

---

### Task 4: `internal/cli` to 100%

**Files:** `internal/cli/cli_test.go`

Gaps: `Main` 92.3%, `store` 55.6%, `login` 67.7%, `up` 87.5%, `session` 64.7%, `share` 94.1%, `list` 61.5%, `logout` 75.0%.

- [ ] **Step 1:** List the uncovered lines.
- [ ] **Step 2:** Cover the argument/usage errors, the not-logged-in and failed-refresh paths, a discovery failure, an API failure, and a bad `TUNNELS_CONFIG_DIR` for every command (`login`, `up`, `share`, `unshare`, `list`, `logout`, `version`), asserting the exit code and the message.
- [ ] **Step 3:** Repeat until 100.0%.
- [ ] **Step 4:** `go test -race ./internal/cli/`. PASS.
- [ ] **Step 5:** Commit `test(cli): cover the command error paths`.

---

### Task 5: `internal/idp` and `internal/frpsapi` to 100%

**Files:** `internal/idp/idp_test.go`, `internal/frpsapi/frpsapi_test.go`

Gaps: `idp.UserInfo` 88.9%; `frpsapi.get` 95.5%.

- [ ] **Step 1:** List the uncovered lines in each.
- [ ] **Step 2:** Cover `UserInfo`'s remaining branches (a 5xx from userinfo, a decode failure, a missing `sub`, a wrong-typed claim) with `httptest`; cover `frpsapi.get`'s remaining branch (a malformed envelope, a short read).
- [ ] **Step 3:** Repeat until both are 100.0%.
- [ ] **Step 4:** `go test -race ./internal/idp/ ./internal/frpsapi/`. PASS.
- [ ] **Step 5:** Commit `test(idp,frpsapi): cover the response error paths`.

---

### Task 6: `internal/mockidp` and `internal/broker` to 100%

**Files:** `internal/mockidp/mockidp_test.go`, `internal/broker/hooks_test.go`, `internal/broker/server_test.go`

Gaps: `mockidp.New` 95.0%, `sign` 75.0%, `deviceAuthorize` 81.8%, `token` 84.6%; `broker.ping` 93.3%, `broker.sharesDelete` 50.0%.

- [ ] **Step 1:** List the uncovered lines.
- [ ] **Step 2:** Cover the remaining mockidp branches (bad `sign` input, a device-authorize and token error case); cover `ping`'s last branch and `sharesDelete`'s remaining branch (the nil-guard and store-error paths) in the broker tests.
- [ ] **Step 3:** Repeat until both are 100.0%.
- [ ] **Step 4:** `go test -race ./internal/mockidp/ ./internal/broker/`. PASS.
- [ ] **Step 5:** Commit `test(mockidp,broker): cover the last branches`.

---

### Task 7: Enforce 100% in CI

**Files:** create `.testcoverage.yml`; modify `.github/workflows/ci.yml`

**Interfaces:** the `test` job already runs `go test -race -covermode=atomic -coverprofile=coverage.txt ./...` and uploads the artifact.

- [ ] **Step 1:** Add `.testcoverage.yml`:

  ```yaml
  profile: coverage.txt
  threshold:
    total: 100
  exclude:
    paths:
      - ^cmd/
  force-annotation-comment: true
  ```

- [ ] **Step 2:** Add a step to the `test` job after the coverage upload, installing and running the tool pinned to a version:

  ```yaml
  - name: Enforce 100% coverage
    run: |
      go install github.com/vladopajic/go-test-coverage/v2@v2.14.1
      "$(go env GOPATH)/bin/go-test-coverage" --config=.testcoverage.yml
  ```

- [ ] **Step 3:** Prove the gate fails on a regression: temporarily set `threshold.total: 99` and confirm it still passes (so a real dip below 100 is what trips it), then confirm at `100` it passes on the merged tree. Record the before/after output.
- [ ] **Step 4:** `go test -race ./...` and the e2e suite unchanged. Commit `ci: enforce 100% coverage on internal`.

---

## Self-Review

- **Spec coverage:** 100% on each `internal` package (Tasks 1-6) and CI enforcement (Task 7), with `cmd/`+`e2e/` excluded per the owner's decision.
- **Type consistency:** no interface changes; the tasks test existing exported and unexported functions.
- **Review Focus:** each line names its owning check — call-only tests and bogus ignores in every task's review; OS branches in Tasks 1-3; the gate's exclusion and fail-on-regression in Task 7; suite speed in all.
- **Proportion:** one task per package (grouped pairs where the gaps are one or two branches) plus the gate, each with the metric as its acceptance criterion; no test bodies are transcribed because the uncovered lines are found and covered by iteration.
