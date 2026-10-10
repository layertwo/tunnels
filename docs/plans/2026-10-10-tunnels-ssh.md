# Tunnels SSH Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a local SSH service through the tunnel agent and reach it from any terminal with `ssh`, over HTTPS on 443, authenticated with Pocket ID.

**Architecture:** The agent runs a small WebSocket bridge on loopback and publishes it as an ordinary frp `http` proxy under a custom domain `<label>.ssh.<SSH_DOMAIN>`. The visitor runs `tunnel dial` (an `ssh_config` `ProxyCommand`), which presents a Pocket ID bearer token; Traefik `forwardAuth` calls the broker's `/authz`, which verifies the token locally and authorizes the owner; frps routes by host to the bridge, which dials the target. The OIDC plugin is deliberately absent from the SSH route.

**Tech Stack:** Go 1.26, `github.com/fatedier/frp` v0.71.0 (client library + plugin types), `github.com/gorilla/websocket` (already in the module graph through frp), `github.com/coreos/go-oidc/v3`, `github.com/spf13/pflag`.

**Spec:** `docs/plans/2026-10-10-tunnels-ssh-design.md`.

## Global Constraints

- Module `github.com/layertwo/tunnels`, `go 1.26.0`, default branch `mainline`, commits `feat(scope): ...`, one pull request per task.
- `github.com/fatedier/frp v0.71.0` always equals the frps image `ghcr.io/fatedier/frps:v0.71.0@sha256:cd8b947ba61678b200baa4f71ccc33f3c52e4e2cc0059700ba3b8354e36af7c3`; bump together.
- New broker env: `SSH_DOMAIN` (required), a DNS name without scheme, port or trailing dot; production value `ssh.tunnels.layertwo.dev`.
- The SSH host is `<label>.<SSH_DOMAIN>` where `<label> = names.Label(handle, tunnel)`; the frp proxy name is `<handle>.<name>` (shared namespace with HTTP tunnels).
- Client config for the SSH proxy: `type = "http"`, `customDomains = ["<label>.<SSH_DOMAIN>"]`, `subDomain = ""`, `localIP = "127.0.0.1"`, `localPort = <bridge port>`, `requestHeaders.set.x-forwarded-proto = "https"`; the rest of the client config is unchanged from a site (`wss` to `tunnels.layertwo.dev:443`, `auth.method = oidc`, file token source, `transport.heartbeatInterval = 30`, `transport.tls.trustedCaFile`).
- The SSH data route runs Traefik `forwardAuth` **only**; the OIDC plugin is never in that chain. Site routes keep the cookie/header path.
- `/authz` on an SSH host: 401 for a missing or invalid bearer token, 403 for a valid token that is not the owner, 503 when the store cannot answer; on allow, 200. Site hosts keep the existing decisions exactly.
- The bridge binds `127.0.0.1` only. The default SSH target is `127.0.0.1:22`; `--target` names a bare host (no port, no scheme).
- Files user-private are 0600; tokens are never logged. Every outbound request has a 10 s deadline and `User-Agent: tunnels/<version>`.
- Tests: `go test -race ./...`, table-driven. Postgres tests read `TEST_DATABASE_URL` and skip when unset. The end-to-end test is behind the `e2e` tag. After adding imports run `go mod tidy` and commit `go.mod`/`go.sum`.

## Review Focus

1. A bearer token presented on a **site** host, or `X-Tunnels-*` headers on an **SSH** host: neither may authorize. The two modes must not cross-talk.
2. A custom domain that is not exactly the owner's `<label>.<SSH_DOMAIN>` — a sibling owner's label, the sites domain, an extra label, uppercase, a port, a trailing dot, or more than one entry — must be refused by `NewProxy`.
3. An SSH `X-Forwarded-Host` with a port, a trailing dot, an extra label or uppercase on `/authz`: refused, never a panic or an accidental allow.
4. A token expired at the `dial` handshake: refresh once and retry; a token expiring **during** an established session must not drop it.
5. `--target` carrying a port or a scheme, or a default that is not loopback: refused at `Build`, never dialed.

---

### Task 1: `names.SSHLabel`

**Files:**
- Modify: `internal/names/names.go`
- Modify: `internal/names/names_test.go`

**Interfaces:**
- Consumes: `names.SiteLabel` (existing).
- Produces: `func SSHLabel(host, sshDomain string) (label string, ok bool)`.

- [ ] **Step 1: Write the failing test** in `internal/names/names_test.go`:

```go
func TestSSHLabel(t *testing.T) {
	const sshDomain = "ssh.tunnels.test"
	tests := []struct {
		host, label string
		ok          bool
	}{
		{"alice-box1.ssh.tunnels.test", "alice-box1", true},
		{"Alice-Box1.SSH.Tunnels.Test", "alice-box1", true},
		{"alice.ssh.tunnels.test", "alice", true},
		{"alice-box1.ssh.tunnels.test:443", "", false},
		{"alice-box1.ssh.tunnels.test.", "", false},
		{"x.alice-box1.ssh.tunnels.test", "", false},
		{"ssh.tunnels.test", "", false},
		{"alice.w.tunnels.test", "", false},
		{"alice.ssh.tunnels.test.evil.com", "", false},
		{"a.com, b.com", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		label, ok := SSHLabel(tt.host, sshDomain)
		if label != tt.label || ok != tt.ok {
			t.Errorf("SSHLabel(%q) = %q, %v; want %q, %v", tt.host, label, ok, tt.label, tt.ok)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails.** `go test ./internal/names/ -run TestSSHLabel -v`. Expected: build failure, `undefined: SSHLabel`.

- [ ] **Step 3: Implement** in `internal/names/names.go`:

```go
// SSHLabel returns the label of host under the SSH domain, exactly as SiteLabel does for sites.
func SSHLabel(host, sshDomain string) (label string, ok bool) { return SiteLabel(host, sshDomain) }
```

- [ ] **Step 4: Run it to verify it passes.** `go test -race ./internal/names/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `git add internal/names && git commit -m "feat(names): parse labels under the ssh domain"`.

---

### Task 2: SSH domain plumbing

**Files:**
- Modify: `internal/broker/config.go`, `internal/broker/config_test.go`
- Modify: `internal/auth/auth.go` (the `Bootstrap` struct)
- Modify: `internal/broker/server.go`, `internal/broker/server_test.go`
- Modify: `cmd/broker/main.go` only if it enumerates config fields

**Interfaces:**
- Produces: `broker.Config.SSHDomain string` (env `SSH_DOMAIN`, required, DNS-name validated); `auth.Bootstrap.SSHDomain string` (json `ssh_domain`); the `/.well-known/tunnels.json` body gains `ssh_domain`.

- [ ] **Step 1: Write the failing tests.** In `config_test.go`, add to the existing table-driven `TestLoadConfig`: a case where every required variable including `SSH_DOMAIN` is set → `Config.SSHDomain` equals it; a case with `SSH_DOMAIN` unset → error naming `SSH_DOMAIN`; a case `SSH_DOMAIN="ssh.tunnels.test:443"` → error. In `server_test.go`, extend `TestWellKnown` so the decoded JSON has `"ssh_domain"` equal to the configured value.

- [ ] **Step 2: Run them to verify they fail.** `go test ./internal/broker/ -run 'LoadConfig|WellKnown' -v`. Expected: FAIL (missing field / key).

- [ ] **Step 3: Implement.** Add `SSHDomain string` to `broker.Config`; set it in `LoadConfig` with `host("SSH_DOMAIN", required("SSH_DOMAIN"))`. Add `SSHDomain string \`json:"ssh_domain"\`` to `auth.Bootstrap` and set it in `server.wellKnown`. Wire `cfg.SSHDomain` into `Authz` and `Hooks` where Tasks 4 and 3 build them (a later task will need the fields; add the struct fields here and pass the config values so `NewHandler` compiles).

- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/broker/ ./internal/auth/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `git add -A && git commit -m "feat(broker): configure and advertise the ssh domain"`.

---

### Task 3: `NewProxy` accepts the SSH custom domain

**Files:**
- Modify: `internal/broker/hooks.go`, `internal/broker/hooks_test.go`
- Modify: `internal/broker/server.go` (pass `SSHDomain` to `Hooks`)

**Interfaces:**
- Consumes: `names.SSHLabel` (Task 1), `Config.SSHDomain` (Task 2).
- Produces: `Hooks.SSHDomain string`; `func ownsSSHProxy(handle, proxy, domain, sshDomain string) bool`.

- [ ] **Step 1: Write the failing tests.** In `hooks_test.go`'s `TestNewProxy` table (handle/owner `alice`, `SSHDomain = "ssh.tunnels.test"`), add: accept `alice.blog` with `customDomains=["alice-blog.ssh.tunnels.test"]` and empty subdomain; reject `alice.blog` with `customDomains=["bob-blog.ssh.tunnels.test"]`, with `customDomains=["alice-blog.w.tunnels.test"]`, with two custom domains, with a non-empty subdomain alongside a custom domain, and with `SSHDomain=""` any custom domain. Update the existing rows that asserted "custom domains set" and "locations set" are rejected so they still describe HTTP tunnels (an HTTP tunnel with a custom domain is accepted only when it is the owner's SSH domain).

- [ ] **Step 2: Run them to verify they fail.** `go test ./internal/broker/ -run NewProxy -v`. Expected: FAIL on the new accept case.

- [ ] **Step 3: Implement.** Add `SSHDomain string` to `Hooks`. In `newProxy`, after the bandwidth check, replace the single http check with:

```go
switch {
case c.ProxyType == "http" && len(c.CustomDomains) == 0 && len(c.Locations) == 0:
	if !ownsProxy(handle, c.ProxyName, c.SubDomain) {
		return h.reject(ctx, plugin.OpNewProxy, "name "+c.ProxyName+" is not yours", nil, who...), nil
	}
case c.ProxyType == "http" && c.SubDomain == "" && len(c.Locations) == 0 && len(c.CustomDomains) == 1:
	if !ownsSSHProxy(handle, c.ProxyName, c.CustomDomains[0], h.SSHDomain) {
		return h.reject(ctx, plugin.OpNewProxy, "name "+c.ProxyName+" is not yours", nil, who...), nil
	}
default:
	return h.reject(ctx, plugin.OpNewProxy, "only plain http and ssh tunnels are allowed", nil, who...), nil
}
```

and add `ownsSSHProxy` next to `ownsProxy`:

```go
func ownsSSHProxy(handle, proxy, domain, sshDomain string) bool {
	tunnel, ok := strings.CutPrefix(proxy, handle+".")
	return ok && sshDomain != "" && names.ValidHandle(handle) &&
		(tunnel == names.Default || names.ValidTunnelName(tunnel)) &&
		domain == names.Label(handle, tunnel)+"."+sshDomain
}
```

- [ ] **Step 4: Run it to verify it passes.** `go test -race ./internal/broker/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `git add -A && git commit -m "feat(broker): let a creator open an ssh tunnel"`.

---

### Task 4: `/authz` bearer mode for the SSH domain

**Files:**
- Modify: `internal/broker/authz.go`, `internal/broker/authz_test.go`
- Modify: `internal/broker/server.go` (pass `Verifier` and `SSHDomain` to `Authz`)

**Interfaces:**
- Consumes: `TokenVerifier` (existing), `idp.ErrInvalidToken` (existing), `names.SSHLabel` (Task 1).
- Produces: `Authz.Verifier TokenVerifier` and `Authz.SSHDomain string`; a decision `outcome` gains `status int` (401 vs 403).

- [ ] **Step 1: Write the failing tests.** In `authz_test.go`, with `SSHDomain = "ssh.tunnels.test"` and a fake verifier: `TestSSHOwnerAllowed` (host `alice-box1.ssh.tunnels.test`, `Authorization: Bearer good`, verifier returns `sub-alice`, store owner `sub-alice` → 200 empty-body), and a table `TestSSHDenied` asserting: no `Authorization` → 401; `Bearer bad` with `idp.ErrInvalidToken` → 401; a valid token whose sub is not the owner → 403; unknown owner → 403; disabled owner → 403; a verifier infrastructure error → 503; host `alice-box1.ssh.tunnels.test:443`, with a trailing dot, `x.alice-box1...`, uppercase `Alice-Box1...` for owner `alice` (uppercase normalises: allowed), and a host under the sites domain → the sites path. Add a `TestSiteStillUsesHeaders`: a site host with only a bearer token and no `X-Tunnels-Sub` → 403.

- [ ] **Step 2: Run them to verify they fail.** `go test ./internal/broker/ -run 'SSH|SiteStill' -v`. Expected: FAIL.

- [ ] **Step 3: Implement.** Add the two fields; add `status int` to `outcome` and make `ServeHTTP` use `o.status` (defaulting to 403) for the deny case. Split `decide` into host dispatch plus `decideSite` (existing logic) and `decideSSH`:

```go
func (a Authz) decideSSH(r *http.Request, label string) outcome {
	handle, _, valid := names.ParseLabel(label)
	if !valid {
		return outcome{reason: "host", status: 403}
	}
	o := outcome{label: label, status: 403}
	token, ok := bearerToken(r)
	if !ok {
		o.reason, o.status = "token", http.StatusUnauthorized
		return o
	}
	ctx, cancel := context.WithTimeout(r.Context(), a.timeout())
	defer cancel()
	sub, err := a.Verifier.VerifyAccessToken(ctx, token)
	if err != nil {
		o.status = http.StatusServiceUnavailable
		if errors.Is(err, idp.ErrInvalidToken) {
			o.status, o.reason = http.StatusUnauthorized, "token"
		} else {
			o.reason = "verify"
			o.err = err
		}
		return o
	}
	o.sub = sub
	owner, err := a.Users.UserByHandle(ctx, handle)
	switch {
	case errors.Is(err, store.ErrNotFound):
		o.reason = "unknown_owner"
	case err != nil:
		o.reason, o.err, o.status = "store", err, http.StatusServiceUnavailable
	case owner.Disabled:
		o.reason = "disabled"
	case owner.Sub != sub:
		o.reason = "not_owner"
	default:
		o.allow, o.reason = true, "owner"
	}
	return o
}
```

`decide` dispatches: if `SitesDomain != ""` and `SiteLabel` matches → `decideSite`; else if `SSHDomain != ""` and `SSHLabel` matches → `decideSSH`; else `outcome{reason: "host", status: 403}`. On allow, set `X-Tunnel-User` only when `o.user != ""`.

- [ ] **Step 4: Run it to verify it passes.** `go test -race ./internal/broker/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `git add -A && git commit -m "feat(broker): authorize ssh visits by bearer token"`.

---

### Task 5: `internal/ws` byte pump

**Files:**
- Create: `internal/ws/ws.go`, `internal/ws/ws_test.go`
- Modify: `go.mod`, `go.sum` (`go get github.com/gorilla/websocket && go mod tidy`)

**Interfaces:**
- Produces: `func Pipe(conn *websocket.Conn, peer io.ReadWriteCloser) error` — copies bytes both ways until either side ends, then closes both.

- [ ] **Step 1: Write the failing test.** `TestPipeEchoes`: start a `httptest.Server` whose handler upgrades with `websocket.Upgrader{}` and runs `Pipe(ws, peer)` against a `net.Pipe()`; from the other end of the pipe echo bytes back; dial with `websocket.DefaultDialer`, `Pipe` it to a buffer, write a line, and assert it returns. Also `TestPipeClosesPeer`: closing the WS side makes `Pipe` return and close the peer.

- [ ] **Step 2: Run it to verify it fails.** `go test ./internal/ws/ -v`. Expected: build failure, `undefined: Pipe`.

- [ ] **Step 3: Implement** the reader/writer pair; one goroutine reads WS messages into `peer`, the other reads `peer` into WS binary messages, and the first error closes both connections (which unblocks the other goroutine):

```go
func Pipe(conn *websocket.Conn, peer io.ReadWriteCloser) error {
	done := make(chan error, 2)
	go func() {
		for {
			_, r, err := conn.NextReader()
			if err != nil { done <- err; return }
			if _, err := io.Copy(peer, r); err != nil { done <- err; return }
		}
	}()
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := peer.Read(buf)
			if n > 0 {
				w, werr := conn.NextWriter(websocket.BinaryMessage)
				if werr == nil {
					_, werr = w.Write(buf[:n])
					if werr == nil { werr = w.Close() }
				}
				if werr != nil { done <- werr; return }
			}
			if err != nil { done <- err; return }
		}
	}()
	err := <-done
	_ = conn.Close()
	_ = peer.Close()
	return err
}
```

- [ ] **Step 4: Run it to verify it passes.** `go test -race ./internal/ws/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `git add internal/ws go.mod go.sum && git commit -m "feat(ws): pump bytes over a websocket"`.

---

### Task 6: `tunnel.Build` produces the SSH proxy

**Files:**
- Modify: `internal/tunnel/tunnel.go`, `internal/tunnel/tunnel_test.go`

**Interfaces:**
- Produces: `Options` gains `SSH bool`, `SSHTarget string` (bare host, default `127.0.0.1`), `SSHPort int` (target port), `SSHDomain string`. In SSH mode `Build` emits one `http` proxy with `CustomDomains=[<label>.<SSHDomain>]`, empty `SubDomain`, and `LocalPort = o.LocalPort` (the bridge port).

- [ ] **Step 1: Write the failing tests.** Add to `tunnel_test.go`: `TestBuildSSHFields` (with `SSH=true`, `SSHTarget="127.0.0.1"`, `SSHPort=22`, `SSHDomain="ssh.tunnels.test"`, `Name="blog"`, `LocalPort=5000`: proxy `*v1.HTTPProxyConfig`, `Type=="http"`, `Name=="blog"`, `CustomDomains==["alice-blog.ssh.tunnels.test"]`, `SubDomain==""`, `LocalIP=="127.0.0.1"`, `LocalPort==5000`, `RequestHeaders.Set["x-forwarded-proto"]=="https"`); `TestBuildSSHDefaultTunnel` (`Name==""` → `CustomDomains==["alice.ssh.tunnels.test"]`, `Name=="default"`); and refusal rows in `TestBuildRefuses`: SSH with empty `SSHDomain`, SSH with `SSHTarget="192.168.1.5:22"`, SSH with `SSHTarget="http://x"`, SSH with `SSHTarget=""`.

- [ ] **Step 2: Run them to verify they fail.** `go test ./internal/tunnel/ -run 'BuildSSH|BuildRefuses' -v`. Expected: build failure (unknown fields) then FAIL.

- [ ] **Step 3: Implement.** Add the fields. Add refusals: `o.SSH && o.SSHDomain == ""`, `o.SSH && !validTargetHost(o.SSHTarget)`, where `validTargetHost` rejects `""`, anything containing `:` or `/`. In the marshalled `proxies` entry, branch: SSH uses `"customDomains": []any{names.Label(o.Handle, o.Name) + "." + o.SSHDomain}` and omits `subdomain`; otherwise unchanged.

- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/tunnel/ -v`. Expected: PASS, and the existing non-SSH tests still pass.

- [ ] **Step 5: Commit.** `git add internal/tunnel && git commit -m "feat(tunnel): build an ssh proxy config"`.

---

### Task 7: The SSH bridge and `Run` wiring

**Files:**
- Create: `internal/tunnel/bridge.go`, `internal/tunnel/bridge_test.go`
- Modify: `internal/tunnel/tunnel.go` (`Run`), `internal/tunnel/tunnel_test.go`

**Interfaces:**
- Consumes: `ws.Pipe` (Task 5).
- Produces: `type bridge` with `newBridge(target string, port int) (*bridge, error)`, `(*bridge).Port() int`, `(*bridge).Serve(ctx context.Context)`, `(*bridge).Close() error`. `Run`, when `o.SSH`, starts a bridge to `o.SSHTarget:o.SSHPort`, sets `o.LocalPort = b.Port()`, serves it in a goroutine, and closes it when `Run` returns.

- [ ] **Step 1: Write the failing test.** `TestBridgeEchoes`: start a TCP listener that echoes; `newBridge("127.0.0.1", echoPort)`; `go b.Serve(ctx)`; dial `ws://127.0.0.1:<b.Port()>/` with `websocket.DefaultDialer`, `ws.Pipe` the connection to a buffer; write `"ping"`; assert `"ping"` comes back. `TestBridgeStopsWithContext`: after cancelling, `Serve` returns and new dials are refused.

- [ ] **Step 2: Run it to verify it fails.** `go test ./internal/tunnel/ -run Bridge -v`. Expected: build failure, `undefined: newBridge`.

- [ ] **Step 3: Implement** `bridge.go`: `net.Listen("tcp", "127.0.0.1:0")`; `Serve` accepts until the listener closes or ctx ends, and for each connection runs `websocket.Upgrader{}.Upgrade(w, r, nil)` then `net.Dial("tcp", net.JoinHostPort(b.target, strconv.Itoa(b.port)))` and `ws.Pipe`. `Close` closes the listener. In `Run`, wrap `Build` as described.

- [ ] **Step 4: Run it to verify it passes.** `go test -race ./internal/tunnel/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `git add internal/tunnel && git commit -m "feat(tunnel): serve an ssh bridge and run it"`.

---

### Task 8: `tunnel up PORT --ssh`

**Files:**
- Modify: `internal/cli/cli.go`, `internal/cli/cli_test.go`

**Interfaces:**
- Consumes: `tunnel.Options` SSH fields (Task 6), `auth.Bootstrap.SSHDomain` (Task 2).
- Produces: `up` accepts `--ssh` (bool) and `--target HOST` (default `127.0.0.1`); on `--ssh` it prints `ssh <label>.<ssh_domain>` when the status becomes `running` and sets the SSH fields on `tunnel.Options`.

- [ ] **Step 1: Write the failing tests.** In `cli_test.go`: `TestUpSSHPassesOptions` — run `Main([]string{"up", "22", "--ssh", "--name", "box1"}, env)` with the fake `Run` capturing `tunnel.Options`, assert `SSH == true`, `SSHtarget == "127.0.0.1"`, `SSHPort == 22`, `SSHDomain == "ssh.tunnels.test"`. `TestUpSSHRejectsTargetWithPort`, `TestUpSSHRejectsTargetWithScheme` — `--target 192.168.1.5:22` / `--target http://x` exit 2 with a message naming the target. The world's bootstrap document gains `"ssh_domain": "ssh.tunnels.test"`.

- [ ] **Step 2: Run them to verify they fail.** `go test ./internal/cli/ -run 'UpSSH' -v`. Expected: FAIL.

- [ ] **Step 3: Implement**: add the flags, validate the target with the same rule as `Build` (reject `:` and `/`), pass the fields, and print the SSH host via `names.Label(tok.Handle, *name) + "." + b.SSHDomain`.

- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/cli/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `git add internal/cli && git commit -m "feat(cli): publish an ssh tunnel with up --ssh"`.

---

### Task 9: `tunnel ssh-config`

**Files:**
- Modify: `internal/cli/cli.go`, `internal/cli/cli_test.go`

**Interfaces:**
- Produces: `tunnel ssh-config [--name NAME]` prints, to stdout, exactly:

```
Host <label>
	HostName <label>.<ssh_domain>
	ProxyCommand tunnel dial %h %p
```

- [ ] **Step 1: Write the failing test.** `TestSSHConfigPrintsBlock`: logged in as `alice`, `--name box1`, bootstrap `ssh_domain=ssh.tunnels.test`; assert stdout equals the exact block with `Host alice-box1`, `HostName alice-box1.ssh.tunnels.test`, `ProxyCommand tunnel dial %h %p`. `TestSSHConfigNotLoggedIn` exits 1 with `tunnel login` in the message.

- [ ] **Step 2: Run it to verify it fails.** `go test ./internal/cli/ -run SSHConfig -v`. Expected: FAIL.

- [ ] **Step 3: Implement** the command (`login`/`logout`/`version` style): load the store, `auth.Discover`, print the block. Add `ssh-config` to `usage`.

- [ ] **Step 4: Run it to verify it passes.** `go test -race ./internal/cli/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `git add internal/cli && git commit -m "feat(cli): print an ssh_config block"`.

---

### Task 10: `tunnel dial`

**Files:**
- Modify: `internal/cli/cli.go`, `internal/cli/cli_test.go`

**Interfaces:**
- Consumes: `ws.Pipe` (Task 5), `auth.Store`, `auth.RefreshStored`, `tunnel.WriteCABundle`.
- Produces: `tunnel dial HOST PORT` connects to `HOST:443` over TLS (ALPN `http/1.1`), upgrades with `Authorization: Bearer <access token>`, and pipes `os.Stdin`/`os.Stdout`. On a 401 handshake it calls `auth.RefreshStored` once and retries; a second failure prints `run: tunnel login` and exits 1.

- [ ] **Step 1: Write the failing tests.** With an `httptest.NewTLSServer` that upgrades only when `Authorization: Bearer <the stored token>` is present and otherwise answers 401: `TestDialPipes` (a `tunnel dial <host> 22` with a valid stored token pipes stdin↔socket and exits 0) and `TestDialRefreshesOn401` (a stale stored token, the mock IdP issues a new one on refresh, the server then accepts it). Inject the TLS root via the `CAFile` written by `WriteCABundle` and a fake `Env`. If a full TLS handshake is impractical in the unit test, cover the token selection helper `dialToken` (fresh when valid, refresh then retry) and leave byte pumping to the e2e task.

- [ ] **Step 2: Run them to verify they fail.** `go test ./internal/cli/ -run Dial -v`. Expected: FAIL.

- [ ] **Step 3: Implement**: `login`-style command; `net.Dialer` + `tls.Client` with `ServerName=HOST`, `NextProtos=["http/1.1"]`, `RootCAs` from the CA file; `websocket.Dialer` with `NetDialTLSContext` returning that TLS conn and `HTTPHeader{Authorization: "Bearer " + token}`; on `ErrBadHandshake` with `resp.StatusCode == 401`, `RefreshStored` and retry once; then `ws.Pipe`.

- [ ] **Step 4: Run them to verify they pass.** `go test -race ./internal/cli/ -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `git add internal/cli && git commit -m "feat(cli): dial an ssh tunnel"`.

---

### Task 11: End-to-end SSH path

**Files:**
- Modify: `e2e/e2e_test.go`

**Interfaces:**
- Consumes: `tunnel.Run` (Task 7), `tunnel.Options` SSH fields (Task 6), broker `SSH_DOMAIN` (Task 2).

- [ ] **Step 1: Write the failing test.** Add `TestSSHEndToEnd`: start an echo TCP listener; run the agent with `SSH=true`, `SSHTarget="127.0.0.1"`, `SSHPort=echoPort`, `SSHDomain=sshDomain` against the real frps; then dial frps's `vhostHTTPPort` directly with `Host: <label>.<sshDomain>` (no Traefik in the harness), `ws.Pipe` to a buffer, write and read a line. Set `SSH_DOMAIN` in the broker config the harness builds. Expected before the change: the tunnel is refused by `NewProxy`.

- [ ] **Step 2: Run it to verify it fails.** `TEST_DATABASE_URL=... go test -tags e2e ./e2e/ -run SSH -v`. Expected: FAIL.

- [ ] **Step 3: Implement** the test using the existing e2e helpers (the same frps binary, broker and store helpers).

- [ ] **Step 4: Run it to verify it passes.** `TEST_DATABASE_URL=... go test -race -tags e2e ./e2e/ -run SSH -v`. Expected: PASS.

- [ ] **Step 5: Commit.** `git add e2e && git commit -m "test(e2e): prove the ssh path end to end"`.

---

### Task 12: Record the deployment changes

**Files:**
- Modify: `README.md`
- Modify: `docs/design.md` (the "Later: SSH" line and the env table)

**Interfaces:** none.

- [ ] **Step 1: Update `README.md`**: add `SSH_DOMAIN` to the broker env table, and a `tunnel up PORT --ssh`, `tunnel ssh-config`, `tunnel dial` line each to the Use section.
- [ ] **Step 2: Update `docs/design.md`**: note SSH is implemented, and list the homelab work this repo cannot do — DNS `*.ssh.<...>` DNS-only, a wildcard certificate, a Traefik `Host(*.ssh.…)` route with `forwardAuth` only (no OIDC plugin) and `authRequestHeaders` including `Authorization`, and that frps and the NetworkPolicy are unchanged.
- [ ] **Step 3: Commit.** `git add README.md docs && git commit -m "docs: record the ssh domain and deployment"`.

---

## Self-Review

- **Spec coverage:** `names` (Task 1) ✔; `SSH_DOMAIN`/bootstrap (Task 2) ✔; `NewProxy` (Task 3) ✔; `/authz` bearer (Task 4) ✔; `Build` SSH proxy (Task 6) ✔; bridge + `Run` (Task 7) ✔; `up --ssh`, `ssh-config`, `dial` (Tasks 8-10) ✔; e2e (Task 11) ✔; infra/docs (Task 12) ✔. The deferred web terminal is intentionally not planned.
- **Type consistency:** `SSHDomain` on `Config`/`Hooks`/`Authz`/`Bootstrap`; `Options.SSH/SSHTarget/SSHPort/SSHDomain`; `ws.Pipe(conn, peer)`. Reused unchanged: `names.Label`, `names.ParseLabel`, `bearerToken`, `TokenVerifier`, `auth.RefreshStored`.
- **Review Focus:** each line names its owning task's test (1 → Tasks 3/4, 2 → Task 3, 3 → Task 4, 4 → Task 10, 5 → Tasks 6/8).
- **Proportion:** task count and detail are proportionate to an eight-file feature; no task transcribes a body its signature and tests already determine, except `ws.Pipe` and `ownsSSHProxy`, whose algorithms are given because they are not otherwise determined.
