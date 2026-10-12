# Tunnels SSH: one host, the name in the path - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish every SSH tunnel at the one host `SSH_DOMAIN` and name the tunnel in the request path, so no `*.ssh.` wildcard exists and a client sends a name rather than composing a hostname.

**Architecture:** The agent publishes one frp `http` proxy with `customDomains=["<SSH_DOMAIN>"]` and `locations=["/<label>/"]`; frps routes by host and then by location prefix. The broker's `NewProxy` accepts exactly that shape, and `/authz` decides an SSH request from the exact host plus the first path segment of `X-Forwarded-Uri`. The CLI takes the label from the SSH name ssh was asked for and puts it in the URL path.

**Tech Stack:** Go 1.26, `github.com/fatedier/frp` v0.71.0 (client library + plugin types), `github.com/gorilla/websocket`, `github.com/spf13/pflag`.

**Spec:** `docs/plans/2026-10-12-tunnels-ssh-one-host-design.md`.

## Global Constraints

- Module `github.com/layertwo/tunnels`, `go 1.26.0`, default branch `mainline`, commits `feat(scope): ...`, one pull request per task.
- `github.com/fatedier/frp` stays v0.71.0, equal to the frps image `ghcr.io/fatedier/frps:v0.71.0@sha256:cd8b947ba61678b200baa4f71ccc33f3c52e4e2cc0059700ba3b8354e36af7c3`; bump together.
- `./internal/...` stays at **100%** test coverage; the CI gate (`go-test-coverage`) enforces it and excludes `cmd/` and the tagged `e2e` package. Write the test before the code.
- Tests: `go test -race ./...`. The e2e test is behind the `e2e` build tag: `go test -tags e2e ./e2e/...` (no `-race`; an upstream frp race).
- Every new configuration option is optional; a release must start with none set. A contradictory value is a startup error naming the variable.
- Never log a token, a private key, the plugin secret, or a run ID.
- An SSH location is `/<label>/` with the trailing boundary - frp matches a location with `strings.HasPrefix`, so `/alice` would swallow `/alicex`. The broker must authorize the same string frps routes on.
- The values that are fixed by the spec: SSH host `ssh.tunnels.layertwo.dev`; a test's domain `ssh.tunnels.test`; label `<handle>` or `<handle>-<name>`; frp proxy name `<handle>.<name>`.

## Review Focus

1. **A request naming a route it does not own.** A publisher registering `/bob/`, `/alice-box1` without the boundary, or a second location must be refused by `NewProxy`; frps would also conflict, but the broker refuses first. Task 3.
2. **A path another owner's location could swallow.** With `/alice/` registered, `/alicex/` must match nothing: frps answers 404 and the broker never allows it. Tasks 2 and 3.
3. **`SSH_DOMAIN` equal to, or under, `SITES_DOMAIN`.** `decide` dispatches sites first, so such a host would be served as a site and SSH would be silently dead. Expect a startup error naming `SSH_DOMAIN`, not a running broker whose SSH routes never fire. Task 4.
4. **Cross-talk between the two authz modes.** A bearer token on a site host, or `X-Tunnels-*` identity headers on the SSH host, must authorize neither. Task 2.
5. **The name a user actually types.** `alice-box1.layertwo.lan` and a bare `alice-box1` must both name the label `alice-box1`; anything that is not a label must be refused before TLS. Task 1.

---

### Task 1: `dial` takes a name, not a hostname

**Files:**
- Modify: `internal/cli/cli.go` (the `usage` and `usageDial` consts near line 50/66; `dial`, lines 367-460)
- Test: `internal/cli/cli_test.go` (`TestDialArgumentErrors:1744`, plus a new test)

**Interfaces:**
- Produces: `func sshEndpoint(name, sshDomain string) (endpoint string, err error)` - the `wss://` data route for the tunnel an SSH name asks for.
- Consumes: `names.ParseLabel` (existing), the stored login's `SSHDomain`.

- [ ] **Step 1: Write the failing test** in `internal/cli/cli_test.go`:

```go
// The name ssh was asked for names the tunnel. The tunnel is the name before the first dot, because
// the alias domain after it is the user's own convention: the service never learns it. The label
// travels in the path, which the broker authorizes and frps routes on.
func TestSSHEndpoint(t *testing.T) {
	const domain = "ssh.tunnels.test"
	tests := []struct {
		name     string
		endpoint string
		ok       bool
	}{
		{"alice-box1.layertwo.lan", "wss://ssh.tunnels.test:443/alice-box1/", true},
		{"alice-box1", "wss://ssh.tunnels.test:443/alice-box1/", true},
		{"alice.layertwo.lan", "wss://ssh.tunnels.test:443/alice/", true},
		{"Alice-Box1.layertwo.lan", "", false}, // paths, and frp locations, are case-sensitive
		{"alice_box1.layertwo.lan", "", false},
		{"x.layertwo.lan", "", false},
		{".layertwo.lan", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		endpoint, err := sshEndpoint(tt.name, domain)
		if endpoint != tt.endpoint || (err == nil) != tt.ok {
			t.Errorf("sshEndpoint(%q) = %q, %v; want %q, ok=%v", tt.name, endpoint, err, tt.endpoint, tt.ok)
		}
	}
}
```

and replace the cases and the usage assertion in `TestDialArgumentErrors`:

```go
	for _, args := range [][]string{
		{"dial"},
		{"dial", "one", "two"},
		{"dial", "--bogus", "alice-box1"},
		{"dial", "alice_box1"},
	} {
		// ... unchanged body, wanting exit 2 and the stderr line "tunnel dial NAME"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/ -run 'TestSSHEndpoint|TestDialArgumentErrors' -v`
Expected: FAIL - `undefined: sshEndpoint`, and the usage assertions find `tunnel dial HOST PORT`.

- [ ] **Step 3: Implement**

In `internal/cli/cli.go`: `sshEndpoint` cuts `name` at the first `.`, requires `names.ParseLabel` to accept what is left, and returns `"wss://" + sshDomain + ":443/" + label + "/"`; the error names the name and says the tunnel is the part before the first dot.

`dial` takes one positional argument (the name) instead of two, drops the port parsing, resolves the domain exactly as it does now (the stored `SSHDomain`, else discovery), calls `sshEndpoint`, and dials it. Its TLS `ServerName` and the `Host` header become the domain, not the name: the endpoint has no per-tunnel host anymore, and `dialStream` already derives the bare host from the endpoint's `url.Hostname()`.

Update `usage`:

```
  tunnel dial NAME                               pipe ssh through a published tunnel (an ssh ProxyCommand)
```

and `usageDial = "Usage: tunnel dial NAME"`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/...`
Expected: PASS. `TestDialStreamSendsTheBareHost` still passes: it drives `dialStream` directly.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/cli.go internal/cli/cli_test.go
git commit -m "feat(cli): dial names the tunnel instead of building a hostname"
```

---

### Task 2: the broker reads the label from the request path

**Files:**
- Modify: `internal/names/names.go:91-93`, `internal/names/names_test.go:150-172`
- Modify: `internal/broker/authz.go` (`decide`, lines 114-134)
- Test: `internal/broker/authz_test.go` (`sshRequest:796`, `TestSSH*`)

**Interfaces:**
- Produces: `func SSHLabel(path string) (label string, ok bool)` - replaces `SSHLabel(host, sshDomain string)`; its only caller is `decide`.
- Consumes: `names.ParseLabel`, the `Authz.SSHDomain` field (existing).

- [ ] **Step 1: Write the failing test** - replace `TestSSHLabel` in `internal/names/names_test.go`:

```go
func TestSSHLabel(t *testing.T) {
	tests := []struct {
		path  string
		label string
		ok    bool
	}{
		{"/alice-box1/", "alice-box1", true},
		{"/alice/", "alice", true},
		{"/alice-box1/anything", "alice-box1", true},
		{"/alice-box1", "", false}, // no boundary: frps's location ends in "/"
		{"alice-box1/", "", false}, // no leading slash
		{"/alice-box1x/", "alice-box1x", true}, // its own label, and a different route
		{"/Alice-Box1/", "", false},
		{"/alice-box1:/", "", false},
		{"/alice-box1./", "", false},
		{"/x/", "", false},
		{"/", "", false},
		{"//alice/", "", false},
		{"", "", false},
		{"/\u212Aelvin/", "", false}, // strings.ToLower would make this "kelvin"
	}
	for _, tt := range tests {
		label, ok := SSHLabel(tt.path)
		if label != tt.label || ok != tt.ok {
			t.Errorf("SSHLabel(%q) = %q, %v; want %q, %v", tt.path, label, ok, tt.label, tt.ok)
		}
	}
}
```

In `internal/broker/authz_test.go`, change `sshRequest` (line 796) to the new shape and add the two dispatch cases:

```go
// sshRequest is what Traefik's forwardAuth sends for a terminal dialling an SSH tunnel: a bearer
// token, the one SSH host, and the tunnel's label as the first segment of the request path.
func sshRequest(auth string) http.Header {
	h := http.Header{}
	h.Set("X-Forwarded-Host", sshDomain)
	h.Set("X-Forwarded-Uri", "/alice-box1/")
	...
}
```

and, in the refusal matrix, add:

```go
		{"the ssh host with no request path", func(_ *authzRig, _ *fakeVerifier, h http.Header) {
			h.Del("X-Forwarded-Uri")
		}, http.StatusForbidden, 0, false},
		{"the ssh host with a repeated request path", func(_ *authzRig, _ *fakeVerifier, h http.Header) {
			h["X-Forwarded-Uri"] = []string{"/alice-box1/", "/alice-box1/"}
		}, http.StatusForbidden, 0, false},
		{"a path with no label boundary", func(_ *authzRig, _ *fakeVerifier, h http.Header) {
			h.Set("X-Forwarded-Uri", "/alice-box1")
		}, http.StatusForbidden, 0, false},
```

The case named "identity headers do not authorize an ssh host" (line 882) keeps its `X-Forwarded-Uri` and must still be refused, and its mirror must be added - a site host carrying a bearer token and no identity headers is still refused by the site branch:

```go
		{"a bearer token does not authorize a site host", func(r *authzRig, _ *fakeVerifier, h http.Header) {
			h.Set("X-Forwarded-Host", "alice."+sitesDomain)
			h.Set("Authorization", "Bearer good")
			h.Del("X-Tunnels-Sub")
			h.Del("X-Tunnels-User")
		}, http.StatusForbidden, 0, false},
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/names/ ./internal/broker/ -run 'TestSSH' -v`
Expected: FAIL to compile - `SSHLabel` takes two arguments; then the new refusal cases fail with 200.

- [ ] **Step 3: Implement**

`names.SSHLabel(path string)`: require a leading `/`, cut on the next `/` (its absence is a refusal - that is the boundary frps's location needs), and require `ParseLabel` to accept the segment. Compare case-sensitively, as frp's locations are.

`Authz.decide`: after the single-`X-Forwarded-Host` guard, and before the sites branch, add - when `a.SSHDomain != ""` and `strings.EqualFold(hosts[0], a.SSHDomain)` - a single-`X-Forwarded-Uri` guard whose failure is the same `outcome{reason: "host", status: 403}` as a bad host, then `names.SSHLabel(uri)` and `a.decideSSH(r, label)`. `decideSSH` itself is unchanged. Keep the existing comment about indexing headers by their canonical names; the URI is read the same way.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/names/names.go internal/names/names_test.go internal/broker/authz.go internal/broker/authz_test.go
git commit -m "feat(broker): read the ssh tunnel's label from the request path"
```

---

### Task 3: one domain, one location per tunnel

The agent's publish shape, the broker's `NewProxy` rule and the e2e proof change together: the broker would refuse a live old-shape agent, so no smaller step leaves both working.

**Files:**
- Modify: `internal/tunnel/tunnel.go:74-79`, `internal/tunnel/tunnel_test.go:96-122`
- Modify: `internal/broker/hooks.go:154-165,198-205`, `internal/broker/hooks_test.go` (`TestNewProxy:279`)
- Modify: `e2e/e2e_test.go` (`upSSH:286`, `TestSSHEndToEnd:898`)

**Interfaces:**
- Consumes: `names.Label` (existing), `h.SSHDomain` (existing).
- Produces: `func ownsSSHProxy(handle, proxy, domain, location, sshDomain string) bool`.

- [ ] **Step 1: Write the failing agent test**

In `internal/tunnel/tunnel_test.go`, the two SSH cases assert the new shape (`p.Locations` already exists on the parsed proxy - the site case at line 77 pins it empty):

```go
	if !reflect.DeepEqual(p.CustomDomains, []string{"ssh.tunnels.test"}) ||
		!reflect.DeepEqual(p.Locations, []string{"/alice-blog/"}) {
		t.Errorf("custom domains %v, locations %v; want the shared ssh host and the one location", p.CustomDomains, p.Locations)
	}
```

and the default-tunnel case wants `CustomDomains ["ssh.tunnels.test"]` with `Locations ["/alice/"]`.

- [ ] **Step 2: Write the failing broker test**

In `internal/broker/hooks_test.go`, add a modifier beside `domains`/`locations` (line 282-283) - the table's fields are `name, handle, proxy, sub, mod, sshOff, count, countErr, reason, wantCounted`, and `sshDomain` is the const from `authz_test.go`, in the same package:

```go
	sshAt := func(location string) mod {
		return func(c *plugin.NewProxyContent) { c.CustomDomains, c.Locations = []string{sshDomain}, []string{location} }
	}
```

Replace the SSH rows (lines 346-376) with:

```go
		// An ssh tunnel is an ordinary http proxy published at the one ssh host with the publisher's
		// own label as its only location; the location must carry the trailing boundary, or a location
		// /alice would answer for /alicex.
		{name: "ssh tunnel", handle: "alice", proxy: "alice.blog", sub: "", count: 1, wantCounted: true,
			mod: sshAt("/alice-blog/")},
		{name: "ssh default tunnel", handle: "alice", proxy: "alice.default", sub: "", wantCounted: true,
			mod: sshAt("/alice/")},
		{name: "ssh location of another owner", handle: "alice", proxy: "alice.blog", sub: "",
			mod: sshAt("/bob-blog/"), reason: "name alice.blog is not yours"},
		{name: "ssh location without the boundary", handle: "alice", proxy: "alice.blog", sub: "",
			mod: sshAt("/alice-blog"), reason: "name alice.blog is not yours"},
		{name: "ssh location with a trailing segment", handle: "alice", proxy: "alice.blog", sub: "",
			mod: sshAt("/alice-blog/extra"), reason: "name alice.blog is not yours"},
		{name: "ssh location in capitals", handle: "alice", proxy: "alice.blog", sub: "",
			mod: sshAt("/ALICE-BLOG/"), reason: "name alice.blog is not yours"},
		{name: "ssh default tunnel with a name's location", handle: "alice", proxy: "alice.default", sub: "",
			mod: sshAt("/alice-blog/"), reason: "name alice.default is not yours"},
		{name: "ssh proxy of another owner", handle: "alice", proxy: "bob.blog", sub: "",
			mod: sshAt("/bob-blog/"), reason: "name bob.blog is not yours"},
		{name: "ssh host with a subdomain", handle: "alice", proxy: "alice.blog", sub: "alice-blog",
			mod: sshAt("/alice-blog/"), reason: "only plain http and ssh tunnels are allowed"},
		{name: "ssh with two locations", handle: "alice", proxy: "alice.blog", sub: "",
			mod: func(c *plugin.NewProxyContent) {
				c.CustomDomains, c.Locations = []string{sshDomain}, []string{"/alice-blog/", "/alice/"}
			},
			reason: "only plain http and ssh tunnels are allowed"},
		{name: "ssh with no location", handle: "alice", proxy: "alice.blog", sub: "",
			mod: domains(sshDomain), reason: "only plain http and ssh tunnels are allowed"},
		{name: "ssh with two custom domains", handle: "alice", proxy: "alice.blog", sub: "",
			mod: func(c *plugin.NewProxyContent) {
				c.CustomDomains, c.Locations = []string{sshDomain, sshDomain}, []string{"/alice-blog/"}
			},
			reason: "only plain http and ssh tunnels are allowed"},
		{name: "ssh host with a label", handle: "alice", proxy: "alice.blog", sub: "",
			mod: sshAt("/alice-blog/"), sshOff: true, reason: "name alice.blog is not yours"},
```

The `locations`-only row at line 343 stays: with no custom domain it still falls to the same refusal.

- [ ] **Step 3: Write the failing e2e**

In `e2e/e2e_test.go`, replace `TestSSHEndToEnd` with a two-tunnel proof, and add a listener that greets before echoing so the two targets are distinguishable:

```go
// greetingListener accepts TCP connections, writes greeting, then echoes each line back; the greeting
// is what tells one target's bytes from another's.
func greetingListener(t *testing.T, greeting string) int { ... }
```

The test publishes alice's default tunnel (location `/alice/`) on one greeting and `box1` (location `/alice-box1/`) on another, then:

```go
	for _, tt := range []struct{ path, greeting string }{
		{"/alice/", "default\n"},
		{"/alice-box1/", "box1\n"},
	} {
		// Dial "ws://"+s.vhost+tt.path with the Host header sshDomain, read a line, and want tt.greeting.
	}
	// A path no location matches is reached by no bridge: one owner's traffic must not land on another.
	if conn, resp, err := (&websocket.Dialer{}).Dial("ws://"+s.vhost+"/alicex/", http.Header{"Host": []string{sshDomain}}); err == nil {
		resp.Body.Close()
		_ = conn.Close()
		t.Error("dialled /alicex/, which no tunnel registered")
	}
```

`upSSH` needs no change: it passes `SSHDomain` into `tunnel.Options`, and `Build` now writes the location.

- [ ] **Step 4: Run the tests to verify they fail**

Run: `go test ./internal/tunnel/ -run TestBuild -v && go test ./internal/broker/ -run TestNewProxy -v`
Expected: FAIL - the locations are empty, and `NewProxy` refuses the shared host.

- [ ] **Step 5: Implement**

`tunnel.Build`, in the `o.SSH` branch: `proxy["customDomains"] = []any{o.SSHDomain}` and `proxy["locations"] = []any{"/" + names.Label(o.Handle, o.Name) + "/"}`, with a one-line comment that frps has one `subDomainHost`, so the SSH subtree is one custom domain told apart by location.

`hooks.go`: in the `newProxy` switch, the SSH arm becomes

```go
	case c.ProxyType == "http" && c.SubDomain == "" && len(c.CustomDomains) == 1 && len(c.Locations) == 1:
		if !ownsSSHProxy(handle, c.ProxyName, c.CustomDomains[0], c.Locations[0], h.SSHDomain) {
```

and

```go
// ownsSSHProxy is ownsProxy for an SSH tunnel: the same name, published at the one ssh host with the
// publisher's own label as its location. The location must carry the trailing boundary, or a
// location /alice would answer for /alicex. sshDomain empty (the feature off) refuses every domain.
func ownsSSHProxy(handle, proxy, domain, location, sshDomain string) bool {
	tunnel, ok := proxyTunnel(handle, proxy)
	return ok && sshDomain != "" && domain == sshDomain && location == "/"+names.Label(handle, tunnel)+"/"
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test -race ./internal/... && go test -tags e2e ./e2e/...`
Expected: PASS, including the two tunnels on one domain and the `/alicex/` refusal.

- [ ] **Step 7: Commit**

```bash
git add internal/tunnel/tunnel.go internal/tunnel/tunnel_test.go internal/broker/hooks.go internal/broker/hooks_test.go e2e/e2e_test.go
git commit -m "feat: publish every ssh tunnel at one host, named by its location"
```

---

### Task 4: an SSH domain under the sites domain is refused at startup

**Files:**
- Modify: `internal/broker/config.go:202-206`
- Test: `internal/broker/config_test.go:515` (the `sameAsSites` case)

**Interfaces:**
- Consumes: `c.SSHDomain`, `c.SitesDomain` (both existing).

- [ ] **Step 1: Write the failing test** - extend the `sameAsSites` case at `config_test.go:515` so the pair is refused when they are equal *or* when `SSH_DOMAIN` is under `SITES_DOMAIN`:

```go
	// decide dispatches sites first, so a host the sites domain claims would be served as a site and
	// the SSH routes would never fire.
	underSites := map[string]string{"SSH_DOMAIN": "ssh.w.tunnels.layertwo.dev"}
```

with the assertion that `Load` returns an error naming `SSH_DOMAIN`, and a companion case that `ssh.tunnels.layertwo.dev` against `SITES_DOMAIN=w.tunnels.layertwo.dev` still loads.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/broker/ -run 'TestLoad' -v`
Expected: FAIL - the broker starts with an SSH host the sites domain owns.

- [ ] **Step 3: Implement**

```go
	// decide's site-first dispatch claims every host the sites domain owns, so an SSH host equal to,
	// or under, it would be silently dead: refuse the pair rather than start such a broker.
	if c.SSHDomain != "" && (c.SSHDomain == c.SitesDomain || strings.HasSuffix(c.SSHDomain, "."+c.SitesDomain)) {
		bad("SSH_DOMAIN", "must not be SITES_DOMAIN or under it")
	}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/broker/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/broker/config.go internal/broker/config_test.go
git commit -m "fix(broker): refuse an ssh domain the sites domain owns"
```

---

### Task 5: `ssh-config` prints the one block, and `up` points at it

**Files:**
- Modify: `internal/cli/cli.go` (`usage:50`, `usageSSHConfig:68`, `sshConfig:287-324`, `up:243-249`)
- Test: `internal/cli/cli_test.go:533-620` (the `---- ssh-config` section, and `up`'s running line)
- Modify: `README.md:18-20,42-44`

**Interfaces:**
- Consumes: the stored login and the bootstrap (`sshConfig` keeps both, so it can still say "this server has ssh disabled").
- Produces: `tunnel ssh-config --alias-domain DOMAIN`; usage `tunnel ssh-config --alias-domain DOMAIN`.

- [ ] **Step 1: Write the failing tests**

Replace the `ssh-config` table at `cli_test.go:543`:

```go
		{"an alias domain", []string{"ssh-config", "--alias-domain", "layertwo.lan"},
			"Host *.layertwo.lan\n\tProxyCommand tunnel dial %n\n"},
```

The existing refusal cases (no login, unreachable server, a bad flag, an extra argument) stay, with `--alias-domain layertwo.lan` added where a login is expected; the missing-`--alias-domain` case wants exit 2 and the stderr line `tunnel ssh-config --alias-domain DOMAIN`.

Add to the `up --ssh` test that the running line names the label and points at `ssh-config`:

```go
	if !strings.Contains(w.out.String(), "alice-box1") || !strings.Contains(w.out.String(), "tunnel ssh-config") {
		t.Errorf("up --ssh did not point at the ssh_config block:\n%s", w.out)
	}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/ -run 'TestSSHConfig|TestUp' -v`
Expected: FAIL - the block still has a per-tunnel `HostName`, and `--alias-domain` is unknown.

- [ ] **Step 3: Implement**

`sshConfig` takes `--alias-domain` (required; its absence is exit 2 with `usageSSHConfig`), drops `--name`, and prints exactly:

```
Host *.<alias domain>
	ProxyCommand tunnel dial %n
```

`%n` is the name ssh was asked for, before any `HostName` substitution - it is what `dial` reads back.

`up`, in the `--ssh` branch, stops printing `ssh <label>` (there is no per-tunnel `Host` block to run that ProxyCommand) and prints a line naming the label and pointing at `tunnel ssh-config`.

`usage` and `usageSSHConfig`:

```
  tunnel ssh-config --alias-domain DOMAIN          print the ssh_config block for your ssh tunnels
```

README lines 18-20 and 42-44: the ssh example names a tunnel under a `.lan` alias, and the prose no longer says a tunnel serves `<label>.ssh.tunnels.layertwo.dev`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/cli.go internal/cli/cli_test.go README.md
git commit -m "docs(cli): print one ssh_config block for every tunnel"
```

---

### Task 6: `docs/design.md` follows the implementation

**Files:**
- Modify: `docs/design.md:37-39` (names), `:207-211` (the shared domain), `:468-494` (SSH), `:658-660` (the implemented summary)
- Modify: `docs/plans/2026-10-10-tunnels-ssh.md` (the header note)

**Interfaces:**
- Consumes: the code as it now stands; `docs/plans/2026-10-12-tunnels-ssh-one-host-design.md`.

- [ ] **Step 1: Update the names**

Line 38-39 no longer says SSH tunnels are `<handle>[-<name>].ssh.tunnels.layertwo.dev`. State that SSH is published at the one ssh host with the tunnel named in the request path.

- [ ] **Step 2: Update the shared-domain reasoning**

Lines 207-211: `subDomainHost` is still `w.tunnels.layertwo.dev` and SSH is still an `http` proxy, but the SSH subtree is now the single host, told apart by an frp location - no wildcard record, no wildcard certificate.

- [ ] **Step 3: Rewrite the SSH section**

Lines 468-494: `tunnel up PORT --ssh [--target HOST]`, the location, `tunnel dial NAME`, `tunnel ssh-config --alias-domain DOMAIN`, the broker's rule, and the homelab list now needing one host instead of a `*.ssh.` record, wildcard certificate and wildcard router. Keep the "Whether SSH is on is the broker's `[ssh]` section" paragraph as it stands.

The homelab list also gains the one thing this repo cannot verify and that must be checked before the route goes live: that Traefik sends `X-Forwarded-Uri`. If it does not, `/authz` sees no label and denies every SSH request - dark, not broken open - so it is safe to deploy and confirm on the first dial.

- [ ] **Step 4: Update the implemented summary and the old plan**

Lines 658-660: the commands are now `ssh-config --alias-domain DOMAIN` and `dial NAME`. Add to the top of `docs/plans/2026-10-10-tunnels-ssh.md` the same kind of superseded note its "Amended 2026-10-12" block already uses, pointing at the new design.

- [ ] **Step 5: Commit**

```bash
git add docs/design.md docs/plans/2026-10-10-tunnels-ssh.md
git commit -m "docs: ssh is one host, named by the request path"
```
