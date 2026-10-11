---
name: Releasing tunnels
description: Use when cutting a tunnels release (pushing a v* tag), writing or revising a release's notes, or activating a release in the homelab — preconditions, the tag-driven workflows, verifying the artifacts, and the deploy order.
---

# Releasing tunnels

The release is **tag-driven**: pushing a `v*` tag runs `release.yml` (goreleaser: CLI archives for
darwin/linux/windows + `checksums.txt` + build provenance) and `image.yml` (the `tunnels-broker` and
`tunnels-frps` images). Only the human merges PRs and pushes tags.

## Preconditions

- The work is on `mainline`. **Check `mainline` CI is green on the exact commit you tag**, not just the
  PR: `gh run list --branch mainline`.
- A red `ci` whose e2e job says `toomanyrequests: Data limit exceeded` is **Docker Hub throttling**,
  not your code — re-run it: `gh run rerun <run-id> --failed`.
- Confirm what you are releasing: `git log --oneline <previous-tag>..origin/mainline`.

## Tag

```sh
git tag -a vX.Y.Z -m vX.Y.Z origin/mainline && git push origin vX.Y.Z
```

Never move a published tag. A fix to an already-released line is a **patch** (`vX.Y.Z` + 1).

## Release notes

goreleaser publishes a raw commit changelog; replace it: `gh release edit vX.Y.Z --notes-file <file>`.

**Write the net diff since the previous tag — not the back-and-forth between unreleased commits.**
Feature work often lands, is replaced, and lands again all on `mainline` before a tag; the notes must
describe what a user on the previous release sees. Determine that from the previous tag itself:

```sh
git show <previous-tag>:internal/cli/cli.go     # the CLI flags and usage text then
git show <previous-tag>:internal/broker/config.go   # the env vars then
```

Call a feature **new** only if the previous tag lacked it; drop anything that existed only between
unreleased commits (client secret paths, renamed internal models, tests added for behavior that already
worked). Cover: new features · changed or breaking CLI/env (a `--flag` → positional change is
breaking) · security · the deploy steps to activate it.

## Verify the release

- Assets: `gh release view vX.Y.Z --json assets` — the archives and `checksums.txt`. Check one with
  `gh attestation verify <archive> -R layertwo/tunnels` and its line in `checksums.txt`.
- Images: the packages are **public** and signed by digest with **cosign (keyless)** — the release notes
  say so. Get the digest the tag points at:
  `podman manifest inspect ghcr.io/layertwo/tunnels-broker:vX.Y.Z` (or grep the `image` workflow log for
  `:vX.Y.Z@sha256:`), **pin that digest**, and confirm the signature:

  ```sh
  cosign verify ghcr.io/layertwo/tunnels-broker@sha256:<digest> \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp 'https://github.com/layertwo/tunnels/.github/workflows/image.yml@.*'
  ```

## Activate it in the homelab

Work in `/Users/lucas/homelab`, branch `chore/tunnels-vX.Y.Z` off `origin/mainline`. Flux reconciles on
merge; only the human merges.

- Pin the broker **and** frps image `tag:` to `vX.Y.Z@sha256:<digest>`.
- **Order matters.** The broker image must be pinned **before** `"NewWorkConn"` is added to frps's
  plugin `ops`. With an older broker, frps calls an operation the plugin rejects, and **every visitor
  request fails**. Enable it in the same PR as the pin so the change is atomic.
- **A release must not require new configuration to keep running** (see `AGENTS.md`). If a release
  makes an existing option `required`, the running broker will not start after the pin bump — fix it
  with a patch first, then deploy.
- `/metrics` needs a scrape and a NetworkPolicy entry only where a Prometheus actually exists; do not
  open ingress to a scraper that isn't deployed.
- After merge: `flux reconcile source git flux-system`, then `kubectl -n tunnels rollout status` and
  confirm the broker started. The human's deploy checklist lives in `docs/design.md`.

## Common mistakes

- Tagging while `mainline` CI is red (often only the Docker Hub flake).
- Enabling `NewWorkConn` before the broker that implements it.
- Writing notes as a changelog of unreleased churn, or claiming a "change" that the previous tag
  already did.
- Deploying a release that adds a required env var instead of making the option optional.
