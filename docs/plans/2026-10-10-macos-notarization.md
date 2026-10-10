# Tunnels macOS Signing and Notarization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the darwin `tunnel` release binaries pass Gatekeeper: signed with a Developer ID and notarized by Apple, so a browser download opens without the "unidentified developer" warning.

**Architecture:** Sign and notarize the darwin binaries inside the existing `release` job using GoReleaser's cross-platform `notarize.macos` (anchore/quill). This needs no macOS runner and no GoReleaser Pro. The step is gated on the signing secret being present, so snapshot builds and PR checks (which have no secrets) produce the same seven archives as today. The archive holds the signed binary because GoReleaser signs the binary before it packs.

**Tech Stack:** GoReleaser v2.18.3 (`notarize.macos`, cross-platform via anchore/quill), a Developer ID Application certificate (`.p12`), an App Store Connect API key (`.p8`), GitHub Actions repo secrets.

**Spec:** `docs/design.md` — the CLI Distribution bullet ("Binaries fetched with curl avoid macOS quarantine; one downloaded in a browser will show the unsigned-binary warning") and the supply-chain controls.

**Series:** this is a small plan between phase 1 (`docs/plans/2026-10-09-phase1-broker-cli.md`) and plan 4 (hardening and `/install.sh`). It changes the release job and the docs only.

## Decisions that amend the spec

1. **Cross-platform notarization, not native.** `notarize.macos` runs on the existing `ubuntu-latest` runner via anchore/quill. `notarize.macos_native` is GoReleaser Pro and needs `codesign`/`xcrun` on macOS; it is not used.
2. **The step is gated on the secret, not the tag.** `enabled: '{{ isEnvSet "MACOS_SIGN_P12" }}'` so `release-check` in `ci.yml` (no secrets) and local snapshots still build all seven archives.
3. **Signing is a release-only concern.** Source builds stay unsigned; the README tells anyone hitting the warning how to clear it.

## Prerequisites (human partner, outside the repo)

These exist before Task 1's signed path can be verified; Task 1's code can land with the step gated off.

- Apple Developer Program membership ($99/year).
- A **Developer ID Application** certificate from that account, exported as `Certificates.p12` with a password.
- An App Store Connect **API key** (`.p8`) with its Key ID and Issuer ID.
- Repo secrets, the two files base64-encoded: `MACOS_SIGN_P12`, `MACOS_SIGN_PASSWORD`, `MACOS_NOTARY_ISSUER_ID`, `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_KEY`.

## Global Constraints

Every task's requirements include this section.

- Module `github.com/layertwo/tunnels`, default branch `mainline`. Commits `build(scope): ...` for Task 1 and `docs(scope): ...` for Task 2; work lands through pull requests the human partner reviews and merges.
- CLI release targets, archives and checksums do not change: seven archives (`darwin/amd64`, `darwin/arm64`, `linux/amd64`, `linux/arm64`, `linux/armv7`, `windows/amd64`, `windows/arm64`) plus `checksums.txt`. The `release-check` invariant in `.github/workflows/ci.yml` (exactly seven) must still hold.
- Runner stays `ubuntu-latest`; GoReleaser stays v2.18.3, pinned action digests unchanged.
- Only the darwin binaries are signed and notarized. Linux and windows artifacts are untouched.
- No certificate, key, password or base64 blob is ever committed; they live only in repo secrets. The gating template means a missing secret disables notarization rather than failing the build.
- The build ID and the `notarize.macos.ids` filter name the same value (`tunnel`) so the step signs the right binaries.

## Review Focus

1. A build with no signing secret (every `release-check` run, every PR, local snapshot) still produces exactly seven archives and does not error (Task 1).
2. The notarized binary is the one inside the published archive, not a copy made after packing: extracting `tunnel_<version>_darwin_arm64.tar.gz` and running `codesign`/`spctl` shows the Developer ID signature (Task 1).
3. A quarantined browser download of a **new** release opens without the `xattr` workaround, while an **old** release and a source build still warn — and the README says so (Task 2).
4. Signing and notarization never touch the linux/windows artifacts, and the `checksums.txt` still covers the archives it always did (Task 1).

## File Structure

- `.goreleaser.yaml` — add the build ID and the `notarize.macos` block (sign + notarize, gated on the secret).
- `.github/workflows/release.yml` — pass the five signing secrets into the GoReleaser step.
- `README.md` — say releases are signed and notarized, and give the `xattr` fallback for anything still quarantined.
- `docs/design.md` — replace the "unsigned-binary warning" sentence with the new behavior.

---

### Task 1: Sign and notarize the darwin binaries

**Files:**
- Modify: `.goreleaser.yaml`
- Modify: `.github/workflows/release.yml:25-30`
- Test: none (config); verified by `goreleaser` and a tagged pre-release

**Interfaces:**
- Consumes: the five repo secrets named in Prerequisites.
- Produces: notarized darwin binaries; no later task reads anything from here.

- [ ] **Step 1: Give the build a stable ID and add the notarize block.** In `.goreleaser.yaml`, add `id: tunnel` as the first key of the build, then add this top-level block (GoReleaser v2.18.3 syntax; cross-platform sign + notarize):

  ```yaml
  notarize:
    macos:
      - enabled: '{{ isEnvSet "MACOS_SIGN_P12" }}'
        ids: [tunnel]
        sign:
          certificate: "{{ .Env.MACOS_SIGN_P12 }}"
          password: "{{ .Env.MACOS_SIGN_PASSWORD }}"
        notarize:
          issuer_id: "{{ .Env.MACOS_NOTARY_ISSUER_ID }}"
          key_id: "{{ .Env.MACOS_NOTARY_KEY_ID }}"
          key: "{{ .Env.MACOS_NOTARY_KEY }}"
          wait: true
  ```

  The `certificate` and `key` values accept the base64 contents, which is what the secrets hold. `wait: true` makes the release fail if Apple rejects; notarization is quick for binaries and the default `timeout` is 10m.

- [ ] **Step 2: Pass the secrets to the release step.** In `.github/workflows/release.yml`, extend the `env:` of the `goreleaser/goreleaser-action` step:

  ```yaml
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          MACOS_SIGN_P12: ${{ secrets.MACOS_SIGN_P12 }}
          MACOS_SIGN_PASSWORD: ${{ secrets.MACOS_SIGN_PASSWORD }}
          MACOS_NOTARY_ISSUER_ID: ${{ secrets.MACOS_NOTARY_ISSUER_ID }}
          MACOS_NOTARY_KEY_ID: ${{ secrets.MACOS_NOTARY_KEY_ID }}
          MACOS_NOTARY_KEY: ${{ secrets.MACOS_NOTARY_KEY }}
  ```

  Add one comment above the block naming the required secrets, so a future reader knows what to set. Do not add these env vars to `ci.yml`; the gating template keeps notarization off there.

- [ ] **Step 3: Verify the no-secret path is unchanged.** Locally (or by the PR's `release-check` job):

  ```sh
  goreleaser check
  goreleaser release --snapshot --clean --skip=publish
  ls dist/*.tar.gz dist/*.zip | wc -l   # expect 7
  test -s dist/checksums.txt
  ```

  Expected: `check` passes, seven archives, `checksums.txt` non-empty. The notarize step reports itself disabled because `MACOS_SIGN_P12` is unset.

- [ ] **Step 4: Verify the signed path (needs the secrets).** With the secrets set, tag a throwaway pre-release (`v0.0.0-rc.1`), let `release` run, then on a Mac:

  ```sh
  gh release download v0.0.0-rc.1 -p 'tunnel_0.0.0-rc.1_darwin_arm64.tar.gz'
  tar xzf tunnel_0.0.0-rc.1_darwin_arm64.tar.gz
  codesign -dv --verbose=4 ./tunnel 2>&1 | grep 'Developer ID Application'
  spctl -a -t execute -vv ./tunnel   # expect "accepted"; source names Notarized Developer ID
  ```

  Expected: a Developer ID signature and an accepted assessment. The final proof is downloading the same asset in Safari and opening `./tunnel` with no Gatekeeper dialog (a ticket alone does not set the quarantine attribute that Finder checks). Then delete the pre-release and its tag.

- [ ] **Step 5: Commit.**

  ```bash
  git add .goreleaser.yaml .github/workflows/release.yml
  git commit -m "build(release): sign and notarize the darwin binaries"
  ```

---

### Task 2: Tell users how to run a build Gatekeeper still blocks

**Files:**
- Modify: `README.md` (Use / Verify a release)
- Modify: `docs/design.md:386-387`

**Interfaces:**
- Consumes: Task 1's behavior (new releases open normally).
- Produces: nothing code reads.

- [ ] **Step 1: README.** In the Use section, one sentence: releases are signed with a Developer ID and notarized by Apple, so they open normally. In Verify a release, one line: a build from source, or a release predating signing, downloaded in a browser still shows the unidentified-developer warning; clear it with `xattr -dr com.apple.quarantine ./tunnel` (or Finder → right-click → Open → Open). Keep it to those two spots; do not add a new section.

- [ ] **Step 2: design.md.** Replace the Distribution sentence

  > Binaries fetched with curl avoid macOS quarantine; one downloaded in a browser will show the unsigned-binary warning.

  with: darwin binaries are Developer ID-signed and notarized by Apple in the release job (cross-platform via anchore/quill, no macOS runner); curl-fetched and browser-fetched copies both open. Source builds stay unsigned and may need the quarantine cleared.

- [ ] **Step 3: Commit.**

  ```bash
  git add README.md docs/design.md
  git commit -m "docs: releases are signed and notarized on macOS"
  ```

---

## Not in this plan

The `/install.sh` script (plan 4) will curl the archive, which already avoids quarantine; it does not need to do anything for signing. Windows SmartScreen and Linux distribution are untouched. No Homebrew cask or `.pkg`/`.dmg` packaging is added — `notarize.macos` covers standalone binaries only, which is all this project ships.
