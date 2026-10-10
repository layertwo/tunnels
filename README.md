# tunnels

A multi-user tunnel service, in the spirit of ngrok, built on [frp](https://github.com/fatedier/frp).
People publish an HTTP service from their own machine at `https://<handle>[-<name>].w.tunnels.layertwo.dev`,
visitors sign in with Pocket ID, and owners share a tunnel with other users or groups.

Work in progress: [the Phase 1 plan](docs/plans/2026-10-09-phase1-broker-cli.md) is being implemented.

## Layout

One Go module and one repository for everything this project ships:

- `cmd/<name>/`: one directory per binary. The broker (the frps plugin, the access decisions behind
  `/authz`, the API) is `cmd/broker`; the CLI, which embeds the frp client library, is `cmd/tunnel`.
- `internal/`: code the binaries share. `internal/names` holds the handle, tunnel name and site label rules.
- `Dockerfile.<component>`: one per container image (`Dockerfile.broker`, `Dockerfile.frps`), built from
  prebuilt binaries.
- `.github/workflows/`: `ci.yml` checks the whole module; image and release workflows run only for the
  paths they build.
- Releases: one `vX.Y.Z` tag releases the CLI archives and tags the images together. Component-prefixed
  tags wait until a component needs its own cadence.
- Cluster manifests live in [`layertwo/homelab`](https://github.com/layertwo/homelab), not here.

## Build

```sh
go build -o broker ./cmd/broker   # settings are environment variables, see internal/broker/config.go
go build -o tunnel ./cmd/tunnel   # the CLI: tunnel login, then tunnel up PORT [--name NAME]
```

## Verify a release

Every archive of a release comes with a signed build provenance. It says which workflow built
the archive from which commit of this repository:

```sh
gh attestation verify tunnel_0.1.0_darwin_arm64.tar.gz --repo layertwo/tunnels
```

The images are signed by digest with cosign (keyless, from the `image` workflow):

```sh
cosign verify ghcr.io/layertwo/tunnels-broker:latest \
  --certificate-identity-regexp '^https://github.com/layertwo/tunnels/\.github/workflows/image\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Test

```sh
go test ./...
```

CI runs `go test -race ./...`, `go vet ./...`, `gofmt -l .` and `govulncheck`.

## Docs

- [Design](docs/design.md)
- [Plans](docs/plans/)
