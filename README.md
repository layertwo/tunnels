# tunnels

A multi-user tunnel service, in the spirit of ngrok, built on [frp](https://github.com/fatedier/frp).
People publish an HTTP service from their own machine at `https://<handle>[-<name>].w.tunnels.layertwo.dev`,
visitors sign in with Pocket ID, and owners share a tunnel with other users or groups.

Work in progress: [the Phase 1 plan](docs/plans/2026-10-09-phase1-broker-cli.md) is being implemented, and
`cmd/` appears with the first binary.

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

## Test

```sh
go test ./...
```

CI runs `go test -race ./...`, `go vet ./...`, `gofmt -l .` and `govulncheck`.

## Docs

- [Design](docs/design.md)
- [Plans](docs/plans/)
