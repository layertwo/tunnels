# tunnels

A multi-user tunnel service, in the spirit of ngrok, built on [frp](https://github.com/fatedier/frp).
People publish an HTTP service from their own machine at `https://<handle>[-<name>].w.tunnels.layertwo.dev`,
visitors sign in with Pocket ID, and owners share a tunnel with other users or groups.

Two Go programs plus the rules they share:

- `cmd/broker`: the frps plugin, the access decisions behind `/authz`, and the API.
- `cmd/tunnel`: the CLI, which embeds the frp client library.
- `internal/names`: handle, tunnel name and site label rules.

## Test

```sh
go test ./...
```

CI runs `go test -race ./...`, `go vet ./...`, `gofmt -l .` and `govulncheck`.

## Build

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=dev" -o dist/broker ./cmd/broker
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=dev -X main.defaultServer=tunnels.layertwo.dev" -o dist/tunnel ./cmd/tunnel
```

The two programs arrive with the phase 1 plan; until then only `internal/` builds.

## Docs

- [Design](docs/design.md)
- [Plans](docs/plans/)
