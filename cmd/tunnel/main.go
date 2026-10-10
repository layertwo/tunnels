// Command tunnel publishes a local web server at https://<handle>[-<name>].<sites domain>.
package main

import (
	"os"

	"github.com/layertwo/tunnels/internal/cli"
)

// Both are set at build time: -ldflags "-X main.version=v1.2.3 -X main.defaultServer=tunnels.layertwo.dev".
var (
	version       = "dev"
	defaultServer = "tunnels.layertwo.dev"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], cli.Env{Stdout: os.Stdout, Stderr: os.Stderr, DefaultServer: defaultServer, Version: version}))
}
