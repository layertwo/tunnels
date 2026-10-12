package tunnel

import (
	"context"
	"net"
	"net/http"
	"strconv"

	"github.com/fatedier/frp/pkg/util/log"
	"github.com/gorilla/websocket"

	"github.com/layertwo/tunnels/internal/ws"
)

// bridge is the loopback WebSocket server that fronts an SSH target. frps forwards the ssh host's
// bytes there (an ordinary http proxy), and every accepted connection is pumped to a fresh dial of
// the target.
type bridge struct {
	target  string
	sshPort int
	port    int
	ln      net.Listener
	http    *http.Server
}

// newBridge listens on a random loopback port and returns a bridge that dials target:port.
func newBridge(target string, port int) (*bridge, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err // coverage-ignore: a loopback listen on an ephemeral port cannot fail
	}
	b := &bridge{target: target, sshPort: port, port: ln.Addr().(*net.TCPAddr).Port, ln: ln}
	b.http = &http.Server{Handler: http.HandlerFunc(b.serve)}
	return b, nil
}

func (b *bridge) Port() int { return b.port }

// Serve serves the bridge until ctx ends or Close is called. AfterFunc runs no goroutine until the
// context ends, so a bridge closed by hand leaves none behind.
func (b *bridge) Serve(ctx context.Context) {
	_ = context.AfterFunc(ctx, func() { _ = b.Close() })
	_ = b.http.Serve(b.ln) // returns once Close closes the listener
}

func (b *bridge) Close() error { return b.http.Close() }

// serve upgrades one connection and pumps it to a new dial of the target.
func (b *bridge) serve(w http.ResponseWriter, r *http.Request) {
	conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
	if err != nil {
		return
	}
	addr := net.JoinHostPort(b.target, strconv.Itoa(b.sshPort))
	peer, err := net.Dial("tcp", addr)
	if err != nil {
		log.Warnf("tunnel: the ssh bridge cannot dial %s: %v", addr, err)
		_ = conn.Close() // a failed dial must not leak the upgraded WebSocket
		return
	}
	_ = ws.Pipe(conn, peer)
}
