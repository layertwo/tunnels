package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/layertwo/tunnels/internal/ws"
)

// echoServer starts a loopback TCP echo server and returns its port. It stops when the test ends.
func echoServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// startBridge runs a bridge to target:port until the test ends and returns it.
func startBridge(t *testing.T, target string, port int) *bridge {
	t.Helper()
	b, err := newBridge(target, port)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(func() { _ = b.Close() })
	t.Cleanup(cancel)
	go b.Serve(ctx)
	return b
}

func bridgeURL(b *bridge) string { return fmt.Sprintf("ws://127.0.0.1:%d/", b.Port()) }

// TestBridgeEchoes publishes a target that echoes, dials the bridge as frps would and checks bytes
// make the round trip.
func TestBridgeEchoes(t *testing.T) {
	b := startBridge(t, "127.0.0.1", echoServer(t))

	conn, _, err := websocket.DefaultDialer.Dial(bridgeURL(b), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	peer, other := net.Pipe()
	t.Cleanup(func() { _ = other.Close() })
	errc := make(chan error, 1)
	go func() { errc <- ws.Pipe(conn, peer) }()

	got := make(chan string, 1)
	go func() {
		if _, err := other.Write([]byte("ping")); err != nil {
			got <- "write: " + err.Error()
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(other, buf); err != nil {
			got <- "read: " + err.Error()
			return
		}
		got <- string(buf)
	}()

	select {
	case s := <-got:
		if s != "ping" {
			t.Fatalf("echoed %q, want %q", s, "ping")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the echo")
	}

	_ = conn.Close()
	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("Pipe did not return after the connection closed")
	}
}

// TestBridgeClosesWebSocketWhenDialFails upgrades the WebSocket and then fails to dial the target;
// the upgrade must not leave the WebSocket open.
func TestBridgeClosesWebSocketWhenDialFails(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := dead.Addr().(*net.TCPAddr).Port
	_ = dead.Close()

	b := startBridge(t, "127.0.0.1", port)
	conn, _, err := websocket.DefaultDialer.Dial(bridgeURL(b), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("the WebSocket stayed open after the target dial failed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the WebSocket was not closed after the target dial failed; the read timed out")
	}
}

// TestBridgeRejectsNonWebSocket sends a plain request: the upgrade fails and the handler returns a
// bad request rather than dialing the target.
func TestBridgeRejectsNonWebSocket(t *testing.T) {
	b := startBridge(t, "127.0.0.1", 1)
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", b.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: a plain request is not a WebSocket upgrade", resp.StatusCode)
	}
}

// TestBridgeStopsWithContext ends the context: Serve returns and the bridge refuses new dials.
func TestBridgeStopsWithContext(t *testing.T) {
	b, err := newBridge("127.0.0.1", 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan struct{})
	go func() {
		b.Serve(ctx)
		close(served)
	}()

	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after its context ended")
	}
	if conn, _, err := websocket.DefaultDialer.Dial(bridgeURL(b), nil); err == nil {
		_ = conn.Close()
		t.Fatal("dialed the bridge after it stopped")
	}
}
