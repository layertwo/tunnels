package ws

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// serve runs handle on an upgraded connection. handle blocks for as long as its pump runs.
func serve(t *testing.T, handle func(*websocket.Conn)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		handle(conn)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dial(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// assertReturns waits for Pipe to return and requires a non-nil error.
func assertReturns(t *testing.T, errc <-chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Pipe returned nil, want an error")
		}
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Pipe did not return")
		return nil
	}
}

// fakePeer is a peer whose Read blocks until Close; Write fails only when write is set.
type fakePeer struct {
	write  func([]byte) (int, error)
	closed chan struct{}
	once   sync.Once
}

func newFakePeer() *fakePeer { return &fakePeer{closed: make(chan struct{})} }

func (p *fakePeer) Read([]byte) (int, error) {
	<-p.closed
	return 0, io.EOF
}

func (p *fakePeer) Write(b []byte) (int, error) {
	if p.write != nil {
		return p.write(b)
	}
	return len(b), nil
}

func (p *fakePeer) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func TestPipeEchoes(t *testing.T) {
	srv := serve(t, func(conn *websocket.Conn) {
		peer, echo := net.Pipe()
		go func() { _, _ = io.Copy(echo, echo) }()
		_ = Pipe(conn, peer)
	})
	conn := dial(t, srv)

	peer, other := net.Pipe()
	t.Cleanup(func() { _ = other.Close() })
	errc := make(chan error, 1)
	go func() { errc <- Pipe(conn, peer) }()

	got := make(chan string, 1)
	go func() {
		if _, err := other.Write([]byte("hello\n")); err != nil {
			got <- "write: " + err.Error()
			return
		}
		buf := make([]byte, 64)
		n, err := other.Read(buf)
		if err != nil {
			got <- "read: " + err.Error()
			return
		}
		got <- string(buf[:n])
	}()

	select {
	case s := <-got:
		if s != "hello\n" {
			t.Fatalf("echoed %q, want %q", s, "hello\n")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the echo")
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	assertReturns(t, errc)
}

func TestPipeClosesPeer(t *testing.T) {
	peer := newFakePeer()
	errc := make(chan error, 1)
	srv := serve(t, func(conn *websocket.Conn) { errc <- Pipe(conn, peer) })
	conn := dial(t, srv)

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	assertReturns(t, errc)

	select {
	case <-peer.closed:
	default:
		t.Fatal("Pipe returned without closing the peer")
	}
}

// TestPipeWriteError drives a failing write to the WebSocket: a write deadline in the past makes
// the pump's write fail, which must end Pipe and close the peer.
func TestPipeWriteError(t *testing.T) {
	others := make(chan net.Conn, 1)
	errc := make(chan error, 1)
	srv := serve(t, func(conn *websocket.Conn) {
		// A write deadline in the past, set before the pump starts, is applied by gorilla's write
		// and makes the pump's write to the socket fail.
		_ = conn.SetWriteDeadline(time.Now().Add(-time.Second))
		peer, other := net.Pipe()
		others <- other
		errc <- Pipe(conn, peer)
	})
	_ = dial(t, srv)

	other := <-others
	t.Cleanup(func() { _ = other.Close() })
	go func() { _, _ = other.Write([]byte("x")) }()
	assertReturns(t, errc)
}

var errWrite = errors.New("peer write failed")

func TestPipePeerWriteError(t *testing.T) {
	peer := newFakePeer()
	peer.write = func([]byte) (int, error) { return 0, errWrite }
	errc := make(chan error, 1)
	srv := serve(t, func(conn *websocket.Conn) { errc <- Pipe(conn, peer) })
	conn := dial(t, srv)

	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := assertReturns(t, errc); !errors.Is(err, errWrite) {
		t.Fatalf("Pipe returned %v, want %v", err, errWrite)
	}
}
