// Package ws pumps bytes between a WebSocket connection and a stream.
package ws

import (
	"io"

	"github.com/gorilla/websocket"
)

// Pipe copies bytes both ways until either the WebSocket or the peer ends, then closes both so the
// other goroutine unblocks. It returns the error that ended the pump.
func Pipe(conn *websocket.Conn, peer io.ReadWriteCloser) error {
	done := make(chan error, 2)
	go func() {
		for {
			_, r, err := conn.NextReader()
			if err != nil {
				done <- err
				return
			}
			if _, err := io.Copy(peer, r); err != nil {
				done <- err
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := peer.Read(buf)
			if n > 0 {
				w, werr := conn.NextWriter(websocket.BinaryMessage)
				if werr == nil {
					_, werr = w.Write(buf[:n])
					if werr == nil {
						werr = w.Close()
					}
				}
				if werr != nil {
					done <- werr
					return
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	err := <-done
	_ = conn.Close()
	_ = peer.Close()
	return err
}
