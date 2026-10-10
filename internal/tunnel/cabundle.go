package tunnel

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/x509roots/fallback/bundle"

	"github.com/layertwo/tunnels/internal/auth"
)

// WriteCABundle writes the Mozilla root certificates (golang.org/x/crypto/x509roots) to dir/cacert.pem,
// the file frp checks the server's certificate against, and returns its path. An identical file is
// left alone.
func WriteCABundle(dir string) (string, error) {
	var b bytes.Buffer
	for r := range bundle.Roots() {
		// A root that is trusted only for certificates issued before a date cannot keep that rule in
		// a PEM file, so it is left out rather than trusted for everything.
		if r.Constraint != nil {
			continue
		}
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: r.Certificate}) // a bytes.Buffer does not fail
	}
	path := filepath.Join(dir, "cacert.pem")
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, b.Bytes()) {
		return path, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("tunnel: %w", err)
	}
	if err := auth.WriteFileAtomic(path, b.Bytes()); err != nil {
		return "", fmt.Errorf("tunnel: write the CA bundle: %w", err)
	}
	return path, nil
}
