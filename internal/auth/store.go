// Package auth is how the CLI proves who it is: the bootstrap document that says where to log in, the
// device flow, the token files and their refresh.
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Tokens are what a login leaves on disk. Handle and Server are what the service told the CLI at
// login: the name it publishes under and the address it logged in at.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Handle       string `json:"handle"`
	Server       string `json:"server"`
}

// ErrNotLoggedIn is what Load says when nobody has logged in here.
var ErrNotLoggedIn = errors.New("not logged in; run: tunnel login")

// Store keeps the tokens in two files of Dir, both readable by the owner only: tokens.json holds
// everything, access-token holds the access token alone because that is what the frp client reads.
type Store struct{ Dir string }

func (s Store) tokensPath() string { return filepath.Join(s.Dir, "tokens.json") }

// AccessTokenPath is the file the frp client reads its token from.
func (s Store) AccessTokenPath() string { return filepath.Join(s.Dir, "access-token") }

// Load returns the stored tokens, or ErrNotLoggedIn.
func (s Store) Load() (Tokens, error) {
	raw, err := os.ReadFile(s.tokensPath())
	if errors.Is(err, fs.ErrNotExist) {
		return Tokens{}, ErrNotLoggedIn
	}
	if err != nil {
		return Tokens{}, fmt.Errorf("auth: read %s: %w", s.tokensPath(), err)
	}
	var t Tokens
	if err := json.Unmarshal(raw, &t); err != nil {
		return Tokens{}, fmt.Errorf("auth: %s is damaged (%v); run: tunnel login", s.tokensPath(), err)
	}
	return t, nil
}

// Save replaces both files, tokens.json first: it holds the refresh token, which is the one that
// cannot be had again if a crash lands between the two.
func (s Store) Save(t Tokens) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	raw, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if err := writeFileAtomic(s.tokensPath(), raw); err != nil {
		return fmt.Errorf("auth: save tokens: %w", err)
	}
	if err := writeFileAtomic(s.AccessTokenPath(), []byte(t.AccessToken)); err != nil {
		return fmt.Errorf("auth: save access token: %w", err)
	}
	return nil
}

// Clear removes both files. Nothing to remove is not an error.
func (s Store) Clear() error {
	for _, path := range []string{s.tokensPath(), s.AccessTokenPath()} {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("auth: %w", err)
		}
	}
	return nil
}

// writeFileAtomic puts data at path with mode 0600 so that a reader sees the old file or the new one,
// never part of it: a temporary file in the same directory, flushed, then renamed over the target.
func writeFileAtomic(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
