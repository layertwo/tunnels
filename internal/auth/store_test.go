package auth

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

func entries(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range list {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestStoreFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tunnels") // does not exist yet: Save makes it
	s := Store{Dir: dir}

	if _, err := s.Load(); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("Load before any login: err = %v, want ErrNotLoggedIn", err)
	}
	if !strings.Contains(ErrNotLoggedIn.Error(), "tunnel login") {
		t.Errorf("ErrNotLoggedIn = %q, want it to say what to run", ErrNotLoggedIn)
	}

	want := Tokens{AccessToken: "at-1", RefreshToken: "rt-1", Handle: "alice", Server: "https://tunnels.example"}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	if got := entries(t, dir); !slices.Equal(got, []string{"access-token", "tokens.json"}) {
		t.Errorf("directory holds %v, want exactly access-token and tokens.json", got)
	}
	if runtime.GOOS != "windows" { // Windows has no permission bits to check
		for _, name := range []string{"tokens.json", "access-token"} {
			if m := mode(t, filepath.Join(dir, name)); m != 0o600 {
				t.Errorf("%s has mode %o, want 600", name, m)
			}
		}
		if m := mode(t, dir); m != 0o700 {
			t.Errorf("directory has mode %o, want 700", m)
		}
	}
	if got, err := s.Load(); err != nil || got != want {
		t.Errorf("Load = %+v, %v, want %+v", got, err, want)
	}
	if s.AccessTokenPath() != filepath.Join(dir, "access-token") {
		t.Errorf("AccessTokenPath = %q", s.AccessTokenPath())
	}
	// An upgraded CLI must still read what an older one wrote, or everybody is logged out.
	wantFile := `{"access_token":"at-1","refresh_token":"rt-1","handle":"alice","server":"https://tunnels.example"}`
	if b, _ := os.ReadFile(filepath.Join(dir, "tokens.json")); string(b) != wantFile {
		t.Errorf("tokens.json holds %s, want %s", b, wantFile)
	}
	// frp reads this file as the token: nothing but the token.
	if b, _ := os.ReadFile(s.AccessTokenPath()); string(b) != "at-1" {
		t.Errorf("access-token holds %q, want the token alone", b)
	}

	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if got := entries(t, dir); len(got) != 0 {
		t.Errorf("after Clear the directory holds %v", got)
	}
	if _, err := s.Load(); !errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("Load after Clear: err = %v, want ErrNotLoggedIn", err)
	}
	if err := s.Clear(); err != nil {
		t.Errorf("Clear when logged out: %v", err)
	}
}

// A file that somebody loosened is tight again after the next save: the new file replaces it.
func TestSaveRestoresTheMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no permission bits")
	}
	s := Store{Dir: t.TempDir()}
	if err := s.Save(Tokens{AccessToken: "a", RefreshToken: "r"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tokens.json", "access-token"} {
		if err := os.Chmod(filepath.Join(s.Dir, name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Save(Tokens{AccessToken: "b", RefreshToken: "s"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tokens.json", "access-token"} {
		if m := mode(t, filepath.Join(s.Dir, name)); m != 0o600 {
			t.Errorf("%s has mode %o, want 600", name, m)
		}
	}
}

// Another process reads these files while this one rewrites them; it must never see half a file.
func TestSaveIsAtomic(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	a := Tokens{AccessToken: strings.Repeat("a", 3000), RefreshToken: strings.Repeat("r", 3000), Handle: "alice", Server: "https://s"}
	b := Tokens{AccessToken: strings.Repeat("b", 3000), RefreshToken: strings.Repeat("s", 3000), Handle: "alice", Server: "https://s"}
	if err := s.Save(a); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			t := a
			if i%2 == 1 {
				t = b
			}
			if err := s.Save(t); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 400; i++ {
		got, err := s.Load()
		if err != nil || (got != a && got != b) {
			close(stop)
			wg.Wait()
			t.Fatalf("read %d: Load = %.60q..., %v, want one of the two complete token sets", i, got.AccessToken, err)
		}
		raw, err := os.ReadFile(s.AccessTokenPath())
		if err != nil || (string(raw) != a.AccessToken && string(raw) != b.AccessToken) {
			close(stop)
			wg.Wait()
			t.Fatalf("read %d: access-token = %.60q..., %v, want one of the two complete tokens", i, raw, err)
		}
	}
	close(stop)
	wg.Wait()
	if got := entries(t, s.Dir); !slices.Equal(got, []string{"access-token", "tokens.json"}) {
		t.Errorf("directory holds %v, want no leftovers", got)
	}
}

// A failed write must not leave temp files that hold a token behind.
func TestSaveLeavesNoTempFilesWhenItFails(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if err := os.Mkdir(s.AccessTokenPath(), 0o700); err != nil { // a directory where the file should go
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.AccessTokenPath(), "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(Tokens{AccessToken: "secret-access", RefreshToken: "secret-refresh"}); err == nil {
		t.Fatal("Save succeeded over a directory")
	}
	for _, name := range entries(t, s.Dir) {
		if strings.Contains(name, "tmp") {
			t.Errorf("temp file %q left behind", name)
		}
	}
}

// If the second file cannot be written, the first is already the new one: tokens.json holds the
// refresh token, and the provider has retired the old one by the time Save runs.
func TestSaveWritesTheRefreshTokenFirst(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if err := os.Mkdir(s.AccessTokenPath(), 0o700); err != nil { // the access token cannot be written
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.AccessTokenPath(), "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	want := Tokens{AccessToken: "at", RefreshToken: "rt-new", Handle: "alice", Server: "https://s"}
	if err := s.Save(want); err == nil {
		t.Fatal("Save succeeded although the access token could not be written")
	}
	if got, err := s.Load(); err != nil || got != want {
		t.Errorf("Load = %+v, %v, want the new tokens.json (%+v)", got, err, want)
	}
}

func TestLoadDamagedFile(t *testing.T) {
	for name, content := range map[string]string{"truncated": `{"access_token":"a","refr`, "empty": "", "array": "[]", "not json": "hello"} {
		t.Run(name, func(t *testing.T) {
			s := Store{Dir: t.TempDir()}
			if err := os.WriteFile(filepath.Join(s.Dir, "tokens.json"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := s.Load()
			if err == nil || errors.Is(err, ErrNotLoggedIn) || !strings.Contains(err.Error(), "tunnel login") {
				t.Errorf("Load = %v, want an error that is not ErrNotLoggedIn and says to log in again", err)
			}
		})
	}
}
