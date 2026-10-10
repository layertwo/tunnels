package store

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// testCtx bounds a test at 30 s so a deadlock (a lost advisory lock, say) fails instead of hanging.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// run executes one statement on a short-lived connection of its own.
func run(dbURL, sql string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, sql)
	return err
}

// count returns the single integer a query selects, on a short-lived connection of its own.
func count(t *testing.T, dbURL, query string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)
	var n int
	if err := conn.QueryRow(ctx, query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// schemaURL creates the private schema t_<random hex> on the server TEST_DATABASE_URL names, drops it
// when the test ends, and returns the URL with search_path pointing at it. It skips the test when
// TEST_DATABASE_URL is unset.
func schemaURL(t *testing.T) string {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	schema := fmt.Sprintf("t_%016x", rand.Uint64())
	if err := run(base, "create schema "+schema); err != nil {
		t.Fatalf("create schema %s: %v", schema, err)
	}
	t.Cleanup(func() {
		if err := run(base, "drop schema "+schema+" cascade"); err != nil {
			t.Errorf("drop schema %s: %v", schema, err)
		}
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema) // pgx hands unknown URL parameters to the server as runtime parameters
	u.RawQuery = q.Encode()
	return u.String()
}

// openStore opens a store on dbURL and closes it when the test ends.
func openStore(t *testing.T, dbURL string) *Store {
	t.Helper()
	s, err := Open(testCtx(t), dbURL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// newStore opens a store on a schema of its own.
func newStore(t *testing.T) *Store {
	t.Helper()
	return openStore(t, schemaURL(t))
}

// parallel runs f(0..n-1) in n goroutines that start together, and waits for all of them.
func parallel(n int, f func(i int)) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Go(func() {
			<-start
			f(i)
		})
	}
	close(start)
	wg.Wait()
}

// migrationFiles lists the migration files on disk, in name order.
func migrationFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("migrations/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("migration files = %v, err = %v", files, err)
	}
	return files
}

func TestOpenIsIdempotent(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	if _, err := s.CreateUser(testCtx(t), "sub-1", "alice"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	openStore(t, dbURL) // the first Open recorded its migrations, so this one must not run them again

	files := migrationFiles(t)
	if got := count(t, dbURL, "select count(*) from schema_migrations"); got != len(files) {
		t.Errorf("schema_migrations has %d rows, want one per file (%d)", got, len(files))
	}
	if got := count(t, dbURL, "select count(*) from schema_migrations where version = 1"); got != 1 {
		t.Errorf("schema_migrations has %d rows for version 1, want 1", got)
	}
	if got := count(t, dbURL, "select count(*) from users"); got != 1 {
		t.Errorf("users has %d rows after the second Open, want 1", got)
	}
}

func TestOpenConcurrently(t *testing.T) {
	// Without the advisory lock the Opens collide only some of the time, so try many fresh schemas.
	for round := range 15 {
		t.Run(fmt.Sprintf("round %d", round), func(t *testing.T) {
			dbURL := schemaURL(t)
			ctx := testCtx(t)
			const n = 5
			stores := make([]*Store, n)
			errs := make([]error, n)
			parallel(n, func(i int) { stores[i], errs[i] = Open(ctx, dbURL) })
			for i := range n {
				if errs[i] != nil {
					t.Errorf("Open #%d: %v", i, errs[i])
					continue
				}
				t.Cleanup(stores[i].Close)
			}
			if got, want := count(t, dbURL, "select count(*) from schema_migrations"), len(migrationFiles(t)); got != want {
				t.Errorf("schema_migrations has %d rows, want one per file (%d)", got, want)
			}
		})
	}
}

func TestCreateUserAndLookups(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	created, err := s.CreateUser(ctx, "sub-1", "alice")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created.Sub != "sub-1" || created.Handle != "alice" || created.Disabled {
		t.Errorf("CreateUser = %+v, want sub-1, alice, not disabled", created)
	}

	tests := []struct {
		name string
		find func(context.Context, string) (User, error)
		key  string
	}{
		{"UserBySub", s.UserBySub, "sub-1"},
		{"UserByHandle", s.UserByHandle, "alice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.find(ctx, tt.key)
			if err != nil {
				t.Fatalf("%s(%q): %v", tt.name, tt.key, err)
			}
			if got != created {
				t.Errorf("%s(%q) = %+v, want %+v", tt.name, tt.key, got, created)
			}
		})
	}
}

func TestCreateUserIsIdempotentPerSub(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	first, err := s.CreateUser(ctx, "sub-1", "alice")
	if err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	second, err := s.CreateUser(ctx, "sub-1", "bob") // the same person comes back under another name
	if err != nil {
		t.Fatalf("second CreateUser: %v", err)
	}
	if second != first {
		t.Errorf("second CreateUser = %+v, want the first row %+v", second, first)
	}
	if _, err := s.UserByHandle(ctx, "bob"); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserByHandle(bob) error = %v, want ErrNotFound", err)
	}
}

func TestHandleTaken(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	if _, err := s.CreateUser(ctx, "sub-a", "alice"); err != nil {
		t.Fatalf("CreateUser(sub-a): %v", err)
	}
	if _, err := s.CreateUser(ctx, "sub-b", "alice"); !errors.Is(err, ErrHandleTaken) {
		t.Fatalf("CreateUser(sub-b, alice) error = %v, want ErrHandleTaken", err)
	}
	if _, err := s.UserBySub(ctx, "sub-b"); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserBySub(sub-b) error = %v, want ErrNotFound", err)
	}
	if got := count(t, dbURL, "select count(*) from users"); got != 1 {
		t.Errorf("users has %d rows, want 1", got)
	}
	owner, err := s.UserByHandle(ctx, "alice")
	if err != nil || owner.Sub != "sub-a" {
		t.Errorf("UserByHandle(alice) = %+v, %v, want sub-a", owner, err)
	}
}

func TestConcurrentFirstLogins(t *testing.T) {
	const n = 20

	t.Run("same sub and handle", func(t *testing.T) {
		dbURL := schemaURL(t)
		s := openStore(t, dbURL)
		ctx := testCtx(t)
		// Many rounds on fresh pairs: the first round only warms the pool, and warm connections overlap
		// closely enough that the handle index reports a duplicate before the sub check does (about one
		// round in four on a laptop). That must not count as a conflict.
		const rounds = 30
		for r := range rounds {
			sub, handle := fmt.Sprintf("sub-%d", r), fmt.Sprintf("handle-%d", r)
			users := make([]User, n)
			errs := make([]error, n)
			parallel(n, func(i int) { users[i], errs[i] = s.CreateUser(ctx, sub, handle) })
			for i := range n {
				if errs[i] != nil {
					t.Errorf("round %d: CreateUser #%d: %v", r, i, errs[i])
				} else if users[i] != users[0] {
					t.Errorf("round %d: CreateUser #%d = %+v, want %+v", r, i, users[i], users[0])
				}
			}
		}
		if got := count(t, dbURL, "select count(*) from users"); got != rounds {
			t.Errorf("users has %d rows, want one per round (%d)", got, rounds)
		}
	})

	t.Run("different subs, one handle", func(t *testing.T) {
		dbURL := schemaURL(t)
		s := openStore(t, dbURL)
		ctx := testCtx(t)
		users := make([]User, n)
		errs := make([]error, n)
		parallel(n, func(i int) { users[i], errs[i] = s.CreateUser(ctx, fmt.Sprintf("sub-%d", i), "alice") })
		winner, taken := -1, 0
		for i := range n {
			switch {
			case errs[i] == nil && winner < 0:
				winner = i
			case errs[i] == nil:
				t.Errorf("CreateUser #%d and #%d both won the handle", winner, i)
			case errors.Is(errs[i], ErrHandleTaken):
				taken++
			default:
				t.Errorf("CreateUser #%d: unexpected error %v", i, errs[i])
			}
		}
		if winner < 0 || taken != n-1 {
			t.Fatalf("winner = %d, taken = %d, want exactly one winner and %d ErrHandleTaken", winner, taken, n-1)
		}
		owner, err := s.UserByHandle(ctx, "alice")
		if err != nil || owner.Sub != users[winner].Sub {
			t.Errorf("UserByHandle(alice) = %+v, %v, want the winner %+v", owner, err, users[winner])
		}
		if got := count(t, dbURL, "select count(*) from users"); got != 1 {
			t.Errorf("users has %d rows, want 1", got)
		}
	})
}

func TestNotFound(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	tests := []struct {
		name string
		find func(context.Context, string) (User, error)
	}{
		{"UserBySub", s.UserBySub},
		{"UserByHandle", s.UserByHandle},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/missing", func(t *testing.T) {
			if _, err := tt.find(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
				t.Errorf("error = %v, want ErrNotFound", err)
			}
		})
		t.Run(tt.name+"/failure is not a miss", func(t *testing.T) {
			// a caller that reads ErrNotFound as "first login" would create a user while the database is down
			if _, err := tt.find(cancelled, "nobody"); err == nil || errors.Is(err, ErrNotFound) {
				t.Errorf("error = %v, want a failure that is not ErrNotFound", err)
			}
		})
	}
}

func TestMigrationVersion(t *testing.T) {
	tests := []struct {
		name string
		want int
		ok   bool
	}{
		{"001_users.sql", 1, true},
		{"010_sharing.sql", 10, true},
		{"2.sql", 2, true},
		{"3_a.b.sql", 3, true},
		{"users.sql", 0, false},
		{"", 0, false},
		{"_users.sql", 0, false},
		{"-1_users.sql", 0, false},
		{"+1_users.sql", 0, false},
		{"99999999999_big.sql", 0, false}, // does not fit the int column
	}
	for _, tt := range tests {
		got, err := version(tt.name)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("version(%q) = %d, %v, want %d (accepted: %v)", tt.name, got, err, tt.want, tt.ok)
		}
	}
}

// A file that shares or lowers a version would be skipped as already applied, or run out of order.
func TestMigrationFilesAscend(t *testing.T) {
	last := 0
	for _, f := range migrationFiles(t) {
		v, err := version(filepath.Base(f))
		if err != nil || v <= last {
			t.Errorf("%s: version %d (%v) does not follow version %d", f, v, err, last)
		}
		last = v
	}
}
