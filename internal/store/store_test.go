package store

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

// An admin disables an account in the table; both lookups must report it, or the broker would never
// refuse a disabled account.
func TestDisabledIsRead(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "sub-1", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "update users set disabled = true where sub = $1", "sub-1"); err != nil {
		t.Fatal(err)
	}
	for name, find := range map[string]func() (User, error){
		"by sub":    func() (User, error) { return s.UserBySub(ctx, "sub-1") },
		"by handle": func() (User, error) { return s.UserByHandle(ctx, "alice") },
	} {
		if u, err := find(); err != nil || !u.Disabled {
			t.Errorf("%s: %+v, %v; want the account disabled", name, u, err)
		}
	}
}

// createUser adds a user, which a share's owner_sub references.
func createUser(t *testing.T, s *Store, ctx context.Context, sub, handle string) {
	t.Helper()
	if _, err := s.CreateUser(ctx, sub, handle); err != nil {
		t.Fatalf("CreateUser(%q, %q): %v", sub, handle, err)
	}
}

// putShare stores a share and fails the test on error.
func putShare(t *testing.T, s *Store, ctx context.Context, ownerSub string, sh Share) {
	t.Helper()
	if err := s.PutShare(ctx, ownerSub, sh); err != nil {
		t.Fatalf("PutShare(%q, %+v): %v", ownerSub, sh, err)
	}
}

func TestPutShareIsIdempotent(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")

	sh := Share{Tunnel: "blog", Kind: "user", Grantee: "Bob"}
	putShare(t, s, ctx, "sub-1", sh)
	putShare(t, s, ctx, "sub-1", sh)

	if got := count(t, dbURL, "select count(*) from shares"); got != 1 {
		t.Errorf("shares has %d rows, want 1", got)
	}
}

func TestDeleteShareIsIdempotent(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")

	sh := Share{Tunnel: "blog", Kind: "user", Grantee: "Bob"}
	putShare(t, s, ctx, "sub-1", sh)
	for i := range 2 { // the second delete removes a row that is not there
		if err := s.DeleteShare(ctx, "sub-1", sh); err != nil {
			t.Errorf("DeleteShare #%d: %v", i+1, err)
		}
	}
	if got := count(t, dbURL, "select count(*) from shares"); got != 0 {
		t.Errorf("shares has %d rows, want 0", got)
	}
}

func TestSharesByOwnerOrders(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	createUser(t, s, ctx, "sub-2", "carol")

	// Stored out of order: the read sorts by tunnel, kind, grantee.
	putShare(t, s, ctx, "sub-1", Share{Tunnel: "blog", Kind: "user", Grantee: "alice"})
	putShare(t, s, ctx, "sub-1", Share{Tunnel: "", Kind: "user", Grantee: "bob"})
	putShare(t, s, ctx, "sub-1", Share{Tunnel: "blog", Kind: "group", Grantee: "family"})
	putShare(t, s, ctx, "sub-2", Share{Tunnel: "blog", Kind: "user", Grantee: "alice"}) // another owner

	want := []Share{
		{Tunnel: "", Kind: "user", Grantee: "bob"},
		{Tunnel: "blog", Kind: "group", Grantee: "family"},
		{Tunnel: "blog", Kind: "user", Grantee: "alice"},
	}
	got, err := s.SharesByOwner(ctx, "sub-1")
	if err != nil {
		t.Fatalf("SharesByOwner: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("SharesByOwner = %+v, want %+v", got, want)
	}
}

func TestShareMatchesUserIsCaseInsensitive(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	putShare(t, s, ctx, "sub-1", Share{Tunnel: "blog", Kind: "user", Grantee: "Bob"})

	for _, username := range []string{"bob", "BOB", "bOb"} {
		got, err := s.ShareMatches(ctx, "sub-1", "blog", username, nil)
		if err != nil {
			t.Fatalf("ShareMatches(%q): %v", username, err)
		}
		if !got {
			t.Errorf("ShareMatches(%q) = false, want true", username)
		}
	}
}

func TestShareMatchesIsExact(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	putShare(t, s, ctx, "sub-1", Share{Tunnel: "blog", Kind: "user", Grantee: "bob"})

	tests := []struct {
		username string
		want     bool
	}{
		{"bob", true},
		{"bobby", false},
		{"bo", false},
	}
	for _, tt := range tests {
		got, err := s.ShareMatches(ctx, "sub-1", "blog", tt.username, nil)
		if err != nil {
			t.Fatalf("ShareMatches(%q): %v", tt.username, err)
		}
		if got != tt.want {
			t.Errorf("ShareMatches(%q) = %v, want %v", tt.username, got, tt.want)
		}
	}
}

func TestShareMatchesGroupIsExact(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	putShare(t, s, ctx, "sub-1", Share{Tunnel: "blog", Kind: "group", Grantee: "family"})

	tests := []struct {
		name   string
		groups []string
		want   bool
	}{
		{"one of several", []string{"work", "family"}, true},
		{"prefix only", []string{"family-admins"}, false},
		{"no groups", nil, false},
		{"empty group name", []string{""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.ShareMatches(ctx, "sub-1", "blog", "alice", tt.groups)
			if err != nil {
				t.Fatalf("ShareMatches(%v): %v", tt.groups, err)
			}
			if got != tt.want {
				t.Errorf("ShareMatches(groups %v) = %v, want %v", tt.groups, got, tt.want)
			}
		})
	}
}

func TestShareMatchesWrongTunnel(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	putShare(t, s, ctx, "sub-1", Share{Tunnel: "blog", Kind: "user", Grantee: "bob"})

	tests := []struct {
		tunnel string
		want   bool
	}{
		{"blog", true},
		{"", false}, // the default tunnel is not the tunnel the share names
		{"other", false},
	}
	for _, tt := range tests {
		got, err := s.ShareMatches(ctx, "sub-1", tt.tunnel, "bob", nil)
		if err != nil {
			t.Fatalf("ShareMatches(%q): %v", tt.tunnel, err)
		}
		if got != tt.want {
			t.Errorf("ShareMatches(tunnel %q) = %v, want %v", tt.tunnel, got, tt.want)
		}
	}
}

func TestShareMatchesError(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	putShare(t, s, ctx, "sub-1", Share{Tunnel: "blog", Kind: "user", Grantee: "bob"})
	s.Close()

	got, err := s.ShareMatches(ctx, "sub-1", "blog", "bob", nil)
	if err == nil {
		t.Fatalf("ShareMatches on a closed store = %v, nil; want an error", got)
	}
	if got {
		t.Errorf("ShareMatches on a closed store = true with error %v, want false", err)
	}
}

// withParam adds one query parameter to dbURL; pgx hands unknown parameters to the server as
// runtime settings (the same trick schemaURL uses for search_path).
func withParam(t *testing.T, dbURL, key, value string) string {
	t.Helper()
	u, err := url.Parse(dbURL)
	if err != nil {
		t.Fatalf("parse %q: %v", dbURL, err)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// An unparseable URL fails in pgxpool.New, before any connection is made.
func TestOpenInvalidDatabaseURLFails(t *testing.T) {
	s, err := Open(testCtx(t), "postgres://postgres@localhost:notaport/postgres?sslmode=disable")
	if err == nil {
		s.Close()
		t.Fatal("Open with an invalid DATABASE_URL succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "store: open pool") {
		t.Errorf("Open error = %v, want it to name the pool", err)
	}
}

// The pool connects lazily, so a reachable URL whose server is down fails in migrate's Acquire.
func TestOpenUnreachableDatabaseFails(t *testing.T) {
	s, err := Open(testCtx(t), "postgres://postgres:postgres@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1")
	if err == nil {
		s.Close()
		t.Fatal("Open against an unreachable server succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "store: connect for migrations") {
		t.Errorf("Open error = %v, want it to name the migration connection", err)
	}
}

// migrate acquires an advisory lock; while another session holds it and the statement timeout is
// short, the lock attempt aborts instead of waiting forever.
func TestMigrateLockTimeoutFails(t *testing.T) {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := testCtx(t)
	holder, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect lock holder: %v", err)
	}
	t.Cleanup(func() { holder.Close(context.Background()) })
	if _, err := holder.Exec(ctx, "select pg_advisory_lock($1)", migrationLock); err != nil {
		t.Fatalf("hold migration lock: %v", err)
	}
	t.Cleanup(func() {
		if _, err := holder.Exec(context.Background(), "select pg_advisory_unlock($1)", migrationLock); err != nil {
			t.Errorf("release migration lock: %v", err)
		}
	})

	dbURL := withParam(t, schemaURL(t), "statement_timeout", "100")
	s, err := Open(ctx, dbURL)
	if err == nil {
		s.Close()
		t.Fatal("Open while the migration lock is held succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "store: lock migrations") {
		t.Errorf("Open error = %v, want it to name the migration lock", err)
	}
}

// A read-only connection cannot create schema_migrations.
func TestMigrateCreateTableFails(t *testing.T) {
	dbURL := withParam(t, schemaURL(t), "default_transaction_read_only", "on")
	s, err := Open(testCtx(t), dbURL)
	if err == nil {
		s.Close()
		t.Fatal("Open on a read-only connection succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "store: create schema_migrations") {
		t.Errorf("Open error = %v, want it to name schema_migrations", err)
	}
}

// A schema_migrations table without a version column makes the applied check fail.
func TestMigrateCheckMigrationFails(t *testing.T) {
	dbURL := schemaURL(t)
	if err := run(dbURL, "create table schema_migrations (not_version int)"); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	s, err := Open(testCtx(t), dbURL)
	if err == nil {
		s.Close()
		t.Fatal("Open with an unreadable schema_migrations succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "store: check migration") {
		t.Errorf("Open error = %v, want it to name the migration check", err)
	}
}

// A conflicting users table makes the first migration's statement fail, rolling back its transaction.
func TestMigrateApplyFails(t *testing.T) {
	dbURL := schemaURL(t)
	if err := run(dbURL, "create table users (not_our_users int)"); err != nil {
		t.Fatalf("create conflicting users: %v", err)
	}
	s, err := Open(testCtx(t), dbURL)
	if err == nil {
		s.Close()
		t.Fatal("Open with a conflicting users table succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "store: apply migration") {
		t.Errorf("Open error = %v, want it to name the failed migration", err)
	}
	if got := count(t, dbURL, "select count(*) from schema_migrations"); got != 0 {
		t.Errorf("schema_migrations has %d rows after a failed migration, want 0", got)
	}
}

// With a schema-local pg_advisory_unlock shadowing the built-in, the migrations succeed but the
// deferred unlock raises, which migrate reports.
func TestMigrateUnlockFails(t *testing.T) {
	dbURL := schemaURL(t)
	u, err := url.Parse(dbURL)
	if err != nil {
		t.Fatalf("parse %q: %v", dbURL, err)
	}
	schema := u.Query().Get("search_path")
	if err := run(dbURL, `create function pg_advisory_unlock(bigint) returns boolean language plpgsql volatile as $$ begin raise exception 'unlock shadow'; end $$`); err != nil {
		t.Fatalf("create the unlock shadow: %v", err)
	}
	// Listing the schema before pg_catalog makes its function win the name lookup.
	dbURL = withParam(t, dbURL, "search_path", schema+",pg_catalog")
	s, err := Open(testCtx(t), dbURL)
	if err == nil {
		s.Close()
		t.Fatal("Open with a shadowed unlock succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "store: unlock migrations") {
		t.Errorf("Open error = %v, want it to name the migration unlock", err)
	}
}

// On a closed pool every statement fails; none may come back as a zero value or a nil error.
func TestStoreClosedPoolErrors(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	sh := Share{Tunnel: "blog", Kind: "user", Grantee: "bob"}
	putShare(t, s, ctx, "sub-1", sh)
	s.Close()

	if _, err := s.CreateUser(ctx, "sub-2", "carol"); err == nil {
		t.Error("CreateUser on a closed store succeeded, want an error")
	}
	if err := s.PutShare(ctx, "sub-1", sh); err == nil {
		t.Error("PutShare on a closed store succeeded, want an error")
	}
	if err := s.DeleteShare(ctx, "sub-1", sh); err == nil {
		t.Error("DeleteShare on a closed store succeeded, want an error")
	}
	if shares, err := s.SharesByOwner(ctx, "sub-1"); err == nil || shares != nil {
		t.Errorf("SharesByOwner on a closed store = %v, %v; want nil, error", shares, err)
	}
	if got := count(t, dbURL, "select count(*) from users"); got != 1 {
		t.Errorf("users has %d rows after the failed writes, want 1", got)
	}
	if got := count(t, dbURL, "select count(*) from shares"); got != 1 {
		t.Errorf("shares has %d rows after the failed writes, want 1", got)
	}
}

// A grantee that is not text makes the query succeed but the row scan fail.
func TestSharesByOwnerScanFails(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	putShare(t, s, ctx, "sub-1", Share{Tunnel: "blog", Kind: "user", Grantee: "bob"})
	if err := run(dbURL, "alter table shares alter column grantee type bytea using convert_to(grantee, 'UTF8')"); err != nil {
		t.Fatalf("alter shares.grantee: %v", err)
	}
	shares, err := s.SharesByOwner(ctx, "sub-1")
	if err == nil || shares != nil {
		t.Errorf("SharesByOwner with an unreadable column = %v, %v; want nil, error", shares, err)
	}
}

// OpenRetry against a database that is up returns a working store on the first try.
func TestOpenRetrySucceeds(t *testing.T) {
	s, err := OpenRetry(testCtx(t), schemaURL(t), time.Minute)
	if err != nil {
		t.Fatalf("OpenRetry: %v", err)
	}
	t.Cleanup(s.Close)
}

// A server that never answers fails before the context does, with the last error.
func TestOpenRetryGivesUp(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	start := time.Now()
	s, err := OpenRetry(ctx, "postgres://postgres:postgres@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1", 200*time.Millisecond)
	if err == nil {
		s.Close()
		t.Fatal("OpenRetry against an unreachable server succeeded, want an error")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("OpenRetry took %v to give up, want well under the 30 s context", elapsed)
	}
}

// A cancelled context stops the loop at once, even while the wait has time left.
func TestOpenRetryStopsOnContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	start := time.Now()
	s, err := OpenRetry(ctx, "postgres://postgres:postgres@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1", time.Minute)
	if err == nil {
		s.Close()
		t.Fatal("OpenRetry with a cancelled context succeeded, want an error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("OpenRetry took %v to stop on a cancelled context, want prompt", elapsed)
	}
}

// A row whose expression raises ends the stream with an error instead of a partial list.
func TestSharesByOwnerRowsError(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	putShare(t, s, ctx, "sub-1", Share{Tunnel: "blog", Kind: "user", Grantee: "bob"})
	putShare(t, s, ctx, "sub-1", Share{Tunnel: "blog", Kind: "user", Grantee: "boom"})
	if err := run(dbURL, "alter table shares rename to shares_base"); err != nil {
		t.Fatalf("rename shares: %v", err)
	}
	if err := run(dbURL, `create function boom() returns text language plpgsql volatile as $$ begin raise exception 'boom'; end $$`); err != nil {
		t.Fatalf("create boom: %v", err)
	}
	if err := run(dbURL, `create view shares as select owner_sub, tunnel, case when grantee = 'boom' then boom() else kind end as kind, grantee from shares_base`); err != nil {
		t.Fatalf("create failing view: %v", err)
	}
	shares, err := s.SharesByOwner(ctx, "sub-1")
	if err == nil || shares != nil {
		t.Errorf("SharesByOwner with a failing row = %v, %v; want nil, error", shares, err)
	}
}
