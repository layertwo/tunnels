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

// runMigration applies one migration file by name, so a test can build the schema in stages: the
// up-only migrations run in name order, and a test that needs a row before a later one applies it.
func runMigration(t *testing.T, dbURL, name string) {
	t.Helper()
	sql, err := os.ReadFile(filepath.Join("migrations", name))
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	if err := run(dbURL, string(sql)); err != nil {
		t.Fatalf("apply migration %s: %v", name, err)
	}
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

// The share-key migration runs against a live table: it adds the site's handle, backfills it from the
// owner's users row (every share ever stored was a person's own site), and refuses a later row with no
// handle.
func TestShareHandleMigrationBackfills(t *testing.T) {
	dbURL := schemaURL(t)
	for _, name := range []string{"001_users.sql", "002_shares.sql", "003_share_expiry.sql", "004_machines.sql"} {
		runMigration(t, dbURL, name)
	}
	if err := run(dbURL, "insert into users (sub, handle) values ('sub-alice', 'alice')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := run(dbURL, "insert into shares (owner_sub, tunnel, kind, grantee) values ('sub-alice', 'blog', 'user', 'bob'), ('sub-alice', '', 'user', 'carol')"); err != nil {
		t.Fatalf("seed shares: %v", err)
	}
	runMigration(t, dbURL, "005_share_site.sql")

	if got := count(t, dbURL, "select count(*) from shares where handle = 'alice'"); got != 2 {
		t.Errorf("%d shares backfilled with the owner's handle, want 2", got)
	}
	if err := run(dbURL, "insert into shares (owner_sub, tunnel, kind, grantee) values ('sub-alice', 'x', 'user', 'dave')"); err == nil {
		t.Error("a share without a handle was inserted, want the NOT NULL constraint to refuse it")
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

	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	sh := Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "Bob", ExpiresAt: expires}
	putShare(t, s, ctx, "sub-1", sh)
	putShare(t, s, ctx, "sub-1", sh)

	if got := count(t, dbURL, "select count(*) from shares"); got != 1 {
		t.Errorf("shares has %d rows, want 1", got)
	}
	got, err := s.SharesByOwner(ctx, "sub-1")
	if err != nil || len(got) != 1 || got[0].Handle != "alice" || !got[0].ExpiresAt.Equal(expires) {
		t.Errorf("SharesByOwner = %+v, %v; want one row for alice ending %v", got, err, expires)
	}
}

// Re-sharing a permanent grant with an end must replace its end, not keep it forever.
func TestPutShareUpdatesExpiry(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")

	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "bob"}) // permanent first
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "bob", ExpiresAt: time.Now().Add(-time.Hour)})

	if got := count(t, dbURL, "select count(*) from shares"); got != 1 {
		t.Errorf("shares has %d rows, want 1", got)
	}
	got, err := s.ShareMatches(ctx, "sub-1", "alice", "blog", "bob", nil)
	if err != nil {
		t.Fatalf("ShareMatches: %v", err)
	}
	if got {
		t.Error("ShareMatches = true after the share was re-granted with a past end, want false")
	}
}

func TestDeleteShareIsIdempotent(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")

	sh := Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "Bob"}
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

	// Stored out of order: the read sorts by handle, tunnel, kind, grantee.
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "alice"})
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "", Kind: "user", Grantee: "bob"})
	putShare(t, s, ctx, "sub-1", Share{Handle: "zoe", Tunnel: "blog", Kind: "group", Grantee: "family"})
	putShare(t, s, ctx, "sub-2", Share{Handle: "carol", Tunnel: "blog", Kind: "user", Grantee: "alice"}) // another owner

	want := []Share{
		{Handle: "alice", Tunnel: "", Kind: "user", Grantee: "bob"},
		{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "alice"},
		{Handle: "zoe", Tunnel: "blog", Kind: "group", Grantee: "family"},
	}
	got, err := s.SharesByOwner(ctx, "sub-1")
	if err != nil {
		t.Fatalf("SharesByOwner: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("SharesByOwner = %+v, want %+v", got, want)
	}
}

// A share may carry an absolute end; a share without one stays open. The time survives the round trip.
func TestPutAndListShareWithExpiry(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")

	expires := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Microsecond)
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "bob", ExpiresAt: expires})
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "carol"}) // no end, ever

	got, err := s.SharesByOwner(ctx, "sub-1")
	if err != nil {
		t.Fatalf("SharesByOwner: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("SharesByOwner = %+v, want two shares", got)
	}
	if !got[0].ExpiresAt.Equal(expires) {
		t.Errorf("expires_at = %v, want %v", got[0].ExpiresAt, expires)
	}
	if !got[1].ExpiresAt.IsZero() {
		t.Errorf("a share without an expiry read back as %v, want the zero time", got[1].ExpiresAt)
	}
}

// An expired share no longer admits a visitor; one without an end never expires.
func TestShareMatchesIgnoresExpired(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "bob", ExpiresAt: time.Now().Add(-time.Hour)})
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "carol"})
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "dave", ExpiresAt: time.Now().Add(time.Hour)})

	tests := []struct {
		username string
		want     bool
	}{
		{"bob", false},  // expired
		{"carol", true}, // no end
		{"dave", true},  // still in the future
	}
	for _, tt := range tests {
		got, err := s.ShareMatches(ctx, "sub-1", "alice", "blog", tt.username, nil)
		if err != nil {
			t.Fatalf("ShareMatches(%q): %v", tt.username, err)
		}
		if got != tt.want {
			t.Errorf("ShareMatches(%q) = %v, want %v", tt.username, got, tt.want)
		}
	}
}

func TestShareMatchesUserIsCaseInsensitive(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "Bob"})

	for _, username := range []string{"bob", "BOB", "bOb"} {
		got, err := s.ShareMatches(ctx, "sub-1", "alice", "blog", username, nil)
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
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "bob"})

	tests := []struct {
		username string
		want     bool
	}{
		{"bob", true},
		{"bobby", false},
		{"bo", false},
	}
	for _, tt := range tests {
		got, err := s.ShareMatches(ctx, "sub-1", "alice", "blog", tt.username, nil)
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
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "group", Grantee: "family"})

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
			got, err := s.ShareMatches(ctx, "sub-1", "alice", "blog", "alice", tt.groups)
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
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "bob"})

	tests := []struct {
		tunnel string
		want   bool
	}{
		{"blog", true},
		{"", false}, // the default tunnel is not the tunnel the share names
		{"other", false},
	}
	for _, tt := range tests {
		got, err := s.ShareMatches(ctx, "sub-1", "alice", tt.tunnel, "bob", nil)
		if err != nil {
			t.Fatalf("ShareMatches(%q): %v", tt.tunnel, err)
		}
		if got != tt.want {
			t.Errorf("ShareMatches(tunnel %q) = %v, want %v", tt.tunnel, got, tt.want)
		}
	}
}

// A share is keyed by the site, not the tunnel name alone: a share on one of an owner's sites must
// never admit another with the same tunnel name (invariant 10).
func TestShareMatchesBySite(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "bob"})

	tests := []struct {
		handle string
		want   bool
	}{
		{"alice", true},  // the site the share names
		{"nas", false},   // another of the owner's sites, same tunnel name
		{"carol", false}, // an unrelated handle
	}
	for _, tt := range tests {
		got, err := s.ShareMatches(ctx, "sub-1", tt.handle, "blog", "bob", nil)
		if err != nil {
			t.Fatalf("ShareMatches(%q): %v", tt.handle, err)
		}
		if got != tt.want {
			t.Errorf("ShareMatches(handle %q) = %v, want %v", tt.handle, got, tt.want)
		}
	}
}

func TestShareMatchesError(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "bob"})
	s.Close()

	got, err := s.ShareMatches(ctx, "sub-1", "alice", "blog", "bob", nil)
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
	if err := s.CreateMachine(ctx, Machine{Handle: "nas", OwnerKind: "user", OwnerRef: "sub-1", ClientID: "client-1", CreatedBy: "sub-1"}); err == nil {
		t.Error("CreateMachine on a closed store succeeded, want an error")
	}
	if _, err := s.MachineByHandle(ctx, "nas"); err == nil {
		t.Error("MachineByHandle on a closed store succeeded, want an error")
	}
	if _, err := s.MachineByClientID(ctx, "client-1"); err == nil {
		t.Error("MachineByClientID on a closed store succeeded, want an error")
	}
	if machines, err := s.MachinesByOwner(ctx, "sub-1"); err == nil || machines != nil {
		t.Errorf("MachinesByOwner on a closed store = %v, %v; want nil, error", machines, err)
	}
	if err := s.SetMachineDisabled(ctx, "client-1", true); err == nil {
		t.Error("SetMachineDisabled on a closed store succeeded, want an error")
	}
	if err := s.DeleteMachine(ctx, "client-1"); err == nil {
		t.Error("DeleteMachine on a closed store succeeded, want an error")
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
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "bob"})
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
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "bob"})
	putShare(t, s, ctx, "sub-1", Share{Handle: "alice", Tunnel: "blog", Kind: "user", Grantee: "boom"})
	if err := run(dbURL, "alter table shares rename to shares_base"); err != nil {
		t.Fatalf("rename shares: %v", err)
	}
	if err := run(dbURL, `create function boom() returns text language plpgsql volatile as $$ begin raise exception 'boom'; end $$`); err != nil {
		t.Fatalf("create boom: %v", err)
	}
	if err := run(dbURL, `create view shares as select owner_sub, handle, tunnel, case when grantee = 'boom' then boom() else kind end as kind, grantee, expires_at from shares_base`); err != nil {
		t.Fatalf("create failing view: %v", err)
	}
	shares, err := s.SharesByOwner(ctx, "sub-1")
	if err == nil || shares != nil {
		t.Errorf("SharesByOwner with a failing row = %v, %v; want nil, error", shares, err)
	}
}

// createMachine adds a machine owned by a user and returns the stored row.
func createMachine(t *testing.T, s *Store, ctx context.Context, handle, ownerRef, clientID string) Machine {
	t.Helper()
	if err := s.CreateMachine(ctx, Machine{Handle: handle, OwnerKind: "user", OwnerRef: ownerRef, ClientID: clientID, CreatedBy: ownerRef}); err != nil {
		t.Fatalf("CreateMachine(%q): %v", handle, err)
	}
	m, err := s.MachineByHandle(ctx, handle)
	if err != nil {
		t.Fatalf("MachineByHandle(%q): %v", handle, err)
	}
	return m
}

// A machine round-trips through both lookups, with the columns the database fills in defaulted.
func TestCreateMachineAndLookups(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	m := Machine{Handle: "nas", OwnerKind: "user", OwnerRef: "sub-1", ClientID: "client-123", CreatedBy: "sub-1"}
	if err := s.CreateMachine(ctx, m); err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	byHandle, err := s.MachineByHandle(ctx, "nas")
	if err != nil {
		t.Fatalf("MachineByHandle: %v", err)
	}
	byClient, err := s.MachineByClientID(ctx, "client-123")
	if err != nil {
		t.Fatalf("MachineByClientID: %v", err)
	}
	if byHandle != byClient {
		t.Errorf("MachineByHandle = %+v, MachineByClientID = %+v, want the same row", byHandle, byClient)
	}
	if byHandle.ID == "" || byHandle.Handle != "nas" || byHandle.OwnerKind != "user" ||
		byHandle.OwnerRef != "sub-1" || byHandle.ClientID != "client-123" ||
		byHandle.Disabled || byHandle.CreatedAt.IsZero() || byHandle.CreatedBy != "sub-1" {
		t.Errorf("machine = %+v, want the fields it was created with and a generated id and created_at", byHandle)
	}
}

// One handle is owned once, whether the earlier claim is another machine or a user.
func TestCreateMachineHandleTaken(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	createMachine(t, s, ctx, "nas", "sub-1", "client-1")

	tests := []struct {
		name    string
		machine Machine
	}{
		{"another machine's handle", Machine{Handle: "nas", OwnerKind: "user", OwnerRef: "sub-1", ClientID: "client-2", CreatedBy: "sub-1"}},
		{"a user's handle", Machine{Handle: "alice", OwnerKind: "user", OwnerRef: "sub-1", ClientID: "client-3", CreatedBy: "sub-1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.CreateMachine(ctx, tt.machine); !errors.Is(err, ErrHandleTaken) {
				t.Errorf("CreateMachine(%q) error = %v, want ErrHandleTaken", tt.machine.Handle, err)
			}
		})
	}
	if got := count(t, dbURL, "select count(*) from machines"); got != 1 {
		t.Errorf("machines has %d rows, want 1", got)
	}
}

// A machine's handle is refused to a brand-new user, and the user is not created.
func TestCreateUserHandleTakenByMachine(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	createMachine(t, s, ctx, "nas", "sub-1", "client-1")
	if _, err := s.CreateUser(ctx, "sub-2", "nas"); !errors.Is(err, ErrHandleTaken) {
		t.Fatalf("CreateUser(sub-2, nas) error = %v, want ErrHandleTaken", err)
	}
	if _, err := s.UserBySub(ctx, "sub-2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserBySub(sub-2) error = %v, want ErrNotFound", err)
	}
	if got := count(t, dbURL, "select count(*) from users"); got != 0 {
		t.Errorf("users has %d rows, want 0", got)
	}
}

// A user's first login and a machine's create racing for one handle leave exactly one owner: the
// advisory lock serialises them, and the loser reads the winner's row.
func TestConcurrentMachineAndUserHandle(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	const rounds = 30
	for r := range rounds {
		handle := fmt.Sprintf("shared-%d", r)
		sub := fmt.Sprintf("sub-%d", r)
		client := fmt.Sprintf("client-%d", r)
		var userErr, machineErr error
		parallel(2, func(i int) {
			if i == 0 {
				_, userErr = s.CreateUser(ctx, sub, handle)
				return
			}
			machineErr = s.CreateMachine(ctx, Machine{Handle: handle, OwnerKind: "user", OwnerRef: sub, ClientID: client, CreatedBy: sub})
		})
		won := 0
		if userErr == nil {
			won++
		} else if !errors.Is(userErr, ErrHandleTaken) {
			t.Errorf("round %d: CreateUser error = %v, want nil or ErrHandleTaken", r, userErr)
		}
		if machineErr == nil {
			won++
		} else if !errors.Is(machineErr, ErrHandleTaken) {
			t.Errorf("round %d: CreateMachine error = %v, want nil or ErrHandleTaken", r, machineErr)
		}
		if won != 1 {
			t.Errorf("round %d: %d owners of %q, want exactly 1", r, won, handle)
		}
	}
	if got := count(t, dbURL, "select (select count(*) from users) + (select count(*) from machines)"); got != rounds {
		t.Errorf("owners = %d, want one per round (%d)", got, rounds)
	}
}

// The flag flips both ways, list returns only the owner's machines in handle order, and delete
// removes one and is idempotent.
func TestMachineDisabledDeleteAndOwnerList(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	createUser(t, s, ctx, "sub-1", "alice")
	createUser(t, s, ctx, "sub-2", "carol")
	createMachine(t, s, ctx, "pi", "sub-1", "client-1")
	createMachine(t, s, ctx, "nas", "sub-1", "client-2")
	createMachine(t, s, ctx, "edge", "sub-2", "client-3")

	if err := s.SetMachineDisabled(ctx, "client-1", true); err != nil {
		t.Fatalf("SetMachineDisabled: %v", err)
	}
	if m, err := s.MachineByClientID(ctx, "client-1"); err != nil || !m.Disabled {
		t.Errorf("MachineByClientID = %+v, %v; want disabled", m, err)
	}
	if err := s.SetMachineDisabled(ctx, "client-1", false); err != nil {
		t.Fatalf("SetMachineDisabled: %v", err)
	}
	if m, err := s.MachineByClientID(ctx, "client-1"); err != nil || m.Disabled {
		t.Errorf("MachineByClientID = %+v, %v; want enabled", m, err)
	}

	got, err := s.MachinesByOwner(ctx, "sub-1")
	if err != nil {
		t.Fatalf("MachinesByOwner: %v", err)
	}
	if len(got) != 2 || got[0].Handle != "nas" || got[1].Handle != "pi" {
		t.Errorf("MachinesByOwner = %+v, want nas then pi", got)
	}

	if err := s.DeleteMachine(ctx, "client-1"); err != nil {
		t.Fatalf("DeleteMachine: %v", err)
	}
	if _, err := s.MachineByClientID(ctx, "client-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("MachineByClientID after delete error = %v, want ErrNotFound", err)
	}
	if err := s.DeleteMachine(ctx, "client-1"); err != nil { // deleting what is gone does nothing
		t.Errorf("second DeleteMachine: %v", err)
	}
	if got := count(t, dbURL, "select count(*) from machines"); got != 2 {
		t.Errorf("machines has %d rows, want 2", got)
	}
}

func TestMachineNotFound(t *testing.T) {
	s := newStore(t)
	ctx := testCtx(t)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	tests := []struct {
		name string
		call func(context.Context, string) (Machine, error)
	}{
		{"MachineByHandle", s.MachineByHandle},
		{"MachineByClientID", s.MachineByClientID},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/missing", func(t *testing.T) {
			if _, err := tt.call(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
				t.Errorf("error = %v, want ErrNotFound", err)
			}
		})
		t.Run(tt.name+"/failure is not a miss", func(t *testing.T) {
			if _, err := tt.call(cancelled, "nobody"); err == nil || errors.Is(err, ErrNotFound) {
				t.Errorf("error = %v, want a failure that is not ErrNotFound", err)
			}
		})
	}
}

// An unreadable users table must fail the handle check, not silently let the handle through.
func TestMachineHandleCheckFails(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	if err := run(dbURL, "alter table users rename to users_base"); err != nil {
		t.Fatalf("rename users: %v", err)
	}
	m := Machine{Handle: "nas", OwnerKind: "user", OwnerRef: "sub-1", ClientID: "client-1", CreatedBy: "sub-1"}
	if err := s.CreateMachine(ctx, m); err == nil {
		t.Error("CreateMachine with an unreadable users table succeeded, want an error")
	}
	if _, err := s.CreateUser(ctx, "sub-1", "alice"); err == nil {
		t.Error("CreateUser with an unreadable users table succeeded, want an error")
	}
}

// While another session holds a handle's advisory lock, a create must fail rather than wait forever.
func TestMachineHandleLockAborts(t *testing.T) {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	holder, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect lock holder: %v", err)
	}
	t.Cleanup(func() { holder.Close(context.Background()) })
	tx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lock holder: %v", err)
	}
	t.Cleanup(func() { tx.Rollback(context.Background()) })
	if _, err := tx.Exec(ctx, "select pg_advisory_xact_lock(hashtext($1))", "nas"); err != nil {
		t.Fatalf("hold the handle lock: %v", err)
	}
	short, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	m := Machine{Handle: "nas", OwnerKind: "user", OwnerRef: "sub-1", ClientID: "client-1", CreatedBy: "sub-1"}
	if err := s.CreateMachine(short, m); err == nil {
		t.Error("CreateMachine while the handle lock is held succeeded, want an error")
	}
}

// A failed insert is reported, not swallowed, once the handle checks have passed.
func TestMachineInsertFails(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	if err := run(dbURL, "alter table machines add constraint no_nas check (handle <> 'nas')"); err != nil {
		t.Fatalf("add machines constraint: %v", err)
	}
	m := Machine{Handle: "nas", OwnerKind: "user", OwnerRef: "sub-1", ClientID: "client-1", CreatedBy: "sub-1"}
	if err := s.CreateMachine(ctx, m); err == nil {
		t.Error("CreateMachine that violates a constraint succeeded, want an error")
	}
}

func TestCreateUserInsertFails(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	if err := run(dbURL, "alter table users add constraint no_bob check (handle <> 'bob')"); err != nil {
		t.Fatalf("add users constraint: %v", err)
	}
	if _, err := s.CreateUser(ctx, "sub-1", "bob"); err == nil {
		t.Error("CreateUser that violates a constraint succeeded, want an error")
	}
}

// An unreadable column makes the query succeed but the row scan fail.
func TestMachinesByOwnerScanFails(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	createMachine(t, s, ctx, "nas", "sub-1", "client-1")
	if err := run(dbURL, "alter table machines alter column client_id type bytea using convert_to(client_id, 'UTF8')"); err != nil {
		t.Fatalf("alter machines.client_id: %v", err)
	}
	machines, err := s.MachinesByOwner(ctx, "sub-1")
	if err == nil || machines != nil {
		t.Errorf("MachinesByOwner with an unreadable column = %v, %v; want nil, error", machines, err)
	}
}

// A row whose expression raises ends the stream with an error instead of a partial list.
func TestMachinesByOwnerRowsError(t *testing.T) {
	dbURL := schemaURL(t)
	s := openStore(t, dbURL)
	ctx := testCtx(t)
	createMachine(t, s, ctx, "nas", "sub-1", "client-1")
	createMachine(t, s, ctx, "boom", "sub-1", "client-2")
	if err := run(dbURL, "alter table machines rename to machines_base"); err != nil {
		t.Fatalf("rename machines: %v", err)
	}
	if err := run(dbURL, `create function boom() returns text language plpgsql volatile as $$ begin raise exception 'boom'; end $$`); err != nil {
		t.Fatalf("create boom: %v", err)
	}
	if err := run(dbURL, `create view machines as select id, handle, case when handle = 'boom' then boom() else owner_kind end as owner_kind, owner_ref, client_id, disabled, created_at, created_by from machines_base`); err != nil {
		t.Fatalf("create failing view: %v", err)
	}
	machines, err := s.MachinesByOwner(ctx, "sub-1")
	if err == nil || machines != nil {
		t.Errorf("MachinesByOwner with a failing row = %v, %v; want nil, error", machines, err)
	}
}
