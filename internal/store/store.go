// Package store keeps the broker's state in Postgres.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// User is a person who has logged in at least once.
type User struct {
	Sub      string
	Handle   string
	Disabled bool
}

// Share grants one user or group access to one tunnel. The empty Tunnel is the default tunnel.
type Share struct {
	Tunnel  string `json:"tunnel"` // "" is the default tunnel
	Kind    string `json:"kind"`   // "user" or "group"
	Grantee string `json:"grantee"`
}

var (
	// ErrNotFound means no row matches. A failed query is never ErrNotFound.
	ErrNotFound = errors.New("store: user not found")
	// ErrHandleTaken means another sub owns the handle.
	ErrHandleTaken = errors.New("store: handle is taken")
)

// uniqueViolation is the SQLSTATE of a duplicate key.
const uniqueViolation = "23505"

// migrationLock is the advisory lock key ("tunnels" in ASCII) that makes concurrent Opens take turns.
const migrationLock int64 = 0x74756e6e656c73

//go:embed migrations/*.sql
var migrations embed.FS

// Store is the broker's database handle. It is safe for concurrent use.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to the database and applies the migrations that have not run yet.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("store: open pool: %w", err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// Close releases the connections.
func (s *Store) Close() {
	s.pool.Close()
}

// migrate applies each embedded migration that schema_migrations does not record, in name order, one
// transaction per file. An advisory lock lets brokers that start together take turns. The lock belongs
// to the session, so everything runs on one connection and unlocks before it returns to the pool.
func migrate(ctx context.Context, pool *pgxpool.Pool) (err error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: connect for migrations: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "select pg_advisory_lock($1)", migrationLock); err != nil {
		return fmt.Errorf("store: lock migrations: %w", err)
	}
	defer func() {
		if _, uerr := conn.Exec(ctx, "select pg_advisory_unlock($1)", migrationLock); uerr != nil && err == nil {
			err = fmt.Errorf("store: unlock migrations: %w", uerr)
		}
	}()

	if _, err := conn.Exec(ctx, "create table if not exists schema_migrations (version int primary key)"); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	files, err := migrations.ReadDir("migrations") // sorted by name
	if err != nil {
		return fmt.Errorf("store: list migrations: %w", err) // coverage-ignore: migrations are embedded at build time, so ReadDir on the embedded FS cannot fail
	}
	for _, f := range files {
		v, err := version(f.Name())
		if err != nil {
			return err // coverage-ignore: the embedded file names are fixed and valid, so version cannot fail here
		}
		var applied bool
		if err := conn.QueryRow(ctx, "select exists (select 1 from schema_migrations where version = $1)", v).Scan(&applied); err != nil {
			return fmt.Errorf("store: check migration %s: %w", f.Name(), err)
		}
		if applied {
			continue
		}
		sql, err := migrations.ReadFile(path.Join("migrations", f.Name()))
		if err != nil {
			return fmt.Errorf("store: read migration %s: %w", f.Name(), err) // coverage-ignore: the embedded file just read by ReadDir always exists
		}
		if err := apply(ctx, conn, v, string(sql)); err != nil {
			return fmt.Errorf("store: apply migration %s: %w", f.Name(), err)
		}
	}
	return nil
}

// apply runs one migration and records its version in the same transaction.
func apply(ctx context.Context, conn *pgxpool.Conn, v int, sql string) error {
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, sql); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "insert into schema_migrations (version) values ($1)", v)
		return err
	})
}

// version is the integer before the first "_" or "." of a migration file name: 001_users.sql is 1.
func version(name string) (int, error) {
	prefix, _, _ := strings.Cut(name, ".")
	prefix, _, _ = strings.Cut(prefix, "_")
	v, err := strconv.ParseUint(prefix, 10, 31) // 31 bits: a Postgres int is a signed 32-bit number
	if err != nil {
		return 0, fmt.Errorf("store: migration %q does not start with a version number", name)
	}
	return int(v), nil
}

const (
	userBySub    = "select sub, handle, disabled from users where sub = $1"
	userByHandle = "select sub, handle, disabled from users where handle = $1"
)

// UserBySub returns the user with this sub, or ErrNotFound.
func (s *Store) UserBySub(ctx context.Context, sub string) (User, error) {
	return s.queryUser(ctx, userBySub, sub)
}

// UserByHandle returns the user who owns this handle, or ErrNotFound.
func (s *Store) UserByHandle(ctx context.Context, handle string) (User, error) {
	return s.queryUser(ctx, userByHandle, handle)
}

func (s *Store) queryUser(ctx context.Context, query, arg string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, query, arg).Scan(&u.Sub, &u.Handle, &u.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: query user: %w", err)
	}
	return u, nil
}

// CreateUser adds the user, or returns the row this sub already has (its handle stays as it was).
// It returns ErrHandleTaken when another sub owns the handle.
func (s *Store) CreateUser(ctx context.Context, sub, handle string) (User, error) {
	_, err := s.pool.Exec(ctx, "insert into users (sub, handle) values ($1, $2) on conflict (sub) do nothing", sub, handle)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		// Only the handle index can raise this, but it also fires when a concurrent insert of this very
		// sub committed between the sub check and the handle check. That insert is not a conflict, so
		// the row for the sub decides.
		u, err := s.UserBySub(ctx, sub)
		if errors.Is(err, ErrNotFound) {
			err = ErrHandleTaken
		}
		return u, err
	}
	if err != nil {
		return User{}, fmt.Errorf("store: create user: %w", err)
	}
	return s.UserBySub(ctx, sub)
}

const (
	shareInsert = "insert into shares (owner_sub, tunnel, kind, grantee) values ($1, $2, $3, $4) on conflict (owner_sub, tunnel, kind, grantee) do nothing"
	shareDelete = "delete from shares where owner_sub = $1 and tunnel = $2 and kind = $3 and grantee = $4"
	shareList   = "select tunnel, kind, grantee from shares where owner_sub = $1 order by tunnel, kind, grantee"
	shareMatch  = `select exists (
    select 1 from shares
    where owner_sub = $1 and tunnel = $2
      and ((kind = 'user' and lower(grantee) = lower($3))
        or (kind = 'group' and grantee = any($4)))
)`
)

// PutShare grants the share. Putting a share that is already there does nothing.
func (s *Store) PutShare(ctx context.Context, ownerSub string, sh Share) error {
	if _, err := s.pool.Exec(ctx, shareInsert, ownerSub, sh.Tunnel, sh.Kind, sh.Grantee); err != nil {
		return fmt.Errorf("store: put share: %w", err)
	}
	return nil
}

// DeleteShare removes the share. Deleting a share that is not there does nothing.
func (s *Store) DeleteShare(ctx context.Context, ownerSub string, sh Share) error {
	if _, err := s.pool.Exec(ctx, shareDelete, ownerSub, sh.Tunnel, sh.Kind, sh.Grantee); err != nil {
		return fmt.Errorf("store: delete share: %w", err)
	}
	return nil
}

// SharesByOwner returns the owner's shares, ordered by tunnel, kind, grantee.
func (s *Store) SharesByOwner(ctx context.Context, ownerSub string) ([]Share, error) {
	rows, err := s.pool.Query(ctx, shareList, ownerSub)
	if err != nil {
		return nil, fmt.Errorf("store: list shares: %w", err)
	}
	defer rows.Close()

	shares := []Share{}
	for rows.Next() {
		var sh Share
		if err := rows.Scan(&sh.Tunnel, &sh.Kind, &sh.Grantee); err != nil {
			return nil, fmt.Errorf("store: list shares: %w", err)
		}
		shares = append(shares, sh)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list shares: %w", err)
	}
	return shares, nil
}

// ShareMatches reports whether the owner shared the tunnel with this username, case-insensitively, or
// with one of these groups. A failed query is an error, never false.
func (s *Store) ShareMatches(ctx context.Context, ownerSub, tunnel, username string, groups []string) (bool, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx, shareMatch, ownerSub, tunnel, username, groups).Scan(&ok); err != nil {
		return false, fmt.Errorf("store: match share: %w", err)
	}
	return ok, nil
}
