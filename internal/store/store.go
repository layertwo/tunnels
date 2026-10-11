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
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// User is a person who has logged in at least once.
type User struct {
	Sub      string
	Handle   string
	Disabled bool
}

// Machine is a broker-owned principal with a handle of its own, owned by a user (later a group).
type Machine struct {
	ID        string
	Handle    string
	OwnerKind string
	OwnerRef  string
	ClientID  string
	Disabled  bool
	CreatedAt time.Time
	CreatedBy string
}

// Share grants one user or group access to one site: the owner's handle and tunnel together. The empty
// Tunnel is the handle's default site.
type Share struct {
	Handle    string    `json:"handle"` // the site's handle: the owner for a person's own site, the machine for a machine's
	Tunnel    string    `json:"tunnel"` // "" is the default tunnel
	Kind      string    `json:"kind"`   // "user" or "group"
	Grantee   string    `json:"grantee"`
	ExpiresAt time.Time `json:"expires_at,omitzero"` // the zero time means the share never ends
}

var (
	// ErrNotFound means no row matches. A failed query is never ErrNotFound.
	ErrNotFound = errors.New("store: user not found")
	// ErrHandleTaken means another sub owns the handle.
	ErrHandleTaken = errors.New("store: handle is taken")
)

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

// OpenRetry opens the store, retrying with a capped backoff until ctx ends or wait elapses. It returns
// the last error when it gives up. It logs nothing; the caller decides what a failure means.
func OpenRetry(ctx context.Context, databaseURL string, wait time.Duration) (*Store, error) {
	deadline := time.Now().Add(wait)
	for backoff := time.Second; ; backoff = min(backoff*2, 10*time.Second) {
		s, err := Open(ctx, databaseURL)
		if err == nil {
			return s, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(backoff):
		}
	}
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
		if err := applyMigrationFile(ctx, conn, f.Name()); err != nil {
			return err
		}
	}
	return nil
}

// applyMigrationFile applies one embedded migration unless schema_migrations already records it.
func applyMigrationFile(ctx context.Context, conn *pgxpool.Conn, name string) error {
	v, err := version(name)
	if err != nil {
		return err // coverage-ignore: the embedded file names are fixed and valid, so version cannot fail here
	}
	var applied bool
	if err := conn.QueryRow(ctx, "select exists (select 1 from schema_migrations where version = $1)", v).Scan(&applied); err != nil {
		return fmt.Errorf("store: check migration %s: %w", name, err)
	}
	if applied {
		return nil
	}
	sql, err := migrations.ReadFile(path.Join("migrations", name))
	if err != nil {
		return fmt.Errorf("store: read migration %s: %w", name, err) // coverage-ignore: the embedded file just read by ReadDir always exists
	}
	if err := apply(ctx, conn, v, string(sql)); err != nil {
		return fmt.Errorf("store: apply migration %s: %w", name, err)
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
	return scanUser(s.pool.QueryRow(ctx, query, arg))
}

// scanUser reads one user row, turning no rows into ErrNotFound.
func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.Sub, &u.Handle, &u.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: query user: %w", err)
	}
	return u, nil
}

// CreateUser adds the user, or returns the row this sub already has (its handle stays as it was).
// It returns ErrHandleTaken when a user or a machine already owns the handle.
func (s *Store) CreateUser(ctx context.Context, sub, handle string) (User, error) {
	var u User
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := claimHandle(ctx, tx, handle); err != nil {
			// A repeat login for a sub that already has a row keeps that row, whatever its handle.
			if errors.Is(err, ErrHandleTaken) {
				if existing, uerr := scanUser(tx.QueryRow(ctx, userBySub, sub)); uerr == nil {
					u = existing
					return nil
				}
			}
			return err
		}
		if _, err := tx.Exec(ctx, "insert into users (sub, handle) values ($1, $2) on conflict (sub) do nothing", sub, handle); err != nil {
			return fmt.Errorf("store: create user: %w", err)
		}
		existing, err := scanUser(tx.QueryRow(ctx, userBySub, sub))
		u = existing
		return err
	})
	return u, err
}

const (
	handleInUse = `select exists (select 1 from users where handle = $1)
    or exists (select 1 from machines where handle = $1)`
	machineInsert = `insert into machines (handle, owner_kind, owner_ref, client_id, created_by)
    values ($1, $2, $3, $4, $5)`
	machineCols = "id, handle, owner_kind, owner_ref, client_id, disabled, created_at, created_by"
)

// claimHandle takes the per-handle advisory lock, then refuses the handle when a user or a machine
// already owns it. The lock is transaction-scoped, so a user's first login and a machine's create
// running at the same time take turns and cannot both claim one handle.
func claimHandle(ctx context.Context, tx pgx.Tx, handle string) error {
	if _, err := tx.Exec(ctx, "select pg_advisory_xact_lock(hashtext($1))", handle); err != nil {
		return fmt.Errorf("store: lock handle: %w", err)
	}
	var taken bool
	if err := tx.QueryRow(ctx, handleInUse, handle).Scan(&taken); err != nil {
		return fmt.Errorf("store: check handle: %w", err)
	}
	if taken {
		return ErrHandleTaken
	}
	return nil
}

// CreateMachine adds a machine row. The database fills in id and created_at. It returns
// ErrHandleTaken when a user or another machine already owns the handle.
func (s *Store) CreateMachine(ctx context.Context, m Machine) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := claimHandle(ctx, tx, m.Handle); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, machineInsert, m.Handle, m.OwnerKind, m.OwnerRef, m.ClientID, m.CreatedBy); err != nil {
			return fmt.Errorf("store: create machine: %w", err)
		}
		return nil
	})
}

// MachineByHandle returns the machine with this handle, or ErrNotFound.
func (s *Store) MachineByHandle(ctx context.Context, handle string) (Machine, error) {
	return scanMachine(s.pool.QueryRow(ctx, "select "+machineCols+" from machines where handle = $1", handle))
}

// MachineByClientID returns the machine with this Pocket ID client id, or ErrNotFound.
func (s *Store) MachineByClientID(ctx context.Context, clientID string) (Machine, error) {
	return scanMachine(s.pool.QueryRow(ctx, "select "+machineCols+" from machines where client_id = $1", clientID))
}

// scanMachine reads one machine row, turning no rows into ErrNotFound.
func scanMachine(row pgx.Row) (Machine, error) {
	var m Machine
	err := row.Scan(&m.ID, &m.Handle, &m.OwnerKind, &m.OwnerRef, &m.ClientID, &m.Disabled, &m.CreatedAt, &m.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Machine{}, ErrNotFound
	}
	if err != nil {
		return Machine{}, fmt.Errorf("store: query machine: %w", err)
	}
	return m, nil
}

// MachinesByOwner returns the owner's machines, ordered by handle.
func (s *Store) MachinesByOwner(ctx context.Context, ownerRef string) ([]Machine, error) {
	rows, err := s.pool.Query(ctx, "select "+machineCols+" from machines where owner_ref = $1 order by handle", ownerRef)
	if err != nil {
		return nil, fmt.Errorf("store: list machines: %w", err)
	}
	defer rows.Close()

	machines := []Machine{}
	for rows.Next() {
		m, err := scanMachine(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list machines: %w", err)
		}
		machines = append(machines, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list machines: %w", err)
	}
	return machines, nil
}

// SetMachineDisabled flips a machine's disabled flag. Updating a machine that is not there does nothing.
func (s *Store) SetMachineDisabled(ctx context.Context, clientID string, disabled bool) error {
	if _, err := s.pool.Exec(ctx, "update machines set disabled = $2 where client_id = $1", clientID, disabled); err != nil {
		return fmt.Errorf("store: disable machine: %w", err)
	}
	return nil
}

// DeleteMachine removes the machine with this client id. Deleting a machine that is not there does nothing.
func (s *Store) DeleteMachine(ctx context.Context, clientID string) error {
	if _, err := s.pool.Exec(ctx, "delete from machines where client_id = $1", clientID); err != nil {
		return fmt.Errorf("store: delete machine: %w", err)
	}
	return nil
}

const (
	shareInsert = "insert into shares (owner_sub, handle, tunnel, kind, grantee, expires_at) values ($1, $2, $3, $4, $5, $6) on conflict (owner_sub, handle, tunnel, kind, grantee) do update set expires_at = excluded.expires_at"
	shareDelete = "delete from shares where owner_sub = $1 and handle = $2 and tunnel = $3 and kind = $4 and grantee = $5"
	shareList   = "select handle, tunnel, kind, grantee, expires_at from shares where owner_sub = $1 order by handle, tunnel, kind, grantee"
	shareMatch  = `select exists (
    select 1 from shares
    where owner_sub = $1 and handle = $2 and tunnel = $3
      and (expires_at is null or expires_at > now())
      and ((kind = 'user' and lower(grantee) = lower($4))
        or (kind = 'group' and grantee = any($5)))
)`
)

// PutShare grants the share, upserting an existing one: a repeat can set or clear expires_at.
func (s *Store) PutShare(ctx context.Context, ownerSub string, sh Share) error {
	var expires *time.Time
	if !sh.ExpiresAt.IsZero() {
		expires = &sh.ExpiresAt
	}
	if _, err := s.pool.Exec(ctx, shareInsert, ownerSub, sh.Handle, sh.Tunnel, sh.Kind, sh.Grantee, expires); err != nil {
		return fmt.Errorf("store: put share: %w", err)
	}
	return nil
}

// DeleteShare removes the share. Deleting a share that is not there does nothing.
func (s *Store) DeleteShare(ctx context.Context, ownerSub string, sh Share) error {
	if _, err := s.pool.Exec(ctx, shareDelete, ownerSub, sh.Handle, sh.Tunnel, sh.Kind, sh.Grantee); err != nil {
		return fmt.Errorf("store: delete share: %w", err)
	}
	return nil
}

// SharesByOwner returns the owner's shares, ordered by handle, tunnel, kind, grantee.
func (s *Store) SharesByOwner(ctx context.Context, ownerSub string) ([]Share, error) {
	rows, err := s.pool.Query(ctx, shareList, ownerSub)
	if err != nil {
		return nil, fmt.Errorf("store: list shares: %w", err)
	}
	defer rows.Close()

	shares := []Share{}
	for rows.Next() {
		var sh Share
		var expires *time.Time
		if err := rows.Scan(&sh.Handle, &sh.Tunnel, &sh.Kind, &sh.Grantee, &expires); err != nil {
			return nil, fmt.Errorf("store: list shares: %w", err)
		}
		if expires != nil {
			sh.ExpiresAt = *expires
		}
		shares = append(shares, sh)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list shares: %w", err)
	}
	return shares, nil
}

// ShareMatches reports whether the owner shared the site (handle + tunnel) with this username,
// case-insensitively, or with one of these groups. A failed query is an error, never false.
func (s *Store) ShareMatches(ctx context.Context, ownerSub, handle, tunnel, username string, groups []string) (bool, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx, shareMatch, ownerSub, handle, tunnel, username, groups).Scan(&ok); err != nil {
		return false, fmt.Errorf("store: match share: %w", err)
	}
	return ok, nil
}
