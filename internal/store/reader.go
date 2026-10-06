package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"lan-sentinel/migrations"
)

// Reader runs the read-only queries behind the API and `--offline`
// (docs/CLI.md). Every query runs in one read transaction, so it sees one
// consistent snapshot.
type Reader struct {
	db   *sql.DB
	path string
	now  func() time.Time
	// Immutable is set when the database was opened without a WAL
	// (daemon stopped); the CLI prints a notice.
	Immutable bool
	// nameExpiry marks names not confirmed for this long as stale.
	nameExpiry atomic.Int64
}

// SetNameExpiry changes the staleness threshold of names (on reload).
func (r *Reader) SetNameExpiry(d time.Duration) { r.nameExpiry.Store(int64(d)) }

func (r *Reader) nameExpiryD() time.Duration { return time.Duration(r.nameExpiry.Load()) }

// DefaultReadBusyTimeout is how long an offline reader waits on a lock.
const DefaultReadBusyTimeout = 5 * time.Second

// ErrReadOnlyBesideWAL is returned when the WAL cannot be read beside a
// running daemon (docs/CLI.md §1).
var ErrReadOnlyBesideWAL = errors.New("cannot open database read-only beside the WAL; run as a member of the service group or copy the database")

// ReadOptions configures OpenReadOnly.
type ReadOptions struct {
	BusyTimeout time.Duration // default DefaultReadBusyTimeout
	Now         func() time.Time
	NameExpiry  time.Duration
}

// OpenReadOnly opens the database for `--offline` following the contract in
// docs/CLI.md §1. With a WAL present (daemon running) it opens mode=ro with
// a busy timeout and query_only; it needs read access to the WAL and an
// existing -shm or a writable directory. Without a WAL (daemon stopped
// cleanly) it opens immutable, since a read-only user cannot create -shm.
func OpenReadOnly(path string, o ReadOptions) (*Reader, error) {
	if o.BusyTimeout <= 0 {
		o.BusyTimeout = DefaultReadBusyTimeout
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	params := []string{"mode=ro", fmt.Sprintf("_pragma=busy_timeout(%d)", o.BusyTimeout.Milliseconds()), "_pragma=query_only(1)"}
	immutable := false
	switch _, err := os.Stat(path + "-wal"); {
	case err == nil:
		if err := besideWAL(path); err != nil {
			return nil, err
		}
	case errors.Is(err, os.ErrNotExist):
		immutable = true
		params = append(params, "immutable=1")
	default:
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	db, err := sql.Open("sqlite", "file:"+escapePath(path)+"?"+strings.Join(params, "&"))
	if err != nil {
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	r := newReader(db, path, o.Now)
	r.Immutable = immutable
	r.SetNameExpiry(o.NameExpiry)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	if err := checkSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	return r, nil
}

// ErrSchemaVersion is returned offline when the database was written by an
// older or newer binary: only the daemon migrates.
var ErrSchemaVersion = errors.New("database schema does not match this binary")

func checkSchema(db *sql.DB) error {
	ms, err := loadMigrations(migrations.FS)
	if err != nil {
		return err
	}
	v, err := schemaVersion(context.Background(), db)
	if err != nil {
		return err
	}
	latest := ms[len(ms)-1].version
	switch {
	case v < latest:
		return fmt.Errorf("%w: version %d, this binary uses %d; start the daemon once to migrate it", ErrSchemaVersion, v, latest)
	case v > latest:
		return fmt.Errorf("%w: version %d is newer than this binary supports (%d)", ErrSchemaVersion, v, latest)
	}
	return nil
}

// besideWAL checks what a read-only connection needs beside a running
// writer: a readable WAL, and an existing -shm or a writable directory.
func besideWAL(path string) error {
	f, err := os.Open(path + "-wal")
	if err != nil {
		return fmt.Errorf("%w (%w)", ErrReadOnlyBesideWAL, err)
	}
	_ = f.Close()
	if _, err := os.Stat(path + "-shm"); err == nil {
		return nil
	}
	if err := unix.Access(filepath.Dir(path), unix.W_OK); err != nil {
		return fmt.Errorf("%w (-shm missing and %s not writable)", ErrReadOnlyBesideWAL, filepath.Dir(path))
	}
	return nil
}

// Reader returns a read-only connection pool on the store's database for
// the API. It reads what the writer has committed (at most one batch
// interval behind).
func (s *Store) Reader(nameExpiry time.Duration) (*Reader, error) {
	db, err := sql.Open("sqlite", "file:"+escapePath(s.path)+"?"+strings.Join([]string{
		"mode=ro", fmt.Sprintf("_pragma=busy_timeout(%d)", busyTimeoutMillis), "_pragma=query_only(1)",
	}, "&"))
	if err != nil {
		return nil, fmt.Errorf("open reader on %s: %w", s.path, err)
	}
	db.SetMaxOpenConns(4)
	r := newReader(db, s.path, s.clock.Now)
	r.SetNameExpiry(nameExpiry)
	return r, nil
}

func newReader(db *sql.DB, path string, now func() time.Time) *Reader {
	if now == nil {
		now = time.Now
	}
	return &Reader{db: db, path: path, now: now}
}

// Close closes the reader.
func (r *Reader) Close() error { return r.db.Close() }

// Path returns the database path.
func (r *Reader) Path() string { return r.path }

// IsBusy reports whether err is SQLite's busy or locked error, which the
// CLI turns into exit 2 after the busy timeout.
func IsBusy(err error) bool {
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		code := coded.Code() & 0xff
		return code == 5 || code == 6 // SQLITE_BUSY, SQLITE_LOCKED
	}
	return false
}

// read runs fn in one read-only transaction.
func (r *Reader) read(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("read %s: %w", r.path, err)
	}
	defer tx.Rollback() //nolint:errcheck // read-only
	if err := fn(tx); err != nil {
		return fmt.Errorf("read %s: %w", r.path, err)
	}
	return nil
}
