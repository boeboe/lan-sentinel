// Package store owns the SQLite database: migrations and the single writer
// goroutine that commits batched transactions (docs/ARCHITECTURE.md §3).
// Collectors never use it; only the correlator and event engine submit
// writes.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"

	"lan-sentinel/internal/clock"
	"lan-sentinel/migrations"
)

// Defaults for Options.
const (
	DefaultFlushInterval = 5 * time.Second
	DefaultMaxBatch      = 1000
	DefaultQueueSize     = 4096
	busyTimeoutMillis    = 5000
)

// ErrClosed is returned when writing to a closed store.
var ErrClosed = errors.New("store closed")

// Op is one unit of work run inside the writer's batch transaction. A failing
// Op is rolled back to its own savepoint without affecting the rest of the
// batch.
type Op func(ctx context.Context, tx *sql.Tx) error

// Options configures Open.
type Options struct {
	Path          string
	Clock         clock.Clock
	Logger        *slog.Logger
	FlushInterval time.Duration // default 5s (NFR-PERF-2)
	MaxBatch      int           // ops per transaction before an early commit
	QueueSize     int
	Migrations    fs.FS // default: the embedded migrations
}

// Store is the single-writer SQLite store.
type Store struct {
	db     *sql.DB
	path   string
	clock  clock.Clock
	log    *slog.Logger
	reqs   chan request
	done   chan struct{}
	exited chan struct{}

	mu     sync.RWMutex
	closed bool

	schemaVersion int
	opErrors      atomic.Uint64
	commits       atomic.Uint64
}

type requestKind int

const (
	reqOp requestKind = iota
	reqFlush
	reqPing
	reqView
)

type request struct {
	kind  requestKind
	op    Op
	reply chan error
}

// Open creates the database directory if needed, opens the database in WAL
// mode, applies migrations and starts the writer goroutine.
func Open(ctx context.Context, o Options) (*Store, error) {
	if o.Path == "" {
		return nil, errors.New("store: empty database path")
	}
	if o.Clock == nil {
		o.Clock = clock.Real()
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = DefaultFlushInterval
	}
	if o.MaxBatch <= 0 {
		o.MaxBatch = DefaultMaxBatch
	}
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultQueueSize
	}
	if o.Migrations == nil {
		o.Migrations = migrations.FS
	}
	if err := os.MkdirAll(filepath.Dir(o.Path), 0o750); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", writerDSN(o.Path))
	if err != nil {
		return nil, fmt.Errorf("open database %s: %w", o.Path, err)
	}
	// One connection: the writer goroutine is the only user of this handle.
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	s := &Store{
		db: db, path: o.Path, clock: o.Clock, log: o.Logger,
		reqs: make(chan request, o.QueueSize), done: make(chan struct{}), exited: make(chan struct{}),
	}
	if err := s.init(ctx, o.Migrations); err != nil {
		_ = db.Close()
		return nil, err
	}
	go s.writer(o.FlushInterval, o.MaxBatch)
	return s, nil
}

func (s *Store) init(ctx context.Context, mfs fs.FS) error {
	var mode string
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
		return fmt.Errorf("open database %s: %w", s.path, err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("open database %s: journal mode is %q, want wal", s.path, mode)
	}
	ms, err := loadMigrations(mfs)
	if err != nil {
		return err
	}
	v, err := migrate(ctx, s.db, ms, s.clock.Now)
	if err != nil {
		return fmt.Errorf("migrate %s: %w", s.path, err)
	}
	s.schemaVersion = v
	return nil
}

// writerDSN builds the modernc.org/sqlite DSN for the writer connection.
func writerDSN(path string) string {
	return "file:" + escapePath(path) + "?" + strings.Join([]string{
		"_pragma=journal_mode(WAL)",
		"_pragma=synchronous(NORMAL)",
		fmt.Sprintf("_pragma=busy_timeout(%d)", busyTimeoutMillis),
		"_pragma=foreign_keys(ON)",
		"_txlock=immediate",
	}, "&")
}

func escapePath(p string) string {
	return strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(p)
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// SchemaVersion returns the schema version after migrations.
func (s *Store) SchemaVersion() int { return s.schemaVersion }

// OpErrors returns how many submitted ops have failed since Open.
func (s *Store) OpErrors() uint64 { return s.opErrors.Load() }

// Commits returns how many batch transactions have been committed.
func (s *Store) Commits() uint64 { return s.commits.Load() }

// Submit queues op for the next batch. It blocks while the queue is full.
func (s *Store) Submit(ctx context.Context, op Op) error {
	return s.send(ctx, request{kind: reqOp, op: op})
}

// Flush commits everything queued before it and waits for the commit.
func (s *Store) Flush(ctx context.Context) error {
	return s.roundTrip(ctx, reqFlush)
}

// View commits everything queued, then runs fn in its own transaction on
// the writer connection and returns fn's error. It is for reads that must
// see every earlier write, such as loading state at startup; fn must not
// keep the transaction open longer than necessary.
func (s *Store) View(ctx context.Context, fn func(ctx context.Context, tx *sql.Tx) error) error {
	reply := make(chan error, 1)
	if err := s.send(ctx, request{kind: reqView, op: fn, reply: reply}); err != nil {
		return err
	}
	select {
	case err := <-reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Ping checks that the writer goroutine is alive and draining its queue.
func (s *Store) Ping(ctx context.Context) error {
	return s.roundTrip(ctx, reqPing)
}

func (s *Store) roundTrip(ctx context.Context, kind requestKind) error {
	reply := make(chan error, 1)
	if err := s.send(ctx, request{kind: kind, reply: reply}); err != nil {
		return err
	}
	select {
	case err := <-reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Store) send(ctx context.Context, r request) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	select {
	case s.reqs <- r:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close commits everything queued, checkpoints and truncates the WAL, and
// closes the database. After a clean Close the -wal file is gone, so the
// database can be copied or opened immutable (docs/CLI.md §1).
func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	close(s.done)
	<-s.exited

	var errs []error
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		errs = append(errs, fmt.Errorf("checkpoint: %w", err))
	}
	if err := s.db.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close database: %w", err))
	}
	return errors.Join(errs...)
}

func (s *Store) writer(flushInterval time.Duration, maxBatch int) {
	defer close(s.exited)
	ticker := s.clock.NewTicker(flushInterval)
	defer ticker.Stop()
	var pending []Op

	commit := func() error {
		if len(pending) == 0 {
			return nil
		}
		err := s.commitBatch(pending)
		pending = pending[:0]
		return err
	}
	handle := func(r request) {
		switch r.kind {
		case reqOp:
			pending = append(pending, r.op)
			if len(pending) >= maxBatch {
				_ = commit()
			}
		case reqFlush:
			r.reply <- commit()
		case reqPing:
			r.reply <- nil
		case reqView:
			if err := commit(); err != nil {
				r.reply <- err
				return
			}
			r.reply <- s.view(r.op)
		}
	}

	for {
		select {
		case r := <-s.reqs:
			handle(r)
		case <-ticker.C():
			_ = commit()
		case <-s.done:
			// No new requests can arrive once done is closed; drain the rest.
			for {
				select {
				case r := <-s.reqs:
					handle(r)
				default:
					_ = commit()
					return
				}
			}
		}
	}
}

func (s *Store) commitBatch(ops []Op) error {
	ctx := context.Background()
	start := time.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.log.Error("store: begin batch failed; ops dropped", "ops", len(ops), "err", err)
		s.opErrors.Add(uint64(len(ops)))
		return fmt.Errorf("begin batch: %w", err)
	}
	failed := 0
	for _, op := range ops {
		if err := runOp(ctx, tx, op); err != nil {
			failed++
			s.opErrors.Add(1)
			s.log.Error("store: op failed", "err", err)
		}
	}
	if err := tx.Commit(); err != nil {
		s.log.Error("store: commit failed; batch lost", "ops", len(ops), "err", err)
		s.opErrors.Add(uint64(len(ops) - failed))
		return fmt.Errorf("commit batch: %w", err)
	}
	s.commits.Add(1)
	s.log.Debug("store: committed batch", "ops", len(ops), "failed", failed, "duration", time.Since(start))
	return nil
}

func (s *Store) view(fn Op) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin view: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // read-only
	return fn(ctx, tx)
}

func runOp(ctx context.Context, tx *sql.Tx, op Op) error {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT op`); err != nil {
		return fmt.Errorf("savepoint: %w", err)
	}
	if err := op(ctx, tx); err != nil {
		if _, rbErr := tx.ExecContext(ctx, `ROLLBACK TO op`); rbErr != nil {
			err = errors.Join(err, fmt.Errorf("rollback to savepoint: %w", rbErr))
		}
		_, _ = tx.ExecContext(ctx, `RELEASE op`)
		return err
	}
	if _, err := tx.ExecContext(ctx, `RELEASE op`); err != nil {
		return fmt.Errorf("release savepoint: %w", err)
	}
	return nil
}
