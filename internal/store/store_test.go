package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"lan-sentinel/internal/clock"
)

var t0 = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

func open(t *testing.T, o Options) *Store {
	t.Helper()
	if o.Path == "" {
		o.Path = filepath.Join(t.TempDir(), "sub", "hosts.db")
	}
	s, err := Open(context.Background(), o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// inspect opens a second, independent connection to the database file.
func inspect(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func count(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func insertContext(name string) Op {
	return func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO network_contexts (interface, first_seen, last_seen) VALUES (?, 1, 1)`, name)
		return err
	}
}

func TestOpenCreatesSchemaInWAL(t *testing.T) {
	s := open(t, Options{})
	if s.SchemaVersion() != 1 {
		t.Fatalf("SchemaVersion = %d, want 1", s.SchemaVersion())
	}
	db := inspect(t, s.Path())
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q, %v", mode, err)
	}
	for _, table := range []string{
		"network_contexts", "context_prefixes", "hosts", "addresses", "address_sources", "names",
		"services", "identifications", "observations", "observation_rollups", "events", "scans",
		"runtime_state", "schema_migrations",
	} {
		if count(t, db, `SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?`, table) != 1 {
			t.Errorf("table %s missing", table)
		}
	}
}

func TestSchemaConstraints(t *testing.T) {
	s := open(t, Options{})
	ctx := context.Background()
	exec := func(stmts ...string) error {
		return s.withTx(ctx, func(tx *sql.Tx) error {
			for _, q := range stmts {
				if _, err := tx.ExecContext(ctx, q); err != nil {
					return err
				}
			}
			return nil
		})
	}
	base := []string{
		`INSERT INTO network_contexts (id, interface, first_seen, last_seen) VALUES (1, 'eth1', 0, 0)`,
		`INSERT INTO hosts (host_id, context_id, mac, presence, first_seen, last_seen) VALUES ('a', 1, '00:1b:1b:aa:bb:01', 'ACTIVE', 0, 0)`,
		`INSERT INTO hosts (host_id, context_id, mac, presence, first_seen, last_seen) VALUES ('b', 1, '00:1b:1b:aa:bb:02', 'ACTIVE', 0, 0)`,
	}
	if err := exec(base...); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		stmts   []string
		wantErr string
	}{
		{"one host per context and MAC",
			[]string{`INSERT INTO hosts (host_id, context_id, mac, presence, first_seen, last_seen) VALUES ('c', 1, '00:1b:1b:aa:bb:01', 'ACTIVE', 0, 0)`},
			"UNIQUE"},
		{"one open binding per host and IP",
			[]string{
				`INSERT INTO addresses (context_id, host_id, ip, family, first_seen, last_seen) VALUES (1, 'a', '10.0.0.1', 4, 0, 0)`,
				`INSERT INTO addresses (context_id, host_id, ip, family, first_seen, last_seen) VALUES (1, 'a', '10.0.0.1', 4, 5, 5)`,
			}, "UNIQUE"},
		{"closed and open bindings for the same host and IP coexist",
			[]string{
				`INSERT INTO addresses (context_id, host_id, ip, family, first_seen, last_seen, ended_at) VALUES (1, 'a', '10.0.0.2', 4, 0, 0, 10)`,
				`INSERT INTO addresses (context_id, host_id, ip, family, first_seen, last_seen) VALUES (1, 'a', '10.0.0.2', 4, 20, 20)`,
			}, ""},
		{"conflicting open bindings on different hosts are allowed",
			[]string{
				`INSERT INTO addresses (context_id, host_id, ip, family, conflict, first_seen, last_seen) VALUES (1, 'a', '10.0.0.3', 4, 1, 0, 0)`,
				`INSERT INTO addresses (context_id, host_id, ip, family, conflict, first_seen, last_seen) VALUES (1, 'b', '10.0.0.3', 4, 1, 0, 0)`,
			}, ""},
		{"interval must not end before it starts",
			[]string{`INSERT INTO addresses (context_id, host_id, ip, family, first_seen, last_seen, ended_at) VALUES (1, 'a', '10.0.0.4', 4, 10, 10, 5)`},
			"CHECK"},
		{"foreign keys enforced",
			[]string{`INSERT INTO addresses (context_id, host_id, ip, family, first_seen, last_seen) VALUES (1, 'nope', '10.0.0.5', 4, 0, 0)`},
			"FOREIGN KEY"},
		{"unknown event type rejected",
			[]string{`INSERT INTO events (ts, type, severity, cause, clock_synced) VALUES (0, 'MAC_ADDED', 'notice', 'test', 1)`},
			"CHECK"},
		{"strict typing",
			[]string{`INSERT INTO network_contexts (interface, first_seen, last_seen) VALUES ('eth9', 'yesterday', 0)`},
			"cannot store TEXT value in INTEGER column"},
		{"rollup key treats NULL host as one value",
			[]string{
				`INSERT INTO observation_rollups (hour, context_id, source, ip, count, first_ts, last_ts) VALUES (1, 1, 'tcp_connect', '10.0.0.99', 1, 0, 0)`,
				`INSERT INTO observation_rollups (hour, context_id, source, ip, count, first_ts, last_ts) VALUES (1, 1, 'tcp_connect', '10.0.0.99', 1, 0, 0)`,
			}, "UNIQUE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := exec(tt.stmts...)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// withTx runs fn in its own transaction through the writer, outside of
// batching, and returns fn's error (tests only).
func (s *Store) withTx(ctx context.Context, fn func(*sql.Tx) error) error {
	errc := make(chan error, 1)
	if err := s.Submit(ctx, func(ctx context.Context, tx *sql.Tx) error {
		err := fn(tx)
		errc <- err
		return err
	}); err != nil {
		return err
	}
	if err := s.Flush(ctx); err != nil {
		return err
	}
	return <-errc
}

func TestBatchingOnTickerAndFlush(t *testing.T) {
	sim := clock.NewSim(t0)
	s := open(t, Options{Clock: sim, FlushInterval: 5 * time.Second})
	ctx := context.Background()
	db := inspect(t, s.Path())

	for _, n := range []string{"eth0", "eth1"} {
		if err := s.Submit(ctx, insertContext(n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Ping(ctx); err != nil { // ops are queued, not committed
		t.Fatal(err)
	}
	if got := count(t, db, `SELECT count(*) FROM network_contexts`); got != 0 {
		t.Fatalf("committed before the flush interval: %d rows", got)
	}
	sim.Advance(5 * time.Second)
	waitFor(t, func() bool { return s.Commits() == 1 })
	if got := count(t, db, `SELECT count(*) FROM network_contexts`); got != 2 {
		t.Fatalf("rows after tick = %d, want 2", got)
	}

	if err := s.Submit(ctx, insertContext("eth2")); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got := count(t, db, `SELECT count(*) FROM network_contexts`); got != 3 {
		t.Fatalf("rows after Flush = %d, want 3", got)
	}
}

func TestMaxBatchCommitsEarly(t *testing.T) {
	s := open(t, Options{Clock: clock.NewSim(t0), MaxBatch: 2})
	ctx := context.Background()
	for _, n := range []string{"a", "b", "c"} {
		if err := s.Submit(ctx, insertContext(n)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool { return s.Commits() == 1 })
	if got := count(t, inspect(t, s.Path()), `SELECT count(*) FROM network_contexts`); got != 2 {
		t.Fatalf("rows = %d, want 2 after an early commit of a full batch", got)
	}
}

func TestFailingOpIsIsolated(t *testing.T) {
	s := open(t, Options{Clock: clock.NewSim(t0)})
	ctx := context.Background()
	for _, op := range []Op{
		insertContext("eth0"),
		insertContext("eth0"), // UNIQUE violation
		func(context.Context, *sql.Tx) error { return errors.New("boom") },
		insertContext("eth1"),
	} {
		if err := s.Submit(ctx, op); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if s.OpErrors() != 2 {
		t.Errorf("OpErrors = %d, want 2", s.OpErrors())
	}
	if got := count(t, inspect(t, s.Path()), `SELECT count(*) FROM network_contexts`); got != 2 {
		t.Fatalf("rows = %d, want the 2 good ops committed", got)
	}
}

func TestCloseFlushesAndRemovesWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.db")
	s, err := Open(context.Background(), Options{Path: path, Clock: clock.NewSim(t0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Submit(context.Background(), insertContext("eth0")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Submit(context.Background(), insertContext("eth1")); !errors.Is(err, ErrClosed) {
		t.Errorf("Submit after Close = %v, want ErrClosed", err)
	}
	if fi, err := os.Stat(path + "-wal"); err == nil && fi.Size() > 0 {
		t.Errorf("WAL still has %d bytes after Close", fi.Size())
	}
	// Reopening keeps the data and does not re-run migrations.
	s2 := open(t, Options{Path: path})
	if s2.SchemaVersion() != 1 {
		t.Fatalf("SchemaVersion = %d", s2.SchemaVersion())
	}
	db := inspect(t, path)
	if got := count(t, db, `SELECT count(*) FROM network_contexts`); got != 1 {
		t.Fatalf("rows after reopen = %d, want 1", got)
	}
	if got := count(t, db, `SELECT count(*) FROM schema_migrations`); got != 1 {
		t.Fatalf("schema_migrations rows = %d, want 1", got)
	}
}

func TestMigrationsInOrderAndNewerSchemaRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.db")
	two := fstest.MapFS{
		"0002_more.sql": {Data: []byte(`ALTER TABLE t ADD COLUMN b INTEGER;`)},
		"0001_init.sql": {Data: []byte(`CREATE TABLE t (a INTEGER);`)},
		"README.md":     {Data: []byte(`ignored`)},
	}
	s, err := Open(context.Background(), Options{Path: path, Migrations: two})
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion() != 2 {
		t.Fatalf("SchemaVersion = %d, want 2", s.SchemaVersion())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	one := fstest.MapFS{"0001_init.sql": two["0001_init.sql"]}
	if _, err := Open(context.Background(), Options{Path: path, Migrations: one}); err == nil ||
		!strings.Contains(err.Error(), "newer than this binary supports") {
		t.Fatalf("opening a newer schema: err = %v", err)
	}
	bad := fstest.MapFS{"init.sql": {Data: []byte(`SELECT 1;`)}}
	if _, err := Open(context.Background(), Options{Path: filepath.Join(t.TempDir(), "x.db"), Migrations: bad}); err == nil {
		t.Fatal("badly named migration accepted")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
