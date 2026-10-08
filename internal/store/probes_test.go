package store_test

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"lan-sentinel/internal/store"
	"lan-sentinel/migrations"
)

func exec(t *testing.T, st *store.Store, q string, args ...any) {
	t.Helper()
	ctx := context.Background()
	if err := st.Submit(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if st.OpErrors() != 0 {
		t.Fatalf("write failed: %s", q)
	}
}

func TestLastScan(t *testing.T) {
	st, _, _ := seed(t)
	r := reader(t, st)
	ctx := context.Background()
	if s, err := r.LastScan(ctx); err != nil || s != nil {
		t.Fatalf("LastScan without scans = %+v, %v", s, err)
	}
	ms := t0.UnixMilli()
	exec(t, st, `INSERT INTO scans (id, context_id, kind, trigger, started_at, finished_at, targets, results_json)
		VALUES (1, 1, 'arp', 'operator', ?, ?, 253, '{"responders":3}')`, ms, ms+31000)
	s, err := r.LastScan(ctx)
	if err != nil || s == nil || s.ID != 1 || s.Kind != "arp" || s.Trigger != "operator" || s.Targets != 253 ||
		!s.Started.Equal(t0) || s.Finished == nil || s.Finished.Sub(t0).Seconds() != 31 || string(s.Results) != `{"responders":3}` {
		t.Fatalf("LastScan = %+v, %v", s, err)
	}
	exec(t, st, `INSERT INTO scans (id, context_id, kind, trigger, started_at, targets) VALUES (2, 1, 'arp,tcp/502', 'operator', ?, 10)`, ms+60000)
	if s, err := r.LastScan(ctx); err != nil || s.ID != 2 || s.Finished != nil || s.Interface == "" {
		t.Fatalf("running scan = %+v, %v", s, err)
	}
}

func TestKnownIPv4(t *testing.T) {
	st, _, _ := seed(t)
	r := reader(t, st)
	ctx := context.Background()
	got, err := r.KnownIPv4(ctx, "eth1")
	if err != nil || len(got) == 0 {
		t.Fatalf("KnownIPv4 = %v, %v", got, err)
	}
	var want int
	if err := st.View(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(DISTINCT ip) FROM addresses WHERE family = 4 AND ended_at IS NULL
			AND context_id = (SELECT id FROM network_contexts WHERE interface = 'eth1')`).Scan(&want)
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != want {
		t.Errorf("%d known addresses, want %d", len(got), want)
	}
	for _, a := range got {
		if !a.IP.Is4() || a.LastSeen.IsZero() {
			t.Errorf("known address %+v", a)
		}
	}
	if none, err := r.KnownIPv4(ctx, "eth9"); err != nil || len(none) != 0 {
		t.Errorf("unknown interface: %v, %v", none, err)
	}
}

func TestIdentifyTargets(t *testing.T) {
	st, _, _ := seed(t)
	r := reader(t, st)
	ctx := context.Background()
	got, err := r.IdentifyTargets(ctx, "eth1", "modbus", time.Time{})
	if err != nil || len(got) == 0 {
		t.Fatalf("IdentifyTargets = %v, %v", got, err)
	}
	var eligible store.IdentifyCandidate
	for _, c := range got {
		if c.Suppress == "" {
			eligible = c
			break
		}
	}
	if eligible.HostID == "" {
		t.Fatal("no eligible host")
	}
	exec(t, st, `INSERT INTO identify_attempts (host_id, probe, result, attempted_at, trigger) VALUES (?, 'modbus', 'timeout', ?, 'scheduled')`,
		eligible.HostID, t0.UnixMilli())
	again, err := r.IdentifyTargets(ctx, "eth1", "modbus", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range again {
		if c.HostID == eligible.HostID && (!c.Attempted || c.Suppress != store.IdentifyAttempted) {
			t.Errorf("after attempt %+v", c)
		}
	}
	att, err := r.IdentifyAttemptOf(ctx, eligible.HostID, "modbus")
	if err != nil || att.Result != "timeout" || att.Trigger != "scheduled" {
		t.Errorf("IdentifyAttemptOf = %+v, %v", att, err)
	}
	stale, err := r.IdentifyTargets(ctx, "eth1", "modbus", t0.Add(100*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range stale {
		if c.Suppress == "" {
			t.Errorf("expected stale or attempted, got %+v", c)
		}
	}
}

func TestServiceDetail(t *testing.T) {
	st, _, _ := seed(t)
	r := reader(t, st)
	ctx := context.Background()
	exec(t, st, `UPDATE services SET detail_json = '{"probe":"ntp","stratum":"2"}'`)
	rows, err := r.Services(ctx, store.ServiceFilter{})
	if err != nil || len(rows) == 0 || rows[0].Detail["stratum"] != "2" {
		t.Fatalf("services = %+v, %v", rows, err)
	}
	h, err := r.Host(ctx, rows[0].HostID)
	if err != nil || len(h.Services) == 0 || h.Services[0].Detail["probe"] != "ntp" {
		t.Fatalf("host services = %+v, %v", h.Services, err)
	}
	exec(t, st, `UPDATE services SET detail_json = 'not json'`)
	rows, err = r.Services(ctx, store.ServiceFilter{})
	if err != nil || rows[0].Detail != nil {
		t.Errorf("bad detail = %+v, %v", rows[0].Detail, err)
	}
}

func TestOfflineRefusesOtherSchemaVersions(t *testing.T) {
	sub := func(names ...string) fstest.MapFS {
		m := fstest.MapFS{}
		for _, n := range names {
			b, err := fs.ReadFile(migrations.FS, n)
			if err != nil {
				t.Fatal(err)
			}
			m[n] = &fstest.MapFile{Data: b}
		}
		return m
	}
	all, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	older := sub(all[:len(all)-1]...)
	newer := sub(all...)
	newer["9999_future.sql"] = &fstest.MapFile{Data: []byte(`CREATE TABLE future (a INTEGER);`)}
	for _, tt := range []struct {
		name string
		fs   fs.FS
		want string
	}{
		{"older", older, "start the daemon once"},
		{"newer", newer, "newer than this binary"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hosts.db")
			st, err := store.Open(context.Background(), store.Options{Path: path, Migrations: tt.fs})
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			_, err = store.OpenReadOnly(path, store.ReadOptions{})
			if !errors.Is(err, store.ErrSchemaVersion) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("OpenReadOnly = %v", err)
			}
		})
	}
}

// Events written before migration 0004 recorded a synchronised clock
// without checking it: they become unknown, and the old column is gone.
func TestClockSyncMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.db")
	all, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := fstest.MapFS{}
	for _, n := range all {
		if n >= "0004" {
			continue
		}
		b, _ := fs.ReadFile(migrations.FS, n)
		old[n] = &fstest.MapFile{Data: b}
	}
	st, err := store.Open(context.Background(), store.Options{Path: path, Migrations: old})
	if err != nil {
		t.Fatal(err)
	}
	exec(t, st, `INSERT INTO events (ts, type, severity, cause, clock_synced) VALUES (0, 'INTERFACE_UP', 'notice', 'test', 1)`)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(context.Background(), store.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var clock string
	var oldCols int
	if err := st.View(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT clock_sync FROM events`).Scan(&clock); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('events') WHERE name = 'clock_synced'`).Scan(&oldCols)
	}); err != nil {
		t.Fatal(err)
	}
	if clock != "unknown" || oldCols != 0 {
		t.Errorf("after migration: clock_sync %q, clock_synced columns %d", clock, oldCols)
	}
	ctx := context.Background()
	if err := st.Submit(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO events (ts, type, severity, cause, clock_sync) VALUES (0, 'INTERFACE_UP', 'notice', 'test', 'maybe')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_ = st.Flush(ctx)
	if st.OpErrors() != 1 {
		t.Error("a clock_sync outside synced/unsynced/unknown was accepted")
	}
}
