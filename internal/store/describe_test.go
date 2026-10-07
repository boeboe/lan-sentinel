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

	"lan-sentinel/internal/store"
	"lan-sentinel/migrations"
)

func TestCleanDescription(t *testing.T) {
	for _, tt := range []struct {
		in, want string
		ok       bool
	}{
		{"  Solar panel rooftop  ", "Solar panel rooftop", true},
		{"", "", true},
		{"   ", "", true},
		{"Zonnepanelen dak — kantoor", "Zonnepanelen dak — kantoor", true},
		{strings.Repeat("é", store.MaxDescription), strings.Repeat("é", store.MaxDescription), true}, // characters, not bytes
		{strings.Repeat("x", store.MaxDescription+1), "", false},
		{"two\nlines", "", false},
		{"a\ttab", "", false},
		{"bad \xff byte", "", false},
	} {
		got, err := store.CleanDescription(tt.in)
		if got != tt.want || (err == nil) != tt.ok || err != nil && !errors.Is(err, store.ErrDescription) {
			t.Errorf("CleanDescription(%q) = %q, %v", tt.in, got, err)
		}
	}
}

// Migration 0007 adds hosts.description and rebuilds events for
// HOST_DESCRIBED, keeping the rows and every index.
func TestDescriptionMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.db")
	all, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := fstest.MapFS{}
	for _, n := range all {
		if n < "0007" {
			b, _ := fs.ReadFile(migrations.FS, n)
			old[n] = &fstest.MapFile{Data: b}
		}
	}
	ctx := context.Background()
	st, err := store.Open(ctx, store.Options{Path: path, Migrations: old})
	if err != nil {
		t.Fatal(err)
	}
	exec(t, st, `INSERT INTO network_contexts (id, interface, first_seen, last_seen) VALUES (1, 'eth1', 0, 0)`)
	exec(t, st, `INSERT INTO hosts (host_id, context_id, mac, presence, first_seen, last_seen) VALUES ('h1', 1, '00:1b:1b:aa:bb:01', 'ACTIVE', 0, 0)`)
	exec(t, st, `INSERT INTO events (ts, type, severity, cause, host_id) VALUES (5, 'HOST_DISCOVERED', 'notice', 'passive_arp', 'h1')`)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(ctx, store.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	exec(t, st, `UPDATE hosts SET description = 'Solar panel rooftop' WHERE host_id = 'h1'`)
	exec(t, st, `INSERT INTO events (ts, type, severity, cause, host_id, new_value) VALUES (6, 'HOST_DESCRIBED', 'notice', 'operator', 'h1', 'Solar panel rooftop')`)
	var types, desc string
	var indexes int
	if err := st.View(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT group_concat(type, ',') FROM (SELECT type FROM events ORDER BY id)`).Scan(&types); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = 'events' AND sql IS NOT NULL`).Scan(&indexes); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT description FROM hosts`).Scan(&desc)
	}); err != nil {
		t.Fatal(err)
	}
	if types != "HOST_DISCOVERED,HOST_DESCRIBED" || indexes != 9 || desc != "Solar panel rooftop" {
		t.Errorf("after 0007: events %q, %d indexes, description %q", types, indexes, desc)
	}
}
