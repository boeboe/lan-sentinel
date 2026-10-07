package store_test

import (
	"context"
	"database/sql"
	"io/fs"
	"path/filepath"
	"testing"
	"testing/fstest"

	"lan-sentinel/internal/store"
	"lan-sentinel/migrations"
)

// Migration 0006 marks the latest identification of each host, field and
// source current, as the correlator read them before.
func TestIdentificationCurrentMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.db")
	all, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := fstest.MapFS{}
	for _, n := range all {
		if n < "0006" {
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
	for _, row := range []struct {
		field, value, source string
		last                 int64
	}{
		{"manufacturer", "Siemens AG", "oui", 1},
		{"product", "1756-L71/B", "enip", 2},
		{"product", "1756-L72/B", "enip", 3}, // the latest
		{"device_type", "Programmable Logic Controller", "enip", 2},
	} {
		exec(t, st, `INSERT INTO identifications (host_id, field, value, confidence, source, first_seen, last_seen) VALUES ('h1', ?, ?, 0.9, ?, 0, ?)`,
			row.field, row.value, row.source, row.last)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(ctx, store.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var current string
	if err := st.View(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT group_concat(value, '; ') FROM (SELECT value FROM identifications WHERE current = 1 ORDER BY id)`).Scan(&current)
	}); err != nil {
		t.Fatal(err)
	}
	if current != "Siemens AG; 1756-L72/B; Programmable Logic Controller" {
		t.Errorf("current = %q", current)
	}
}
