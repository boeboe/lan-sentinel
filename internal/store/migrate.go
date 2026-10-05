package store

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads NNNN_description.sql files from fsys in version order.
func loadMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	var ms []migration
	seen := map[int]string{}
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".sql" {
			continue
		}
		prefix, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(prefix)
		if !ok || err != nil || v <= 0 {
			return nil, fmt.Errorf("migration %s: name must be NNNN_description.sql", e.Name())
		}
		if other, dup := seen[v]; dup {
			return nil, fmt.Errorf("migrations %s and %s share version %d", other, e.Name(), v)
		}
		seen[v] = e.Name()
		body, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", e.Name(), err)
		}
		ms = append(ms, migration{version: v, name: e.Name(), sql: string(body)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	return ms, nil
}

// migrate applies every migration newer than the database's schema version,
// each in its own transaction. It refuses a database written by a newer
// binary.
func migrate(ctx context.Context, db *sql.DB, ms []migration, now func() time.Time) (int, error) {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	) STRICT`); err != nil {
		return 0, fmt.Errorf("create schema_migrations: %w", err)
	}
	current, err := schemaVersion(ctx, db)
	if err != nil {
		return 0, err
	}
	latest := 0
	if len(ms) > 0 {
		latest = ms[len(ms)-1].version
	}
	if current > latest {
		return current, fmt.Errorf("database schema version %d is newer than this binary supports (%d)", current, latest)
	}
	for _, m := range ms {
		if m.version <= current {
			continue
		}
		if err := applyMigration(ctx, db, m, now); err != nil {
			return current, err
		}
		current = m.version
	}
	return current, nil
}

func applyMigration(ctx context.Context, db *sql.DB, m migration, now func() time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migration %s: %w", m.name, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return fmt.Errorf("migration %s: %w", m.name, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		m.version, now().UnixMilli()); err != nil {
		return fmt.Errorf("migration %s: record version: %w", m.name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %s: commit: %w", m.name, err)
	}
	return nil
}

func schemaVersion(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (int, error) {
	var v int
	if err := q.QueryRowContext(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return v, nil
}
