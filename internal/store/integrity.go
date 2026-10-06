package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

// SQLite primary result codes that mean the file is damaged.
const (
	sqliteCorrupt = 11
	sqliteNotADB  = 26
)

// corruptError is a failed integrity check.
type corruptError struct{ detail string }

func (e corruptError) Error() string { return "integrity check failed: " + e.detail }

// check runs PRAGMA quick_check, which reads every page and verifies the
// b-tree structure without the slower index cross-checks of
// integrity_check.
func (s *Store) check(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, `PRAGMA quick_check(1)`).Scan(&result); err != nil {
		return fmt.Errorf("check database %s: %w", s.path, err)
	}
	if result != "ok" {
		return fmt.Errorf("check database %s: %w", s.path, corruptError{result})
	}
	return nil
}

// isCorrupt reports whether err means the database file is damaged (as
// opposed to, say, missing permissions or a newer schema).
func isCorrupt(err error) bool {
	var ce corruptError
	if errors.As(err, &ce) {
		return true
	}
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		code := coded.Code() & 0xff // primary code of an extended result code
		return code == sqliteCorrupt || code == sqliteNotADB
	}
	return false
}

// quarantine renames a corrupt database and its -wal and -shm files to
// <path>.corrupt-<UTC time>, keeping them together for later inspection,
// and returns the new database name.
func quarantine(path string, now time.Time) (string, error) {
	dst := path + ".corrupt-" + now.UTC().Format("20060102T150405Z")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		err := os.Rename(path+suffix, dst+suffix)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("quarantine corrupt database: %w", err)
		}
	}
	return dst, nil
}
