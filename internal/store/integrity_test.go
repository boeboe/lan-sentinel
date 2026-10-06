package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/clock"
)

func TestCorruptDatabaseIsQuarantined(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(t *testing.T, path string)
		reason  string
	}{
		{"not a database", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(strings.Repeat("this is not SQLite ", 300)), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "file is not a database"},
		{"damaged page", func(t *testing.T, path string) {
			// A healthy database with data, then garbage over a b-tree page.
			s := open(t, Options{Path: path})
			seed(t, s, addObservations(500, func(int) time.Time { return t0 }, "h1", "10.0.0.1", `{"pad":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}`))
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.WriteAt([]byte(strings.Repeat("\xff", 4096)), 4*4096); err != nil {
				t.Fatal(err)
			}
		}, "check database"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hosts.db")
			tt.corrupt(t, path)
			sim := clock.NewSim(t0)
			s, err := Open(context.Background(), Options{Path: path, Clock: sim})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer s.Close()
			r := s.Recovery()
			if r == nil || !strings.Contains(r.Reason, tt.reason) {
				t.Fatalf("recovery = %+v, want reason containing %q", r, tt.reason)
			}
			if want := path + ".corrupt-20261001T100000Z"; r.QuarantinedTo != want {
				t.Errorf("quarantined to %s, want %s", r.QuarantinedTo, want)
			}
			if _, err := os.Stat(r.QuarantinedTo); err != nil {
				t.Errorf("quarantined file: %v", err)
			}
			if s.SchemaVersion() != 1 {
				t.Errorf("new database schema version = %d", s.SchemaVersion())
			}
		})
	}
}

func TestHealthyDatabaseIsNotQuarantined(t *testing.T) {
	s := open(t, Options{})
	if s.Recovery() != nil {
		t.Errorf("recovery = %+v", s.Recovery())
	}
	path := s.Path()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open(t, Options{Path: path})
	if s.Recovery() != nil {
		t.Errorf("reopen: recovery = %+v", s.Recovery())
	}
}

func TestIsCorrupt(t *testing.T) {
	if isCorrupt(errors.New("permission denied")) || isCorrupt(nil) {
		t.Error("ordinary errors are not corruption")
	}
	if !isCorrupt(corruptError{"page 3"}) || !isCorrupt(codedErr(11|(1<<8))) || !isCorrupt(codedErr(26)) || isCorrupt(codedErr(5)) {
		t.Error("corruption codes misclassified")
	}
	// A rename that fails for another reason than a missing file fails the
	// quarantine.
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.db")
	if err := os.Mkdir(path+".corrupt-20261001T100000Z", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path+".corrupt-20261001T100000Z", "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := quarantine(path, t0); err == nil {
		t.Error("quarantine onto a non-empty directory succeeded")
	}
}

type codedErr int

func (c codedErr) Error() string { return "sqlite error" }
func (c codedErr) Code() int     { return int(c) }
