package events

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io/fs"
	"log/slog"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/store"
	"lan-sentinel/migrations"
)

// The catalogue must match the CHECK constraint on events.type, as the
// last migration that (re)creates the table defines it.
func TestCatalogueMatchesSchema(t *testing.T) {
	files, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	var block [][]byte
	for _, name := range files {
		sql, err := migrations.FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if m := regexp.MustCompile(`(?s)type\s+TEXT\s+NOT NULL CHECK \(type IN \((.*?)\)\)`).FindSubmatch(sql); m != nil {
			block = m
		}
	}
	if block == nil {
		t.Fatal("events.type CHECK constraint not found")
	}
	var schema []string
	for _, m := range regexp.MustCompile(`'([A-Z_]+)'`).FindAllSubmatch(block[1], -1) {
		schema = append(schema, string(m[1]))
	}
	var cat []string
	for _, s := range All() {
		cat = append(cat, string(s.Type))
		if got, ok := ByCLIName(s.CLIName); !ok || got != s.Type {
			t.Errorf("ByCLIName(%q) = %q, %v", s.CLIName, got, ok)
		}
	}
	sort.Strings(schema)
	if strings.Join(cat, ",") != strings.Join(schema, ",") {
		t.Errorf("catalogue %v\nschema    %v", cat, schema)
	}
}

func TestEmitWritesRowAndLogEntry(t *testing.T) {
	st, err := store.Open(context.Background(), store.Options{Path: filepath.Join(t.TempDir(), "hosts.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e := NewEngine(st, log, func() platform.ClockState { return platform.ClockUnsynced })

	ts := time.Date(2026, 10, 1, 11, 0, 0, 0, time.UTC)
	err = e.Emit(context.Background(), Event{
		TS: ts, Type: IPChanged, Interface: "eth1", MAC: "00:1b:1b:aa:bb:01",
		Old: "192.168.110.50", New: "192.168.110.51", Cause: "passive_dhcp",
		Evidence: Evidence{TS: ts, Source: "passive_dhcp", IP: "192.168.110.51"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Emit(context.Background(), Event{Type: "NOT_A_TYPE"}); err == nil {
		t.Error("unknown type accepted")
	}
	if err := st.Flush(context.Background()); err != nil || st.OpErrors() != 0 {
		t.Fatalf("flush: %v, %d failed writes", err, st.OpErrors())
	}

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log entry %q: %v", buf.String(), err)
	}
	for k, want := range map[string]any{
		"msg":   "IP_CHANGED eth1 00:1b:1b:aa:bb:01 192.168.110.50 -> 192.168.110.51",
		"event": "ip_changed", "iface": "eth1", "old_value": "192.168.110.50", "new_value": "192.168.110.51",
		"source": "passive_dhcp", "clock_sync": "unsynced",
	} {
		if rec[k] != want {
			t.Errorf("log %s = %v, want %v", k, rec[k], want)
		}
	}
	if got := message(Event{Type: HostDiscovered, Interface: "eth1", MAC: "00:1b:1b:aa:bb:01", New: "00:1b:1b:aa:bb:01",
		Evidence: Evidence{IP: "192.168.110.50"}}); got != "HOST_DISCOVERED eth1 00:1b:1b:aa:bb:01 192.168.110.50" {
		t.Errorf("discovery message = %q", got)
	}
	if c := e.Counts()[IPChanged]; c != 1 {
		t.Errorf("count = %d", c)
	}
	var clock string
	if err := st.View(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT clock_sync FROM events`).Scan(&clock)
	}); err != nil || clock != "unsynced" {
		t.Errorf("clock_sync = %q, %v", clock, err)
	}
}

// The clock state is recorded with every event, and logged unless synced;
// without a clock source it is unknown, never assumed synchronised.
func TestClockStateOfEvents(t *testing.T) {
	for _, tt := range []struct {
		name   string
		clock  func() platform.ClockState
		want   string
		logged bool
	}{
		{"synced", func() platform.ClockState { return platform.ClockSynced }, "synced", false},
		{"unsynced", func() platform.ClockState { return platform.ClockUnsynced }, "unsynced", true},
		{"no clock source", nil, "unknown", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st, err := store.Open(context.Background(), store.Options{Path: filepath.Join(t.TempDir(), "hosts.db")})
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			var buf bytes.Buffer
			e := NewEngine(st, slog.New(slog.NewJSONHandler(&buf, nil)), tt.clock)
			ch, cancel := e.Subscribe(1)
			defer cancel()
			ts := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
			if err := e.Emit(context.Background(), Event{TS: ts, Type: InterfaceUp, Interface: "eth1", New: "up", Cause: "iface_monitor"}); err != nil {
				t.Fatal(err)
			}
			if got := (<-ch).ClockSync; got != tt.want {
				t.Errorf("streamed clock_sync = %q", got)
			}
			if logged := strings.Contains(buf.String(), `"clock_sync":"`+tt.want+`"`); logged != tt.logged {
				t.Errorf("log %s, want clock_sync logged %v", buf.String(), tt.logged)
			}
		})
	}
}

func TestSubscribe(t *testing.T) {
	st, err := store.Open(context.Background(), store.Options{Path: filepath.Join(t.TempDir(), "hosts.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	e := NewEngine(st, slog.New(slog.DiscardHandler), func() platform.ClockState { return platform.ClockUnsynced })
	ch, cancel := e.Subscribe(1)
	ctx := context.Background()
	ts := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	ev := Event{TS: ts, Type: InterfaceUp, Interface: "eth1", New: "up", Cause: "iface_monitor", Evidence: Evidence{TS: ts, Interface: "eth1"}}
	if err := e.Emit(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if err := e.Emit(ctx, ev); err != nil { // the buffer of 1 is full: missed
		t.Fatal(err)
	}
	got := <-ch
	if got.Type != "INTERFACE_UP" || got.Severity != "notice" || got.Interface != "eth1" || got.ClockSync != "unsynced" ||
		!strings.Contains(string(got.Evidence), `"interface":"eth1"`) {
		t.Errorf("streamed event = %+v", got)
	}
	if e.Missed() != 1 {
		t.Errorf("missed = %d, want 1", e.Missed())
	}
	cancel()
	cancel() // idempotent
	if _, ok := <-ch; ok {
		t.Error("channel open after cancel")
	}
	if err := e.Emit(ctx, ev); err != nil {
		t.Fatal(err)
	}
}
