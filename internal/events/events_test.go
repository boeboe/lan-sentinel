package events

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/store"
	"lan-sentinel/migrations"
)

// The catalogue must match the CHECK constraint on events.type.
func TestCatalogueMatchesSchema(t *testing.T) {
	sql, err := migrations.FS.ReadFile("0001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)type\s+TEXT\s+NOT NULL CHECK \(type IN \((.*?)\)\)`).FindSubmatch(sql)
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
	e := NewEngine(st, log, func() bool { return false })

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
		"source": "passive_dhcp", "clock_synced": false,
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
}

func TestSubscribe(t *testing.T) {
	st, err := store.Open(context.Background(), store.Options{Path: filepath.Join(t.TempDir(), "hosts.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	e := NewEngine(st, slog.New(slog.DiscardHandler), func() bool { return false })
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
	if got.Type != "INTERFACE_UP" || got.Severity != "notice" || got.Interface != "eth1" || got.ClockSynced ||
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
