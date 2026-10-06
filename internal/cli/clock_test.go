package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/store"
)

// Events written before the clock was synchronised are flagged in tables
// and carry their state in CSV (NFR-REL-2).
func TestEventClockMarks(t *testing.T) {
	ts := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	evs := []store.Event{
		{TS: ts, Type: "HOST_DISCOVERED", Cause: "passive_arp", ClockSync: "synced"},
		{TS: ts, Type: "IP_ADDED", Cause: "passive_arp", ClockSync: "unsynced"},
		{TS: ts, Type: "IP_CHANGED", Cause: "passive_dhcp", ClockSync: "unknown"},
	}
	run := func(format string) string {
		var buf bytes.Buffer
		a := &app{env: Env{Stdout: &buf, Location: time.UTC}, g: globals{output: format}}
		if err := a.eventsTable(evs); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	table := run("table")
	for _, want := range []string{
		"2026-10-01 10:00:00   HOST_DISCOVERED", "2026-10-01 10:00:00*  IP_ADDED", "2026-10-01 10:00:00?  IP_CHANGED",
		"* written before the system clock was synchronised", "? written while the clock's synchronisation was unknown",
	} {
		if !strings.Contains(table, want) {
			t.Errorf("table lacks %q:\n%s", want, table)
		}
	}
	if synced := run("table"); strings.Contains(strings.Split(synced, "\n")[1], "*") {
		t.Errorf("a synced event is marked:\n%s", synced)
	}
	csv := run("csv")
	if !strings.Contains(csv, ",CLOCK_SYNC\n") || !strings.Contains(csv, ",passive_arp,unsynced\n") {
		t.Errorf("csv:\n%s", csv)
	}
}
