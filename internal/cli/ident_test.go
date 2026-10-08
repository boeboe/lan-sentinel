package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/store"
)

// The Identification block: sources by their confidence, then by last seen
// (in show only the current claims count, so mdns drops behind), then by
// name; within a source by field, the current claim first. evidence
// shows every claim's confidence, which is why one claim is current and a
// weaker one is not; show lists only current claims, with a confidence only
// where it differs from its source's.
func TestIdentificationBlock(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	a := &app{env: Env{Now: func() time.Time { return now }, Location: time.UTC}}
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	ev := json.RawMessage(`{"k":"v"}`)
	ids := []store.Identification{
		{Source: "oui", Field: "manufacturer", Value: "Siemens AG", Confidence: 0.7, LastSeen: ago(3 * time.Hour), Current: true, Evidence: ev},
		{Source: "mdns", Field: "device_type", Value: "Media player", Confidence: 0.6, LastSeen: ago(time.Hour), Evidence: ev},
		{Source: "mdns", Field: "device_type", Value: "Printer", Confidence: 0.7, LastSeen: ago(5 * time.Hour), Current: true, Evidence: ev},
		{Source: "mdns", Field: "model", Value: "LaserJet", Confidence: 0.5, LastSeen: ago(5 * time.Hour), Current: true, Evidence: ev},
		{Source: "modbus", Field: "vendor", Value: "ACME", Confidence: 0.95, LastSeen: ago(time.Minute), Current: true, Evidence: ev},
		{Source: "lldp", Field: "device_type", Value: "Switch", Confidence: 0.7, LastSeen: ago(2 * time.Hour), Current: true, Evidence: ev},
	}

	var b bytes.Buffer
	a.printIdentifications(&b, ids, identPrint{markCurrent: true, everyConfidence: true, withEvidence: true})
	want := []string{
		"",
		"Identification:",
		"  modbus  (0.95)  1m ago",
		"    *vendor        ACME          (0.95)  {\"k\":\"v\"}",
		"  mdns    (0.70)  1h ago",
		"    *device_type   Printer       (0.70)  {\"k\":\"v\"}",
		"     device_type   Media player  (0.60)  {\"k\":\"v\"}",
		"    *model         LaserJet      (0.50)  {\"k\":\"v\"}",
		"  lldp    (0.70)  2h ago",
		"    *device_type   Switch        (0.70)  {\"k\":\"v\"}",
		"  oui     (0.70)  3h ago",
		"    *manufacturer  Siemens AG    (0.70)  {\"k\":\"v\"}",
		"  (* current: the value each source holds now)",
	}
	if got := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("evidence block:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	b.Reset()
	a.printIdentifications(&b, ids, identPrint{currentOnly: true})
	want = []string{
		"",
		"Identification:",
		"  modbus  (0.95)  1m ago",
		"    vendor        ACME",
		"  lldp    (0.70)  2h ago",
		"    device_type   Switch",
		"  oui     (0.70)  3h ago",
		"    manufacturer  Siemens AG",
		"  mdns    (0.70)  5h ago",
		"    device_type   Printer",
		"    model         LaserJet    (0.50)",
	}
	if got := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("show block:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	b.Reset()
	a.printIdentifications(&b, nil, identPrint{})
	if b.Len() != 0 {
		t.Errorf("no claims printed %q", b.String())
	}
}
