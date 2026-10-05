// Package golden holds the golden correlator scenarios. Each scenario is a
// JSONL observation stream (the replay format, docs/DATA_MODEL.md §2) and
// the expected bindings, events and CLI query answers.
//
// The test validates each fixture (syntax, and that its expected query
// answers follow from its expected bindings under docs/DATA_MODEL.md §3–§4),
// then runs the stream through the correlator and compares the database
// with the expectations (correlate_test.go).
package golden

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"

	"lan-sentinel/internal/events"
	"lan-sentinel/internal/observation"
)

// Expected is a scenario's expected outcome.
type Expected struct {
	Description string            `json:"description"`
	Interface   string            `json:"interface"`
	Prefixes    []string          `json:"prefixes"`
	Hosts       map[string]string `json:"hosts"` // label -> MAC
	Bindings    []Binding         `json:"bindings"`
	Events      []Event           `json:"events"`
	Unbound     int               `json:"unbound_observations"`
	Queries     []Query           `json:"queries"`
	History     []History         `json:"history"`
}

// Binding is an expected address binding at the end of the stream.
type Binding struct {
	Host      string     `json:"host"`
	IP        string     `json:"ip"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	EndedAt   *time.Time `json:"ended_at"`
	Conflict  bool       `json:"conflict"`
}

// Event is an expected event, in order.
type Event struct {
	TS         time.Time `json:"ts"`
	Type       string    `json:"type"`
	Host       string    `json:"host"`
	Related    string    `json:"related,omitempty"`
	Old        string    `json:"old,omitempty"`
	New        string    `json:"new,omitempty"`
	Cause      string    `json:"cause"`
	EvidenceIP string    `json:"evidence_ip,omitempty"`
}

// Query is an expected `hosts find <ip> --at` answer.
type Query struct {
	Find     string     `json:"find"`
	At       time.Time  `json:"at"`
	Holders  []Holder   `json:"holders"`
	Conflict bool       `json:"conflict"`
	Previous *Neighbour `json:"previous,omitempty"`
	Next     *Neighbour `json:"next,omitempty"`
}

// Holder is one host holding the queried IP at the queried time.
type Holder struct {
	Host        string     `json:"host"`
	FirstSeen   time.Time  `json:"first_seen"`
	EndedAt     *time.Time `json:"ended_at"`
	Unconfirmed bool       `json:"unconfirmed"`
}

// Neighbour is the binding before or after a gap: the holder and when its
// binding ended (previous) or started (next).
type Neighbour struct {
	Host string    `json:"host"`
	At   time.Time `json:"at"`
}

// History is an expected `hosts history <ip>` answer, as indexes into Events.
type History struct {
	IP     string `json:"ip"`
	Events []int  `json:"events"`
}

func TestScenarios(t *testing.T) {
	dirs, err := filepath.Glob("*/expected.json")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no scenarios found: %v", err)
	}
	for _, p := range dirs {
		dir := filepath.Dir(p)
		t.Run(dir, func(t *testing.T) {
			obs := readObservations(t, filepath.Join(dir, "observations.jsonl"))
			exp := readExpected(t, p)
			t.Run("observations", func(t *testing.T) { checkObservations(t, obs, exp) })
			t.Run("expected", func(t *testing.T) { checkExpected(t, exp) })
			t.Run("queries follow from bindings", func(t *testing.T) { checkQueries(t, exp) })
			t.Run("history follows from events", func(t *testing.T) { checkHistory(t, exp) })
			t.Run("correlator", func(t *testing.T) { runCorrelator(t, obs, exp) })
		})
	}
}

func readObservations(t *testing.T, path string) []observation.Observation {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []observation.Observation
	if err := observation.ReadJSONL(f, func(o observation.Observation) error {
		out = append(out, o)
		return nil
	}); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

func readExpected(t *testing.T, path string) Expected {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var e Expected
	if err := dec.Decode(&e); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return e
}

func checkObservations(t *testing.T, obs []observation.Observation, exp Expected) {
	var prev time.Time
	for i, o := range obs {
		where := fmt.Sprintf("observation %d", i+1)
		if o.Time.Before(prev) {
			t.Errorf("%s: time %s goes backwards", where, o.Time)
		}
		prev = o.Time
		if o.Interface != exp.Interface {
			t.Errorf("%s: interface %q, scenario uses %q", where, o.Interface, exp.Interface)
		}
	}
}

func checkExpected(t *testing.T, e Expected) {
	labels := map[string]bool{}
	for l, mac := range e.Hosts {
		labels[l] = true
		if _, err := net.ParseMAC(mac); err != nil {
			t.Errorf("host %s: %v", l, err)
		}
	}
	for i, b := range e.Bindings {
		switch {
		case !labels[b.Host]:
			t.Errorf("binding %d: unknown host %q", i, b.Host)
		case b.LastSeen.Before(b.FirstSeen):
			t.Errorf("binding %d: last_seen before first_seen", i)
		case b.EndedAt != nil && b.EndedAt.Before(b.FirstSeen):
			t.Errorf("binding %d: ended_at before first_seen", i)
		}
	}
	var prev time.Time
	for i, ev := range e.Events {
		if _, ok := events.Lookup(events.Type(ev.Type)); !ok {
			t.Errorf("event %d: unknown type %q", i, ev.Type)
		}
		if !labels[ev.Host] || (ev.Related != "" && !labels[ev.Related]) {
			t.Errorf("event %d: unknown host label", i)
		}
		if ev.TS.Before(prev) {
			t.Errorf("event %d: out of order", i)
		}
		prev = ev.TS
	}
}

// pointInTime implements the query semantics of DATA_MODEL.md §4 over the
// expected bindings.
func pointInTime(bs []Binding, ip string, at time.Time) (holders []Binding, prev, next *Binding) {
	for i := range bs {
		b := bs[i]
		if b.IP != ip {
			continue
		}
		inEffect := !b.FirstSeen.After(at) && (b.EndedAt == nil || b.EndedAt.After(at))
		switch {
		case inEffect:
			holders = append(holders, b)
		case b.EndedAt != nil && !b.EndedAt.After(at):
			if prev == nil || b.EndedAt.After(*prev.EndedAt) {
				prev = &bs[i]
			}
		case b.FirstSeen.After(at):
			if next == nil || b.FirstSeen.Before(next.FirstSeen) {
				next = &bs[i]
			}
		}
	}
	sort.Slice(holders, func(i, j int) bool { return holders[i].Host < holders[j].Host })
	return holders, prev, next
}

func checkQueries(t *testing.T, e Expected) {
	for _, q := range e.Queries {
		name := fmt.Sprintf("find %s --at %s", q.Find, q.At.Format(time.RFC3339))
		holders, prev, next := pointInTime(e.Bindings, q.Find, q.At)
		if len(holders) != len(q.Holders) {
			t.Errorf("%s: bindings give %d holders, expected.json says %d", name, len(holders), len(q.Holders))
			continue
		}
		if (len(holders) >= 2) != q.Conflict {
			t.Errorf("%s: conflict = %v, but %d holders", name, q.Conflict, len(holders))
		}
		for i, h := range q.Holders {
			b := holders[i]
			unconfirmed := q.At.After(b.LastSeen)
			if h.Host != b.Host || !h.FirstSeen.Equal(b.FirstSeen) || !sameTime(h.EndedAt, b.EndedAt) || h.Unconfirmed != unconfirmed {
				t.Errorf("%s: holder %d = %+v, bindings give host %s from %s ended %v unconfirmed %v",
					name, i, h, b.Host, b.FirstSeen, b.EndedAt, unconfirmed)
			}
		}
		if len(holders) == 0 {
			if !neighbourMatches(q.Previous, prev, true) {
				t.Errorf("%s: previous = %+v, bindings give %+v", name, q.Previous, prev)
			}
			if !neighbourMatches(q.Next, next, false) {
				t.Errorf("%s: next = %+v, bindings give %+v", name, q.Next, next)
			}
		}
	}
}

func neighbourMatches(n *Neighbour, b *Binding, previous bool) bool {
	if n == nil || b == nil {
		return n == nil && b == nil
	}
	at := b.FirstSeen
	if previous {
		at = *b.EndedAt
	}
	return n.Host == b.Host && n.At.Equal(at)
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// checkHistory applies the IP-history definition of CLI.md §4: events whose
// old value, new value or evidence IP is the IP.
func checkHistory(t *testing.T, e Expected) {
	for _, h := range e.History {
		var got []int
		for i, ev := range e.Events {
			if ev.Old == h.IP || ev.New == h.IP || ev.EvidenceIP == h.IP {
				got = append(got, i)
			}
		}
		if !slices.Equal(got, h.Events) {
			t.Errorf("history %s: events %v, expected.json says %v", h.IP, got, h.Events)
		}
	}
}
