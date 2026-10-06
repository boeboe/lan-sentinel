package golden

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/correlate"
	"lan-sentinel/internal/events"
	"lan-sentinel/internal/identify"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/store"
)

// pointInTimeSQL is the query of docs/DATA_MODEL.md §4, as `hosts find
// --at` runs it.
const pointInTimeSQL = `
SELECT h.host_id, a.first_seen, a.last_seen, a.ended_at
FROM addresses a
JOIN network_contexts c ON c.id = a.context_id
JOIN hosts h ON h.host_id = a.host_id
WHERE c.interface = ? AND a.ip = ? AND a.first_seen <= ? AND (a.ended_at IS NULL OR a.ended_at > ?)
ORDER BY a.last_seen DESC`

// historySQL is the IP history of docs/CLI.md §4.
const historySQL = `
SELECT ts, type, host_id FROM events
WHERE old_value = ? OR new_value = ? OR json_extract(evidence_json, '$.ip') = ?
ORDER BY id`

// runCorrelator replays the stream through the correlator into a fresh
// database and compares bindings, events, the unbound count and the query
// answers with the scenario's expectations; then it compacts the database
// as it would be a week later and checks that every answer and every
// event's evidence is unchanged (docs/DATA_MODEL.md §10).
func runCorrelator(t *testing.T, obs []observation.Observation, exp Expected) {
	ctx := context.Background()
	start := obs[0].Time
	sim := clock.NewSim(start)
	st, err := store.Open(ctx, store.Options{Path: filepath.Join(t.TempDir(), "hosts.db"), Clock: sim})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := config.Defaults()
	var prefixes []netip.Prefix
	for _, p := range exp.Prefixes {
		prefixes = append(prefixes, netip.MustParsePrefix(p))
	}
	cfg.Interfaces = []config.InterfaceConfig{{Name: exp.Interface, Prefixes: prefixes, Replay: &config.InterfaceReplay{File: "observations.jsonl"}}}
	vendors, err := identify.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	c, err := correlate.New(ctx, correlate.Options{
		Store: st, Events: events.NewEngine(st, log, nil), Vendors: vendors, Clock: sim,
		Logger: log, Config: cfg, DataDriven: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Handle(ctx, observation.Message{Link: &observation.LinkState{Time: start, Interface: exp.Interface, Present: true, Up: true, Prefixes: prefixes}})
	for _, o := range obs {
		sim.Set(o.Time)
		c.Handle(ctx, observation.Message{Observation: o})
	}
	if err := st.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if st.OpErrors() != 0 {
		t.Fatalf("%d store writes failed", st.OpErrors())
	}

	check := func(t *testing.T) {
		err := st.View(ctx, func(ctx context.Context, tx *sql.Tx) error {
			labels := hostLabels(t, ctx, tx, exp)
			compareBindings(t, ctx, tx, exp, labels)
			compareEvents(t, ctx, tx, exp, labels)
			compareQueries(t, ctx, tx, exp, labels)
			compareHistory(t, ctx, tx, exp, labels)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Run("answers", check)
	if got := c.Unbound(); got != uint64(exp.Unbound) {
		t.Errorf("unbound observations = %d, want %d", got, exp.Unbound)
	}

	eventsBefore := dump(t, st, `SELECT * FROM events ORDER BY id`)
	stored := dump(t, st, `SELECT count(*) FROM observations`)
	week := 7 * 24 * time.Hour
	res, err := st.Compact(ctx, store.Retention{Observations: week, Rollups: 90 * 24 * time.Hour, Events: 730 * 24 * time.Hour},
		obs[len(obs)-1].Time.Add(week+time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("answers after 7-day compaction", check)
	if fmt.Sprint(res.RolledUp) != stored[0] || dump(t, st, `SELECT count(*) FROM observations`)[0] != "0" ||
		dump(t, st, `SELECT sum(count) FROM observation_rollups`)[0] != stored[0] {
		t.Errorf("compaction rolled up %d of %s observations", res.RolledUp, stored[0])
	}
	if after := dump(t, st, `SELECT * FROM events ORDER BY id`); strings.Join(after, "\n") != strings.Join(eventsBefore, "\n") {
		t.Errorf("events changed by compaction:\nbefore %v\nafter  %v", eventsBefore, after)
	}
}

// dump renders every row of a query as text.
func dump(t *testing.T, st *store.Store, query string) []string {
	t.Helper()
	var out []string
	err := st.View(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		defer rows.Close()
		cols, err := rows.Columns()
		if err != nil {
			return err
		}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				return err
			}
			parts := make([]string, len(vals))
			for i, v := range vals {
				parts[i] = fmt.Sprint(v)
			}
			out = append(out, strings.Join(parts, "|"))
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func atMS(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.UnixMilli(v.Int64).UTC()
	return &t
}

// hostLabels maps host ids to the scenario's labels via their MACs.
func hostLabels(t *testing.T, ctx context.Context, tx *sql.Tx, exp Expected) map[string]string {
	byMAC := map[string]string{}
	for label, mac := range exp.Hosts {
		byMAC[mac] = label
	}
	rows, err := tx.QueryContext(ctx, `SELECT host_id, mac FROM hosts`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	labels := map[string]string{}
	for rows.Next() {
		var id, mac string
		if err := rows.Scan(&id, &mac); err != nil {
			t.Fatal(err)
		}
		label, ok := byMAC[mac]
		if !ok {
			t.Errorf("unexpected host with MAC %s", mac)
		}
		labels[id] = label
	}
	if len(labels) != len(exp.Hosts) {
		t.Errorf("%d hosts, want %d", len(labels), len(exp.Hosts))
	}
	return labels
}

func compareBindings(t *testing.T, ctx context.Context, tx *sql.Tx, exp Expected, labels map[string]string) {
	rows, err := tx.QueryContext(ctx, `SELECT host_id, ip, first_seen, last_seen, ended_at, conflict FROM addresses`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type row struct {
		host, ip    string
		first, last int64
		ended       sql.NullInt64
		conflict    bool
	}
	got := map[string]row{}
	for rows.Next() {
		var r row
		var id string
		var conflict int
		if err := rows.Scan(&id, &r.ip, &r.first, &r.last, &r.ended, &conflict); err != nil {
			t.Fatal(err)
		}
		r.host, r.conflict = labels[id], conflict == 1
		got[r.host+" "+r.ip+" "+time.UnixMilli(r.first).UTC().Format(time.RFC3339)] = r
	}
	if len(got) != len(exp.Bindings) {
		t.Errorf("%d bindings, want %d: %+v", len(got), len(exp.Bindings), got)
	}
	for _, b := range exp.Bindings {
		key := b.Host + " " + b.IP + " " + b.FirstSeen.Format(time.RFC3339)
		r, ok := got[key]
		if !ok {
			t.Errorf("binding %s missing", key)
			continue
		}
		if r.last != ms(b.LastSeen) || !sameTime(atMS(r.ended), b.EndedAt) || r.conflict != b.Conflict {
			t.Errorf("binding %s: last_seen %s ended_at %v conflict %v; want %s %v %v", key,
				time.UnixMilli(r.last).UTC().Format(time.RFC3339), atMS(r.ended), r.conflict, b.LastSeen.Format(time.RFC3339), b.EndedAt, b.Conflict)
		}
	}
}

func compareEvents(t *testing.T, ctx context.Context, tx *sql.Tx, exp Expected, labels map[string]string) {
	// Host events only: context events (SUBNET_CHANGED from the replay's
	// prefixes) are not part of the scenario.
	rows, err := tx.QueryContext(ctx, `SELECT ts, type, host_id, coalesce(related_host_id, ''), coalesce(old_value, ''),
		coalesce(new_value, ''), cause, evidence_json FROM events WHERE host_id IS NOT NULL ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []Event
	for rows.Next() {
		var e Event
		var ts int64
		var host, related, evidence string
		if err := rows.Scan(&ts, &e.Type, &host, &related, &e.Old, &e.New, &e.Cause, &evidence); err != nil {
			t.Fatal(err)
		}
		e.TS, e.Host, e.Related = time.UnixMilli(ts).UTC(), labels[host], labels[related]
		var ev events.Evidence
		if err := json.Unmarshal([]byte(evidence), &ev); err != nil {
			t.Fatal(err)
		}
		e.EvidenceIP = ev.IP
		got = append(got, e)
	}
	if len(got) != len(exp.Events) {
		t.Errorf("%d events, want %d", len(got), len(exp.Events))
	}
	for i := range min(len(got), len(exp.Events)) {
		g, w := got[i], exp.Events[i]
		if !g.TS.Equal(w.TS) || g.Type != w.Type || g.Host != w.Host || g.Related != w.Related ||
			g.Old != w.Old || g.New != w.New || g.Cause != w.Cause || g.EvidenceIP != w.EvidenceIP {
			t.Errorf("event %d:\n got  %+v\n want %+v", i, g, w)
		}
	}
}

func compareQueries(t *testing.T, ctx context.Context, tx *sql.Tx, exp Expected, labels map[string]string) {
	for _, q := range exp.Queries {
		rows, err := tx.QueryContext(ctx, pointInTimeSQL, exp.Interface, q.Find, ms(q.At), ms(q.At))
		if err != nil {
			t.Fatal(err)
		}
		var got []Holder
		for rows.Next() {
			var id string
			var first, last int64
			var ended sql.NullInt64
			if err := rows.Scan(&id, &first, &last, &ended); err != nil {
				t.Fatal(err)
			}
			got = append(got, Holder{Host: labels[id], FirstSeen: time.UnixMilli(first).UTC(), EndedAt: atMS(ended), Unconfirmed: ms(q.At) > last})
		}
		rows.Close()
		sort.Slice(got, func(i, j int) bool { return got[i].Host < got[j].Host })
		name := "find " + q.Find + " --at " + q.At.Format(time.RFC3339)
		if len(got) != len(q.Holders) || (len(got) >= 2) != q.Conflict {
			t.Errorf("%s: %d holders %+v, want %+v", name, len(got), got, q.Holders)
			continue
		}
		for i, h := range q.Holders {
			g := got[i]
			if g.Host != h.Host || !g.FirstSeen.Equal(h.FirstSeen) || !sameTime(g.EndedAt, h.EndedAt) || g.Unconfirmed != h.Unconfirmed {
				t.Errorf("%s: holder %d = %+v, want %+v", name, i, g, h)
			}
		}
	}
}

func compareHistory(t *testing.T, ctx context.Context, tx *sql.Tx, exp Expected, labels map[string]string) {
	for _, h := range exp.History {
		rows, err := tx.QueryContext(ctx, historySQL, h.IP, h.IP, h.IP)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for rows.Next() {
			var ts int64
			var typ, host string
			if err := rows.Scan(&ts, &typ, &host); err != nil {
				t.Fatal(err)
			}
			got = append(got, time.UnixMilli(ts).UTC().Format(time.RFC3339)+" "+typ+" "+labels[host])
		}
		rows.Close()
		var want []string
		for _, i := range h.Events {
			e := exp.Events[i]
			want = append(want, e.TS.Format(time.RFC3339)+" "+e.Type+" "+e.Host)
		}
		if len(got) != len(want) {
			t.Errorf("history %s: %v, want %v", h.IP, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("history %s[%d] = %s, want %s", h.IP, i, got[i], want[i])
			}
		}
	}
}
