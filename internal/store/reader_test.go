package store_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/store"
	"lan-sentinel/internal/store/storetest"
)

var t0 = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

type expected = storetest.Expected

func seed(t *testing.T) (*store.Store, string, expected) {
	t.Helper()
	return storetest.Seed(t, golden)
}

const golden = "../../test/golden/reconstruction/"

func reader(t *testing.T, st *store.Store) *store.Reader {
	t.Helper()
	r, err := st.Reader(168 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func label(exp expected, mac string) string {
	for l, m := range exp.Hosts {
		if m == mac {
			return l
		}
	}
	return mac
}

// The golden point-in-time queries answered by Find.
func TestFindGoldenQueries(t *testing.T) {
	st, _, exp := seed(t)
	r := reader(t, st)
	for _, q := range exp.Queries {
		at := q.At
		res, err := r.Find(context.Background(), store.FindQuery{Query: q.Find, Interface: "eth1", At: &at})
		if err != nil {
			t.Fatal(err)
		}
		name := q.Find + " at " + at.Format(time.RFC3339)
		if res.Kind != store.KindIP || len(res.Hosts) != len(q.Holders) {
			t.Errorf("%s: %d holders, want %d", name, len(res.Hosts), len(q.Holders))
			continue
		}
		got := map[string]store.FoundHost{}
		for _, h := range res.Hosts {
			got[label(exp, h.MAC)] = h
			if h.Conflict != q.Conflict {
				t.Errorf("%s: conflict %v, want %v", name, h.Conflict, q.Conflict)
			}
			if q.Conflict && (h.ConflictEvent == nil || h.ConflictEvent.Type != "DUPLICATE_IP_DETECTED") {
				t.Errorf("%s: conflict event = %+v", name, h.ConflictEvent)
			}
		}
		for _, w := range q.Holders {
			h, ok := got[w.Host]
			if !ok {
				t.Errorf("%s: holder %s missing", name, w.Host)
				continue
			}
			endOK := (h.Binding.EndedAt == nil) == (w.EndedAt == nil) && (w.EndedAt == nil || h.Binding.EndedAt.Equal(*w.EndedAt))
			if !h.Binding.FirstSeen.Equal(w.FirstSeen) || !endOK || h.Unconfirmed != w.Unconfirmed {
				t.Errorf("%s: holder %s = %+v unconfirmed %v, want %+v", name, w.Host, h.Binding, h.Unconfirmed, w)
			}
		}
		if q.Previous != nil && (len(res.Previous) != 1 || label(exp, res.Previous[0].MAC) != q.Previous.Host ||
			!res.Previous[0].Binding.EndedAt.Equal(q.Previous.At)) {
			t.Errorf("%s: previous = %+v, want %+v", name, res.Previous, q.Previous)
		}
		if q.Next != nil && (len(res.Next) != 1 || label(exp, res.Next[0].MAC) != q.Next.Host ||
			!res.Next[0].Binding.FirstSeen.Equal(q.Next.At)) {
			t.Errorf("%s: next = %+v, want %+v", name, res.Next, q.Next)
		}
	}
}

// Replaced-by and moved-to: at T0+30m X is A's, later B's, and A moved to Y.
func TestFindReplacedBy(t *testing.T) {
	st, _, exp := seed(t)
	r := reader(t, st)
	at := t0.Add(30 * time.Minute)
	res, err := r.Find(context.Background(), store.FindQuery{Query: "192.168.110.50", At: &at})
	if err != nil || len(res.Hosts) != 1 {
		t.Fatalf("find: %v %+v", err, res)
	}
	h := res.Hosts[0]
	if h.ReplacedBy == nil || label(exp, h.ReplacedBy.MAC) != "B" || !h.ReplacedBy.Binding.FirstSeen.Equal(t0.Add(2*time.Hour)) {
		t.Errorf("replaced by = %+v", h.ReplacedBy)
	}
	if h.MovedTo == nil || h.MovedTo.Binding.IP != "192.168.110.51" || !h.MovedTo.Binding.FirstSeen.Equal(t0.Add(time.Hour)) {
		t.Errorf("moved to = %+v", h.MovedTo)
	}
	if len(h.Addresses) != 1 || h.Addresses[0].IP != "192.168.110.50" || len(h.Addresses[0].Sources) == 0 {
		t.Errorf("addresses in effect at T0+30m = %+v", h.Addresses)
	}
}

func TestFindCurrentAndOtherKinds(t *testing.T) {
	st, _, exp := seed(t)
	r := reader(t, st)
	ctx := context.Background()
	res, err := r.Find(ctx, store.FindQuery{Query: "192.168.110.50"})
	if err != nil || len(res.Hosts) != 1 || label(exp, res.Hosts[0].MAC) != "B" || res.Hosts[0].Binding.EndedAt != nil {
		t.Fatalf("current holder of X: %v %+v", err, res.Hosts)
	}
	if res.Hosts[0].PreferredName != "plc-b.local" || len(res.Hosts[0].Names) != 1 || res.Hosts[0].Names[0].Stale {
		t.Errorf("names of B = %q %+v", res.Hosts[0].PreferredName, res.Hosts[0].Names)
	}
	// MAC in its dash and dot forms; the addresses in effect at a time.
	at := t0.Add(150 * time.Minute)
	for _, q := range []string{"00-1b-1b-aa-bb-01", "001b.1baa.bb01"} {
		res, err = r.Find(ctx, store.FindQuery{Query: q, At: &at})
		if err != nil || res.Kind != store.KindMAC || len(res.Hosts) != 1 || len(res.Hosts[0].Addresses) != 1 ||
			res.Hosts[0].Addresses[0].IP != "192.168.110.51" {
			t.Errorf("find %s at T0+150m: %v %+v", q, err, res)
		}
	}
	// Names, case-insensitive, now and before the name existed.
	res, err = r.Find(ctx, store.FindQuery{Query: "PLC-B.local"})
	if err != nil || res.Kind != store.KindName || len(res.Hosts) != 1 {
		t.Errorf("find by name: %v %+v", err, res)
	}
	before := t0.Add(time.Hour)
	if res, err = r.Find(ctx, store.FindQuery{Query: "plc-b.local", At: &before}); err != nil || len(res.Hosts) != 0 {
		t.Errorf("find by name before it existed: %v %+v", err, res)
	}
	// Host ID; an explicit kind that does not match; an unknown host.
	hosts, _ := r.Hosts(ctx, store.HostFilter{})
	id := hosts[0].HostID
	if res, err = r.Find(ctx, store.FindQuery{Query: strings.ToUpper(id)}); err != nil || res.Kind != store.KindHost || len(res.Hosts) != 1 {
		t.Errorf("find by host id: %v %+v", err, res)
	}
	if _, err := r.Find(ctx, store.FindQuery{Query: "plc-b.local", Kind: store.KindIP}); !errors.Is(err, store.ErrBadQuery) {
		t.Errorf("explicit kind mismatch: %v", err)
	}
	if _, err := r.Host(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown host: %v", err)
	}
}

func TestHistory(t *testing.T) {
	st, _, exp := seed(t)
	r := reader(t, st)
	ctx := context.Background()
	for _, h := range exp.History {
		// Until: the extra mDNS name for B at T0+4h01 is in X's history too.
		evs, err := r.History(ctx, store.HistoryQuery{Query: h.IP, Interface: "eth1", Until: t0.Add(4 * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		var got, want []string
		for _, e := range evs {
			got = append(got, e.Type+" "+label(exp, e.MAC))
		}
		for _, i := range h.Events {
			want = append(want, exp.Events[i].Type+" "+exp.Events[i].Host)
		}
		if !slices.Equal(got, want) {
			t.Errorf("history %s = %v, want %v", h.IP, got, want)
		}
	}
	// A MAC's history includes the events where it is the related host.
	evs, err := r.History(ctx, store.HistoryQuery{Query: exp.Hosts["A"], Until: t0.Add(4 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, e := range evs {
		types = append(types, e.Type)
	}
	if !slices.Contains(types, "DUPLICATE_IP_RESOLVED") || !slices.Contains(types, "IP_CHANGED") {
		t.Errorf("history of A = %v", types)
	}
	if evs, err := r.History(ctx, store.HistoryQuery{Query: "plc-b.local", Since: t0.Add(4 * time.Hour)}); err != nil ||
		len(evs) == 0 || evs[len(evs)-1].Type != "HOSTNAME_ADDED" {
		t.Errorf("history of a name: %v %+v", err, evs)
	}
	if _, err := r.History(ctx, store.HistoryQuery{Query: "x", Kind: store.KindMAC}); !errors.Is(err, store.ErrBadQuery) {
		t.Errorf("bad query: %v", err)
	}
}

func TestHostsAndHost(t *testing.T) {
	st, _, exp := seed(t)
	r := reader(t, st)
	ctx := context.Background()
	all, err := r.Hosts(ctx, store.HostFilter{})
	if err != nil || len(all) != 4 {
		t.Fatalf("hosts: %v %d", err, len(all))
	}
	var a store.HostSummary
	for _, h := range all {
		if label(exp, h.MAC) == "A" {
			a = h
		}
	}
	if a.Vendor != "Siemens AG" || !slices.Equal(a.IPs, []string{"192.168.110.52"}) {
		t.Errorf("host A = %+v", a)
	}
	for _, tt := range []struct {
		name string
		f    store.HostFilter
		want int
	}{
		{"interface", store.HostFilter{Interface: "eth0"}, 1},
		{"vendor substring", store.HostFilter{Vendor: "siemens"}, 2},
		{"ever held an IP", store.HostFilter{Query: "192.168.110.51"}, 2},
		{"name", store.HostFilter{Query: "plant-sw-01"}, 1},
		{"open port", store.HostFilter{Port: 502}, 1},
		{"seen within", store.HostFilter{SeenSince: t0.Add(4 * time.Hour)}, 2},
		// At T0+4h02: B and the switch are ACTIVE, A (3h30) and C (3h) STALE.
		{"live", store.HostFilter{Live: true}, 2},
		{"not live", store.HostFilter{NotLive: true}, 2},
	} {
		got, err := r.Hosts(ctx, tt.f)
		if err != nil || len(got) != tt.want {
			t.Errorf("%s: %v, %d hosts, want %d", tt.name, err, len(got), tt.want)
		}
	}
	if _, err := r.Hosts(ctx, store.HostFilter{Query: "x", QueryKind: store.KindIP}); !errors.Is(err, store.ErrBadQuery) {
		t.Errorf("bad query: %v", err)
	}
	h, err := r.Host(ctx, a.HostID)
	if err != nil || len(h.Addresses) != 3 || h.Addresses[0].EndedAt == nil || len(h.Identifications) != 1 {
		t.Errorf("full record of A: %v %+v", err, h)
	}
}

func TestEventsObservationsServices(t *testing.T) {
	st, _, exp := seed(t)
	r := reader(t, st)
	ctx := context.Background()
	all, err := r.Events(ctx, store.EventFilter{})
	if err != nil || len(all) < 10 {
		t.Fatalf("events: %v %d", err, len(all))
	}
	dup, _ := r.Events(ctx, store.EventFilter{Types: []string{"DUPLICATE_IP_DETECTED"}})
	if len(dup) != 1 || label(exp, dup[0].MAC) != "C" || label(exp, dup[0].RelatedMAC) != "A" {
		t.Errorf("duplicate-ip events = %+v", dup)
	}
	last, _ := r.Events(ctx, store.EventFilter{Limit: 2})
	if len(last) != 2 || !last[1].TS.Equal(all[len(all)-1].TS) {
		t.Errorf("last 2 events = %+v", last)
	}
	for _, f := range []store.EventFilter{
		{Interface: "eth0"}, {MAC: exp.Hosts["B"]}, {IP: "192.168.110.50"}, {HostID: dup[0].HostID},
		{Since: t0.Add(3 * time.Hour), Until: t0.Add(3 * time.Hour)},
	} {
		if got, err := r.Events(ctx, f); err != nil || len(got) == 0 {
			t.Errorf("events %+v: %v %d", f, err, len(got))
		}
	}

	obs, err := r.Observations(ctx, store.ObservationFilter{})
	if err != nil || len(obs) != 10 || !obs[0].TS.Before(obs[len(obs)-1].TS) {
		t.Fatalf("observations: %v %d", err, len(obs))
	}
	if got, _ := r.Observations(ctx, store.ObservationFilter{Unbound: true}); len(got) != 1 || got[0].IP != "192.168.110.99" {
		t.Errorf("unbound = %+v", got)
	}
	if got, _ := r.Observations(ctx, store.ObservationFilter{Source: "tcp_connect", Limit: 1}); len(got) != 1 {
		t.Errorf("limited by source = %+v", got)
	}
	for _, f := range []store.ObservationFilter{{Interface: "eth0"}, {MAC: exp.Hosts["A"]}, {IP: "192.168.110.51"}, {HostID: dup[0].HostID}} {
		if got, err := r.Observations(ctx, f); err != nil || len(got) == 0 {
			t.Errorf("observations %+v: %v %d", f, err, len(got))
		}
	}
	if got, err := r.Rollups(ctx, store.ObservationFilter{}); err != nil || len(got) != 0 {
		t.Errorf("roll-ups before compaction: %v %d", err, len(got))
	}
	if _, err := st.Compact(ctx, store.Retention{Observations: time.Hour}, t0.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, err := r.Rollups(ctx, store.ObservationFilter{IP: "192.168.110.50"}); err != nil || len(got) == 0 || got[0].Count == 0 {
		t.Errorf("roll-ups: %v %+v", err, got)
	}

	svc, err := r.Services(ctx, store.ServiceFilter{Port: 502, State: "open"})
	if err != nil || len(svc) != 1 || label(exp, svc[0].MAC) != "B" || !slices.Equal(svc[0].IPs, []string{"192.168.110.50"}) {
		t.Errorf("services: %v %+v", err, svc)
	}
	if got, _ := r.Services(ctx, store.ServiceFilter{Interface: "eth0"}); len(got) != 0 {
		t.Errorf("services on eth0 = %+v", got)
	}
}

func TestInterfacesDBInfoCheckEvidence(t *testing.T) {
	st, path, exp := seed(t)
	r := reader(t, st)
	ctx := context.Background()
	ifs, err := r.Interfaces(ctx)
	if err != nil || len(ifs) != 2 || ifs[1].Name != "eth1" || !slices.Equal(ifs[1].Prefixes, []string{"192.168.110.0/24"}) ||
		ifs[1].Hosts != 3 || ifs[1].State != "unknown" {
		t.Errorf("interfaces: %v %+v", err, ifs)
	}
	info, err := r.DBInfo(ctx)
	if err != nil || info.Path != path || info.SchemaVersion != 2 || info.JournalMode != "wal" || info.Rows["hosts"] != 4 || info.UsedSize == 0 {
		t.Errorf("db info: %v %+v", err, info)
	}
	if res, err := r.Check(ctx); err != nil || !res.OK {
		t.Errorf("check: %v %+v", err, res)
	}
	hosts, _ := r.Hosts(ctx, store.HostFilter{Query: exp.Hosts["A"]})
	ev, err := r.Evidence(ctx, hosts[0].HostID, time.Time{})
	if err != nil || len(ev.Host.Addresses) != 3 || len(ev.Events) < 4 {
		t.Fatalf("evidence: %v %+v", err, ev)
	}
	var sources []string
	for _, c := range ev.Counts {
		sources = append(sources, c.Source+" "+c.IP)
	}
	if !slices.Contains(sources, "passive_dhcp 192.168.110.51") || !slices.Contains(sources, "kernel_neighbor 192.168.110.51") {
		t.Errorf("evidence counts = %v", sources)
	}
	if ev.Events[0].EvidenceIP() != "192.168.110.50" {
		t.Errorf("first event's evidence IP = %q", ev.Events[0].EvidenceIP())
	}
}

// Stale names: not confirmed for name_expiry, still in effect.
func TestStaleNames(t *testing.T) {
	st, _, exp := seed(t)
	r, err := st.Reader(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	res, err := r.Find(context.Background(), store.FindQuery{Query: exp.Hosts["B"]})
	if err != nil || len(res.Hosts) != 1 || len(res.Hosts[0].Names) != 1 || !res.Hosts[0].Names[0].Stale {
		t.Errorf("names: %v %+v", err, res)
	}
}

func TestClassify(t *testing.T) {
	for in, want := range map[string]string{
		"3db0ce66-38c2-4f50-a1ce-a593cb872f88": "host 3db0ce66-38c2-4f50-a1ce-a593cb872f88",
		"00:1B:1B:AA:BB:01":                    "mac 00:1b:1b:aa:bb:01",
		"001b.1baa.bb01":                       "mac 00:1b:1b:aa:bb:01",
		"192.168.110.50":                       "ip 192.168.110.50",
		"::ffff:192.168.110.50":                "ip 192.168.110.50",
		"FD00::1":                              "ip fd00::1",
		" plc-1.local ":                        "name plc-1.local",
		"00:1b:1b:aa:bb":                       "name 00:1b:1b:aa:bb",
	} {
		k, q := store.Classify(in)
		if got := string(k) + " " + q; got != want {
			t.Errorf("Classify(%q) = %s, want %s", in, got, want)
		}
	}
	if _, _, ok := store.Normalize(store.KindName, "192.168.1.1"); !ok {
		t.Error("an explicit name accepts any text")
	}
}

// The offline open contract (docs/CLI.md §1).
func TestOpenReadOnly(t *testing.T) {
	st, path, _ := seed(t)
	ctx := context.Background()

	// Beside the running writer: reads what is committed.
	r, err := store.OpenReadOnly(path, store.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Immutable {
		t.Error("opened immutable while the WAL exists")
	}
	if hosts, err := r.Hosts(ctx, store.HostFilter{}); err != nil || len(hosts) != 4 {
		t.Errorf("hosts beside the writer: %v %d", err, len(hosts))
	}
	_ = r.Close()

	// Unreadable WAL.
	if err := os.Chmod(path+"-wal", 0); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		if _, err := store.OpenReadOnly(path, store.ReadOptions{}); !errors.Is(err, store.ErrReadOnlyBesideWAL) {
			t.Errorf("unreadable WAL: %v", err)
		}
	}
	if err := os.Chmod(path+"-wal", 0o600); err != nil {
		t.Fatal(err)
	}

	// Busy: with the daemon stopped, a connection in exclusive locking mode
	// writing to the database (WAL in heap memory, no -shm) blocks readers
	// past the busy timeout.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	lock, err := sql.Open("sqlite", "file:"+path+"?_pragma=locking_mode(EXCLUSIVE)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	lock.SetMaxOpenConns(1)
	if _, err := lock.Exec(`INSERT INTO runtime_state (key, value, updated_at) VALUES ('test', '{}', 0)`); err != nil {
		t.Fatal(err)
	}
	r, err = store.OpenReadOnly(path, store.ReadOptions{BusyTimeout: 50 * time.Millisecond})
	if err == nil {
		_, err = r.Hosts(ctx, store.HostFilter{})
		_ = r.Close()
	}
	if !store.IsBusy(err) {
		t.Errorf("reader beside an exclusive lock: %v, want SQLITE_BUSY", err)
	}
	if store.IsBusy(errors.New("other")) {
		t.Error("IsBusy on a plain error")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}

	// Daemon stopped cleanly: no WAL, opened immutable.
	r, err = store.OpenReadOnly(path, store.ReadOptions{})
	if err != nil || !r.Immutable {
		t.Fatalf("after shutdown: %v immutable=%v", err, r != nil && r.Immutable)
	}
	if info, err := r.DBInfo(ctx); err != nil || info.JournalMode != "wal" {
		t.Errorf("journal mode of an immutable open: %v %q", err, info.JournalMode)
	}
	if hosts, err := r.Hosts(ctx, store.HostFilter{}); err != nil || len(hosts) != 4 {
		t.Errorf("hosts from the immutable database: %v %d", err, len(hosts))
	}
	_ = r.Close()
	if _, err := os.Stat(path + "-shm"); err == nil {
		t.Error("an immutable read created -shm")
	}

	if _, err := store.OpenReadOnly(filepath.Join(t.TempDir(), "missing.db"), store.ReadOptions{}); err == nil {
		t.Error("missing database opened")
	}
}

// -shm missing beside a WAL in a directory the reader cannot write.
func TestOpenReadOnlyNeedsShm(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write anywhere")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.db")
	for _, f := range []string{path, path + "-wal"} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if _, err := store.OpenReadOnly(path, store.ReadOptions{}); !errors.Is(err, store.ErrReadOnlyBesideWAL) {
		t.Errorf("missing -shm in a read-only directory: %v", err)
	}
}

// Replaced by: only a binding that started when or after the holder's
// ended; a claimant during the binding is a conflict, not a successor.
func TestFindReplacedByIsASuccessor(t *testing.T) {
	st, _, _ := seed(t)
	r := reader(t, st)
	ctx := context.Background()
	at := t0.Add(2 * time.Hour) // A holds Y; C claims Y at T0+3h while A holds it until T0+3h30
	res, err := r.Find(ctx, store.FindQuery{Query: "192.168.110.51", At: &at})
	if err != nil || len(res.Hosts) != 1 {
		t.Fatalf("find Y at T0+2h: %v %+v", err, res)
	}
	if h := res.Hosts[0]; h.ReplacedBy != nil || h.MovedTo == nil || h.MovedTo.Binding.IP != "192.168.110.52" {
		t.Errorf("replaced by %+v, moved to %+v; want no successor and a move to .52", h.ReplacedBy, h.MovedTo)
	}
	at = t0.Add(150 * time.Minute) // B's open binding of X
	if res, err = r.Find(ctx, store.FindQuery{Query: "192.168.110.50", At: &at}); err != nil || len(res.Hosts) != 1 ||
		res.Hosts[0].ReplacedBy != nil || res.Hosts[0].MovedTo != nil {
		t.Errorf("open binding: %v %+v", err, res.Hosts)
	}
	local := time.Date(2026, 10, 1, 12, 30, 0, 0, time.FixedZone("CEST", 2*3600))
	if res, err = r.Find(ctx, store.FindQuery{Query: "192.168.110.50", At: &local}); err != nil || res.At.Location() != time.UTC {
		t.Errorf("At not in UTC: %v %v", err, res.At)
	}
}

// MAC and IP filters accept every written form, and refuse what is not a
// MAC or IP.
func TestFilterNormalization(t *testing.T) {
	st, _, exp := seed(t)
	r := reader(t, st)
	ctx := context.Background()
	lower, _ := r.Events(ctx, store.EventFilter{MAC: exp.Hosts["A"]})
	for _, mac := range []string{strings.ToUpper(exp.Hosts["A"]), strings.ReplaceAll(exp.Hosts["A"], ":", "-"), "001b.1baa.bb01"} {
		if got, err := r.Events(ctx, store.EventFilter{MAC: mac}); err != nil || len(got) != len(lower) || len(got) == 0 {
			t.Errorf("events --mac %s: %v %d, want %d", mac, err, len(got), len(lower))
		}
		if got, err := r.Observations(ctx, store.ObservationFilter{MAC: mac}); err != nil || len(got) == 0 {
			t.Errorf("observations --mac %s: %v %d", mac, err, len(got))
		}
	}
	if got, err := r.Events(ctx, store.EventFilter{IP: "::ffff:192.168.110.50"}); err != nil || len(got) == 0 {
		t.Errorf("events --ip in mapped form: %v %d", err, len(got))
	}
	for _, f := range []store.EventFilter{{MAC: "not-a-mac"}, {IP: "192.168.110"}} {
		if _, err := r.Events(ctx, f); !errors.Is(err, store.ErrBadQuery) {
			t.Errorf("events %+v: %v", f, err)
		}
	}
	if _, err := r.Observations(ctx, store.ObservationFilter{IP: "x"}); !errors.Is(err, store.ErrBadQuery) {
		t.Errorf("observations bad IP: %v", err)
	}
	if _, err := r.Rollups(ctx, store.ObservationFilter{MAC: "x"}); !errors.Is(err, store.ErrBadQuery) {
		t.Errorf("roll-ups bad MAC: %v", err)
	}
	// Empty results are empty lists, as online.
	if got, err := r.Hosts(ctx, store.HostFilter{Interface: "eth9"}); err != nil || got == nil || len(got) != 0 {
		t.Errorf("no hosts: %v %#v", err, got)
	}
}

func TestEvidenceFor(t *testing.T) {
	st, _, _ := seed(t)
	r := reader(t, st)
	evs, err := r.EvidenceFor(context.Background(), store.HostFilter{Query: "192.168.110.51"}, time.Time{})
	if err != nil || len(evs) != 2 || len(evs[0].Events) == 0 || len(evs[1].Counts) == 0 {
		t.Errorf("evidence for the holders of Y: %v %+v", err, evs)
	}
	if _, err := r.EvidenceFor(context.Background(), store.HostFilter{Query: "x", QueryKind: store.KindMAC}, time.Time{}); !errors.Is(err, store.ErrBadQuery) {
		t.Errorf("bad query: %v", err)
	}
}

// More hosts than SQLite has bound variables (32766): hosts are never
// pruned, and listing them must keep working.
func TestManyHosts(t *testing.T) {
	st, _, _ := seed(t)
	err := st.Submit(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 33000)
			INSERT INTO hosts (host_id, context_id, mac, presence, first_seen, last_seen)
			SELECT printf('h%05d', i), 1, printf('02:00:00:%02x:%02x:%02x', i / 65536, i / 256 % 256, i % 256), 'MISSING', 0, 0 FROM n`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Flush(context.Background()); err != nil || st.OpErrors() != 0 {
		t.Fatalf("insert: %v %d", err, st.OpErrors())
	}
	r := reader(t, st)
	if hosts, err := r.Hosts(context.Background(), store.HostFilter{}); err != nil || len(hosts) != 33004 {
		t.Errorf("hosts: %v %d", err, len(hosts))
	}
}
