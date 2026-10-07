package daemon

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/platform/fake"
	"lan-sentinel/internal/store"
)

// A host's description goes through the correlator: set, unchanged, removed,
// each change a HOST_DESCRIBED event with the caller, kept across a restart.
func TestDescribeHostThroughTheDaemon(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x1b, 0x1b, 0xaa, 0xbb, 0x01}
	neighbours := func(n *fake.Neighbors, i *fake.Interfaces) {
		i.SetLinks([]platform.Link{{Name: "eth1", Index: 2, Up: true, MAC: net.HardwareAddr{2, 0, 0, 0, 0, 9},
			Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.110.0/24")}}})
		n.SetTable([]platform.Neighbor{{Interface: "eth1", IP: netip.MustParseAddr("192.168.110.50"), MAC: mac, State: "REACHABLE"}})
	}
	h := startWith(t, testConfig("$DIR", "info", ""), 0, neighbours)
	h.waitLog("HOST_DISCOVERED eth1")
	if err := h.d.store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	client := api.NewClient(filepath.Join(h.dir, "api.sock"), 5*time.Second)
	ctx := context.Background()
	hosts, err := client.Hosts(ctx, store.HostFilter{})
	if err != nil || len(hosts) != 1 {
		t.Fatalf("hosts = %+v, %v", hosts, err)
	}
	id := hosts[0].HostID

	got, err := client.SetDescription(ctx, id, "Solar panel rooftop")
	if err != nil || got.Description != "Solar panel rooftop" || got.MAC != mac.String() {
		t.Fatalf("set = %+v, %v", got, err)
	}
	if _, err := client.SetDescription(ctx, id, "Solar panel rooftop"); err != nil { // the same text: no event
		t.Fatal(err)
	}
	if found, _ := client.Hosts(ctx, store.HostFilter{Description: "ROOFTOP"}); len(found) != 1 {
		t.Errorf("--description filter found %d hosts", len(found))
	}
	if got, err := client.SetDescription(ctx, id, ""); err != nil || got.Description != "" {
		t.Errorf("remove = %+v, %v", got, err)
	}
	if _, err := client.SetDescription(ctx, "0199a0e0-0000-7000-8000-000000000000", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown host: %v", err)
	}
	if _, err := client.SetDescription(ctx, id, "PLC line 3"); err != nil {
		t.Fatal(err)
	}
	h.stop()

	db := filepath.Join(h.dir, "data", "hosts.db")
	evs := queryDB(t, db, `SELECT coalesce(old_value, '') || ' > ' || coalesce(new_value, '') || ' by ' || json_extract(evidence_json, '$.actor')
		FROM events WHERE type = 'HOST_DESCRIBED' ORDER BY id`)
	me := "uid " + strconv.Itoa(os.Getuid()) // how SO_PEERCRED names a user without a passwd entry
	if u, err := user.LookupId(strconv.Itoa(os.Getuid())); err == nil {
		me = u.Username
	}
	want := []string{" > Solar panel rooftop by " + me, "Solar panel rooftop >  by " + me, " > PLC line 3 by " + me}
	if len(evs) != len(want) {
		t.Fatalf("HOST_DESCRIBED events = %q, want %q", evs, want)
	}
	for i := range want {
		if evs[i] != want[i] {
			t.Errorf("event %d = %q, want %q", i, evs[i], want[i])
		}
	}

	// After a restart the description is there, and the correlator knows it:
	// the same text again records nothing.
	h2 := startWith(t, testConfig(h.dir, "info", ""), 0, neighbours) // the same database and socket
	client = api.NewClient(filepath.Join(h.dir, "api.sock"), 5*time.Second)
	if got, err := client.SetDescription(ctx, id, "PLC line 3"); err != nil || got.Description != "PLC line 3" {
		t.Errorf("after the restart = %+v, %v", got, err)
	}
	h2.stop()
	if n := queryDB(t, db, `SELECT count(*) FROM events WHERE type = 'HOST_DESCRIBED'`); n[0] != "3" {
		t.Errorf("%s HOST_DESCRIBED events after the restart, want 3", n[0])
	}
}
