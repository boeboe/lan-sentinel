//go:build nettest

package nettest

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	_ "modernc.org/sqlite"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/daemon"
	"lan-sentinel/internal/platform"
)

func env(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Skipf("%s not set: run via make test-net", name)
	}
	return v
}

func ip(t *testing.T, name string) netip.Addr {
	t.Helper()
	v := env(t, name)
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Addr()
	}
	return netip.MustParseAddr(v)
}

// ping sends one ICMP echo from an unprivileged ping socket, which makes the
// kernel resolve (or re-confirm) the neighbour.
func ping(t *testing.T, target netip.Addr) {
	t.Helper()
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		t.Fatalf("ping socket: %v", err)
	}
	defer c.Close()
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 1, Seq: 1, Data: []byte("lan-sentinel")}}
	b, _ := msg.Marshal(nil)
	_, _ = c.WriteTo(b, &net.UDPAddr{IP: target.AsSlice()})
}

// request asks run.sh for an action outside the runner and waits for it.
// Each request has its own id, so repeating an action waits for the new
// reply rather than finding the previous one. Arguments go into the request
// file.
func request(t *testing.T, action string, args ...string) {
	t.Helper()
	dir := env(t, "LS_TEST_SYNC")
	name := fmt.Sprintf("%s@%d", action, time.Now().UnixNano())
	// Written under another name and renamed, so run.sh never reads a
	// request before its arguments are in it.
	tmp := filepath.Join(dir, name+".tmp")
	if err := os.WriteFile(tmp, []byte(strings.Join(args, " ")+"\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, name+".request")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, name+".done")); err == nil {
			return
		}
		if _, err := os.Stat(filepath.Join(dir, name+".failed")); err == nil {
			t.Fatalf("action %s failed", action)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("action %s not performed within 60s", action)
}

// linkWithPrefix waits until an interface has prefix and returns its name.
func linkWithPrefix(t *testing.T, prefix netip.Prefix) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		links, err := platform.New().Interfaces.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range links {
			if slices.Contains(l.Prefixes, prefix) {
				return l.Name
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no interface with %s", prefix)
	return ""
}

// awaitNeighbor pings target every second until an event satisfies match.
func awaitNeighbor(t *testing.T, ch <-chan platform.NeighborEvent, target netip.Addr, timeout time.Duration, match func(platform.NeighborEvent) bool) platform.NeighborEvent {
	t.Helper()
	deadline := time.After(timeout)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	ping(t, target)
	var seen []string
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("neighbour watch closed")
			}
			if ev.Neighbor.IP != target {
				continue
			}
			seen = append(seen, ev.Neighbor.State+" "+ev.Neighbor.MAC.String())
			if match(ev) {
				return ev
			}
		case <-tick.C:
			ping(t, target)
		case <-deadline:
			t.Fatalf("no matching neighbour event for %s within %v; saw %v", target, timeout, seen)
		}
	}
}

func TestInterfaces(t *testing.T) {
	iface, prefix := env(t, "LS_TEST_IFACE"), netip.MustParsePrefix(env(t, "LS_TEST_PREFIX"))
	links, err := platform.New().Interfaces.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range links {
		if l.Name != iface {
			continue
		}
		if !l.Up || !slices.Contains(l.Prefixes, prefix) {
			t.Errorf("%s = %+v, want up with %s", iface, l, prefix)
		}
		if os.Getenv("LS_TEST_IPV6") == "1" && !slices.Contains(l.Prefixes, netip.MustParsePrefix("fd5e:5e:1::/64")) {
			t.Errorf("%s lacks its IPv6 prefix: %v", iface, l.Prefixes)
		}
		return
	}
	t.Fatalf("%s not listed", iface)
}

// TestNeighborAppears: pinging a host makes its neighbour entry appear,
// with a REACHABLE notification. If an earlier test already left the entry
// REACHABLE, pings change nothing and no notification comes; the snapshot
// then shows it. (Notifications are also covered by the MAC-change and
// expiry tests.)
func TestNeighborAppears(t *testing.T) {
	target, mac, iface := ip(t, "LS_TEST_OPEN"), env(t, "LS_TEST_OPEN_MAC"), env(t, "LS_TEST_IFACE")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nbs := platform.New().Neighbors
	ch, err := nbs.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reachable := func() (platform.Neighbor, bool) {
		list, err := nbs.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range list {
			if n.IP == target && n.MAC.String() == mac && n.State == "REACHABLE" {
				return n, true
			}
		}
		return platform.Neighbor{}, false
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ping(t, target)
		wait := time.After(2 * time.Second)
	events:
		for {
			select {
			case ev := <-ch:
				if ev.Neighbor.IP == target && ev.Neighbor.MAC.String() == mac && ev.Neighbor.State == "REACHABLE" {
					n, ok := reachable()
					if !ok || n.Interface != iface || n.ConfirmedAgo > 10*time.Second {
						t.Errorf("snapshot after the notification = %+v (found %v)", n, ok)
					}
					return
				}
			case <-wait:
				break events
			}
		}
		if n, ok := reachable(); ok {
			if n.Interface != iface {
				t.Errorf("snapshot entry = %+v", n)
			}
			t.Logf("%s was already REACHABLE (no notification): %+v", target, n)
			return
		}
	}
	t.Fatalf("%s never became REACHABLE", target)
}

func TestNeighborMACChange(t *testing.T) {
	target := ip(t, "LS_TEST_SWAP")
	macA, macB := env(t, "LS_TEST_SWAP_MAC_A"), env(t, "LS_TEST_SWAP_MAC_B")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := platform.New().Neighbors.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	awaitNeighbor(t, ch, target, 20*time.Second, func(ev platform.NeighborEvent) bool {
		return ev.Neighbor.MAC.String() == macA
	})
	request(t, "swap")
	awaitNeighbor(t, ch, target, 60*time.Second, func(ev platform.NeighborEvent) bool {
		return ev.Neighbor.MAC.String() == macB
	})
}

func TestNeighborExpiry(t *testing.T) {
	absent, gone, goneMAC := ip(t, "LS_TEST_ABSENT"), ip(t, "LS_TEST_GONE"), env(t, "LS_TEST_GONE_MAC")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := platform.New().Neighbors.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	failedOrGone := func(ev platform.NeighborEvent) bool { return ev.Deleted || ev.Neighbor.State == "FAILED" }

	// Nobody answers: resolution fails.
	awaitNeighbor(t, ch, absent, 20*time.Second, failedOrGone)

	// A host that was there disappears: its entry goes stale and fails.
	awaitNeighbor(t, ch, gone, 20*time.Second, func(ev platform.NeighborEvent) bool {
		return ev.Neighbor.MAC.String() == goneMAC && ev.Neighbor.State == "REACHABLE"
	})
	request(t, "stop-gone")
	awaitNeighbor(t, ch, gone, 120*time.Second, failedOrGone)
}

func TestLinkEvents(t *testing.T) {
	prefix := netip.MustParsePrefix(env(t, "LS_TEST_NET2_PREFIX"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := platform.New().Interfaces.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	await := func(what string, match func(platform.LinkEvent) bool) platform.LinkEvent {
		t.Helper()
		deadline := time.After(30 * time.Second)
		for {
			select {
			case ev := <-ch:
				if match(ev) {
					return ev
				}
			case <-deadline:
				t.Fatalf("no link event: %s", what)
			}
		}
	}
	request(t, "net-connect")
	added := await("link with "+prefix.String(), func(ev platform.LinkEvent) bool {
		return !ev.Removed && slices.Contains(ev.Link.Prefixes, prefix)
	})
	request(t, "net-disconnect")
	await("removal of "+added.Link.Name, func(ev platform.LinkEvent) bool {
		return ev.Link.Index == added.Link.Index && (ev.Removed || !slices.Contains(ev.Link.Prefixes, prefix))
	})
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestDaemonFindsHosts runs the daemon on two test networks (phase 1 exit
// criterion, in Docker): hosts appear from the kernel neighbour table alone,
// with their vendor, scoped per interface. The same MAC on both networks is
// two hosts, one per interface, linked by MAC_MOVED.
func TestDaemonFindsHosts(t *testing.T) {
	iface, prefix := env(t, "LS_TEST_IFACE"), env(t, "LS_TEST_PREFIX")
	prefix2 := env(t, "LS_TEST_NET2_PREFIX")
	open, closed, plc, twin := ip(t, "LS_TEST_OPEN"), ip(t, "LS_TEST_CLOSED"), ip(t, "LS_TEST_PLC"), ip(t, "LS_TEST_TWIN")
	openMAC, closedMAC, plcMAC := env(t, "LS_TEST_OPEN_MAC"), env(t, "LS_TEST_CLOSED_MAC"), env(t, "LS_TEST_PLC_MAC")

	request(t, "net-connect")
	defer request(t, "net-disconnect")
	iface2 := linkWithPrefix(t, netip.MustParsePrefix(prefix2))

	dir := t.TempDir()
	cfgPath, db := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "hosts.db")
	cfg := "version: 1\ninterfaces:\n" +
		"  - name: " + iface + "\n    passive: { enabled: false }\n" +
		"  - name: " + iface2 + "\n    passive: { enabled: false }\n" +
		"storage: { path: " + db + " }\napi: { socket: " + filepath.Join(dir, "api.sock") + " }\nlogging: { format: text }\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	log := &syncBuffer{}
	signals := make(chan os.Signal, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- daemon.Run(context.Background(), daemon.Options{Load: config.LoadOptions{Path: cfgPath}, Stderr: log, Signals: signals})
	}()
	// The MAC seen on two interfaces is two hosts linked by MAC_MOVED on
	// whichever was discovered second (that depends on the neighbour dump's
	// order).
	for _, want := range []string{
		"HOST_DISCOVERED " + iface + " " + openMAC,
		"HOST_DISCOVERED " + iface + " " + closedMAC,
		"HOST_DISCOVERED " + iface + " " + plcMAC,
		"HOST_DISCOVERED " + iface2 + " " + openMAC,
		"MAC_MOVED ",
	} {
		deadline := time.Now().Add(30 * time.Second)
		for !strings.Contains(log.String(), want) {
			if time.Now().After(deadline) {
				t.Fatalf("log never showed %q:\n%s", want, log)
			}
			for _, target := range []netip.Addr{open, closed, plc, twin} {
				ping(t, target)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	signals <- syscall.SIGTERM
	if err := <-errc; err != nil {
		t.Fatalf("daemon: %v\n%s", err, log)
	}

	conn, err := sql.Open("sqlite", "file:"+db+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	query := func(q string) []string {
		rows, err := conn.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		return out
	}
	hosts := query(`SELECT c.interface || ' ' || h.mac || ' ' || a.ip || ' ' || coalesce(h.vendor, '-') || ' la=' || h.locally_administered
		FROM hosts h JOIN network_contexts c ON c.id = h.context_id
		JOIN addresses a ON a.host_id = h.host_id AND a.ended_at IS NULL`)
	for _, want := range []string{
		iface + " " + openMAC + " " + open.String() + " - la=1",
		iface + " " + closedMAC + " " + closed.String() + " - la=1",
		iface + " " + plcMAC + " " + plc.String() + " Siemens AG la=0",
		iface2 + " " + openMAC + " " + twin.String() + " - la=1",
	} {
		if !slices.Contains(hosts, want) {
			t.Errorf("hosts lack %q:\n  %s", want, strings.Join(hosts, "\n  "))
		}
	}
	if got := query(`SELECT count(DISTINCT host_id) FROM hosts WHERE mac = '` + openMAC + `'`); got[0] != "2" {
		t.Errorf("hosts with MAC %s = %v, want 2 (one per interface)", openMAC, got)
	}
	if got := query(`SELECT old_value || '>' || new_value FROM events WHERE type = 'MAC_MOVED'`); len(got) != 1 ||
		got[0] != iface+">"+iface2 && got[0] != iface2+">"+iface {
		t.Errorf("MAC_MOVED events = %v, want one between %s and %s", got, iface, iface2)
	}
	prefixes := query(`SELECT c.interface || ' ' || p.prefix FROM context_prefixes p
		JOIN network_contexts c ON c.id = p.context_id WHERE p.ended_at IS NULL`)
	for _, want := range []string{iface + " " + prefix, iface2 + " " + prefix2} {
		if !slices.Contains(prefixes, want) {
			t.Errorf("open prefixes %v lack %q", prefixes, want)
		}
	}
	if got := query(`SELECT DISTINCT source FROM address_sources`); strings.Join(got, ",") != "kernel_neighbor" {
		t.Errorf("address sources = %v, want only kernel_neighbor", got)
	}
}
