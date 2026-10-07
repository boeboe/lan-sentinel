//go:build soak

// Package soak simulates 90 days of a 50-host LAN through the correlator
// and the store on a simulated clock, with hourly compaction at the
// default retention, to check the storage and memory budgets of
// NFR-PERF-1 before a board runs for that long (docs/TEST_PLAN.md E1).
// Run it with `make soak`; it takes several minutes.
package soak

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
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

const (
	days    = 90
	iface   = "eth1"
	budget  = 200_000_000 // NFR-PERF-1: database < 200 MB after 90 days
	network = "10.20.0.0/24"
)

var t0 = time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC) // a Monday

// The kinds of device on the simulated LAN.
const (
	ot     = iota // always on: passive IPv4, ARP, the ARP sweep
	laptop        // weekdays 08:00–18:00, DHCP and mDNS
	phone         // weekdays 09:00–17:00, a new random MAC every day
	router        // the gateway and DHCP server
	sw            // the switch, LLDP
)

type device struct {
	kind   int
	index  int
	mac    net.HardwareAddr
	ip     netip.Addr
	second int // its offset within a minute
	name   string
}

func addr(n int) netip.Addr { return netip.AddrFrom4([4]byte{10, 20, 0, byte(n)}) }

func mac(oui []byte, n int) net.HardwareAddr {
	return net.HardwareAddr{oui[0], oui[1], oui[2], byte(n >> 16), byte(n >> 8), byte(n)}
}

var (
	siemens = []byte{0x00, 0x1b, 0x1b}
	dell    = []byte{0x00, 0x14, 0x22}
	cisco   = []byte{0x00, 0x1e, 0xc9}
	gateway = []byte{0x00, 0x00, 0x5e}
)

// lan returns the fixed devices: 35 OT devices, 12 laptops, the router and
// the switch (the 3 phones are made per day).
func lan() []*device {
	var out []*device
	for i := range 35 {
		out = append(out, &device{kind: ot, index: i, mac: mac(siemens, i+1), ip: addr(10 + i)})
	}
	for i := range 12 {
		out = append(out, &device{kind: laptop, index: i, mac: mac(dell, i+1), ip: addr(100 + i), name: "DESKTOP-" + strconv.Itoa(1000000+i)})
	}
	out = append(out, &device{kind: router, mac: mac(gateway, 1), ip: addr(1)}, &device{kind: sw, mac: mac(cisco, 1), ip: addr(2), name: "plant-sw-01"})
	for i, d := range out {
		d.second = i % 60
	}
	return out
}

// phones are the day's phones: a new locally administered MAC each day and
// an address from a small pool, so addresses are reused across days.
func phones(day int) []*device {
	out := make([]*device, 3)
	for i := range out {
		n := day*3 + i
		out[i] = &device{kind: phone, index: i, mac: net.HardwareAddr{0x02, 0xaa, byte(n >> 16), byte(n >> 8), byte(n), byte(i)},
			ip: addr(150 + n%40), second: 50 + i, name: fmt.Sprintf("Android_%08X", n*2654435761%(1<<32))}
	}
	return out
}

// present reports whether d is on the LAN in minute m.
func present(d *device, m int) bool {
	day, minute := m/1440, m%1440
	weekday := day%7 < 5
	switch d.kind {
	case laptop:
		return weekday && minute >= 480 && minute < 1080
	case phone:
		return weekday && minute >= 540 && minute < 1020
	}
	return true
}

// ipOf is d's address in minute m: three OT devices are moved during the run.
func ipOf(d *device, m int) netip.Addr {
	if d.kind == ot && d.index < 3 && m/1440 >= 30+15*d.index {
		return addr(200 + d.index)
	}
	return d.ip
}

// minute returns the observations of minute m, in time order: what the
// capture decoders pass on (an unchanged observation at most every 2
// minutes), the kernel neighbour table and the periodic ARP sweep.
func minute(lan, day []*device, m int) []observation.Observation {
	var out []observation.Observation
	add := func(d *device, o observation.Observation) {
		o.Time = t0.Add(time.Duration(m)*time.Minute + time.Duration(d.second)*time.Second)
		o.Interface, o.MAC = iface, d.mac
		out = append(out, o)
	}
	every := func(d *device, period int) bool { return (m+d.second)%period == 0 }
	arrives := func(d *device) bool { return present(d, m) && !present(d, m-1) }
	for _, d := range append(append([]*device{}, lan...), day...) {
		if !present(d, m) {
			continue
		}
		ip := ipOf(d, m)
		if every(d, 2) {
			add(d, observation.Observation{Source: observation.PassiveIPv4, IP: ip})
		}
		if every(d, 5) {
			add(d, observation.Observation{Source: observation.PassiveARP, IP: ip, Meta: map[string]string{"arp": "request"}})
			add(d, observation.Observation{Source: observation.ARPScan, IP: ip})
		}
		switch d.kind {
		case ot:
			if d.index < 5 && every(d, 2) {
				add(d, observation.Observation{Source: observation.KernelNeighbor, IP: ip, NeighborState: "REACHABLE"})
			}
		case laptop, phone:
			if every(d, 5) {
				services := "_workstation._tcp,_ssh._tcp"
				if d.kind == phone {
					services = "_googlecast._tcp"
				}
				name := d.name
				if d.kind == phone { // Android rotates its mDNS name
					name = fmt.Sprintf("%s%02d", d.name[:12], m/120%100)
				}
				add(d, observation.Observation{Source: observation.PassiveMDNS, IP: ip, Hostname: name + ".local", NameType: observation.NameMDNS,
					Meta: map[string]string{"services": services, "txt": "model=Workstation;vers=1"}})
			}
			if arrives(d) {
				vc := "MSFT 5.0"
				if d.kind == phone {
					vc = "android-dhcp-14"
				}
				add(d, observation.Observation{Source: observation.PassiveDHCP, Hostname: d.name, NameType: observation.NameDHCP,
					Meta: map[string]string{"dhcp": "request", "vendor_class": vc, "parameter_request_list": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"}})
				add(d, observation.Observation{Source: observation.PassiveDHCPLease, IP: ip,
					Meta: map[string]string{"dhcp": "ack", "server_id": "10.20.0.1", "lease_seconds": "86400"}})
				gw := lan[len(lan)-2]
				add(gw, observation.Observation{Source: observation.PassiveDHCPServer, IP: gw.ip,
					Meta: map[string]string{"dhcp": "ack", "server_id": "10.20.0.1", "router": "10.20.0.1", "dns": "10.20.0.1", "subnet_mask": "255.255.255.0"}})
			}
		case sw:
			if every(d, 2) {
				add(d, observation.Observation{Source: observation.PassiveLLDP, Hostname: d.name, NameType: observation.NameLLDP,
					Meta: map[string]string{"chassis_id": d.mac.String(), "port_id": "ge-0/0/23", "capabilities": "bridge",
						"system_description": "Industrial Ethernet Switch", "management_ip": d.ip.String()}})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

func cpu() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// rss is the process's resident set in bytes.
func rss() int64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "VmRSS:"); ok {
			kb, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
			return kb << 10
		}
	}
	return 0
}

type sample struct {
	day                 int
	size, heap, rss     int64
	hosts, observations int64
}

func TestNinetyDays(t *testing.T) {
	ctx := context.Background()
	sim := clock.NewSim(t0)
	path := filepath.Join(t.TempDir(), "hosts.db")
	st, err := store.Open(ctx, store.Options{Path: path, Clock: sim})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Defaults()
	cfg.Interfaces = []config.InterfaceConfig{{Name: iface}}
	vendors, err := identify.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	c, err := correlate.New(ctx, correlate.Options{Store: st, Events: events.NewEngine(st, log, nil), Vendors: vendors, Clock: sim,
		Logger: log, Config: cfg, DataDriven: true})
	if err != nil {
		t.Fatal(err)
	}
	c.Handle(ctx, observation.Message{Link: &observation.LinkState{Time: t0, Interface: iface, Present: true, Up: true,
		Prefixes: []netip.Prefix{netip.MustParsePrefix(network)}}})
	r := cfg.Storage.Retention
	retention := store.Retention{Observations: r.Observations.D(), Rollups: r.Rollups.D(), Events: r.Events.D()} // the cap off: the natural size

	fixed := lan()
	var samples []sample
	var observations int64
	cpu0, wall0 := cpu(), time.Now()
	for m := 0; m < days*1440; m++ {
		day := phones(m / 1440)
		for _, o := range minute(fixed, day, m) {
			sim.Set(o.Time)
			c.Handle(ctx, observation.Message{Observation: o})
			observations++
		}
		if (m+1)%60 == 0 {
			sim.Set(t0.Add(time.Duration(m+1) * time.Minute))
			if _, err := st.Compact(ctx, retention, sim.Now()); err != nil {
				t.Fatal(err)
			}
		}
		if (m+1)%1440 == 0 {
			if err := st.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			size, err := st.UsedSize(ctx)
			if err != nil {
				t.Fatal(err)
			}
			runtime.GC()
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			s := sample{day: (m + 1) / 1440, size: size, heap: int64(ms.HeapInuse), rss: rss(), observations: observations}
			s.hosts = count(t, st, `SELECT count(*) FROM hosts`)
			samples = append(samples, s)
		}
	}
	elapsed, used := time.Since(wall0), cpu()-cpu0
	if st.OpErrors() != 0 {
		t.Fatalf("%d store writes failed", st.OpErrors())
	}

	t.Logf("%d observations in %s wall, %s CPU: %.1f µs CPU per observation", observations, elapsed.Round(time.Second),
		used.Round(time.Second), float64(used.Microseconds())/float64(observations))
	t.Logf("%5s %10s %8s %8s %6s %12s", "day", "db", "heap", "rss", "hosts", "observations")
	for _, s := range samples {
		if s.day == 1 || s.day%10 == 0 {
			t.Logf("%5d %8.1fMB %6.1fMB %6.1fMB %6d %12d", s.day, mb(s.size), mb(s.heap), mb(s.rss), s.hosts, s.observations)
		}
	}
	for _, table := range []string{"observations", "observation_rollups", "events", "addresses", "names", "identifications", "hosts", "dhcp_servers"} {
		t.Logf("%-20s %8d rows", table, count(t, st, `SELECT count(*) FROM `+table))
	}

	end := samples[len(samples)-1]
	if end.size >= budget {
		t.Errorf("database %.1f MB after %d days, budget %.0f MB", mb(end.size), days, mb(budget))
	}
	// Retention: raw observations are at most 7 days old, roll-ups 90.
	now := t0.Add(days * 24 * time.Hour)
	if oldest := count(t, st, `SELECT coalesce(min(ts), 0) FROM observations`); time.UnixMilli(oldest).Before(now.Add(-r.Observations.D() - time.Hour)) {
		t.Errorf("raw observations from %s kept, retention %s", time.UnixMilli(oldest).UTC(), r.Observations)
	}
	if oldest := count(t, st, `SELECT coalesce(min(hour), 0) FROM observation_rollups`); time.UnixMilli(oldest).Before(now.Add(-r.Rollups.D() - time.Hour)) {
		t.Errorf("roll-ups from %s kept, retention %s", time.UnixMilli(oldest).UTC(), r.Rollups)
	}
	// Memory follows the state, not time: after the first weeks, the heap
	// grows only with the hosts the phones' daily MACs add.
	day30 := samples[29]
	if perHost := float64(end.heap-day30.heap) / float64(max(end.hosts-day30.hosts, 1)); end.heap > day30.heap && perHost > 64<<10 {
		t.Errorf("heap grew %.1f MB from day 30 to %d (%.0f KB per added host)", mb(end.heap-day30.heap), days, perHost/1024)
	}
}

func mb(n int64) float64 { return float64(n) / 1e6 }

func count(t *testing.T, st *store.Store, q string) int64 {
	t.Helper()
	var n int64
	if err := st.View(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, q).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}
