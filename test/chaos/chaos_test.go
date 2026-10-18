//go:build chaos

// Package chaos runs the daemon in-process on the fake platform under a
// seeded storm of everything that can happen to it at once, and checks its
// invariants throughout (make chaos, docs/IMPLEMENTATION_PLAN.md testing
// strategy). The actors run concurrently: captured frames of every
// protocol (with IP changes, MAC swaps, duplicate IPs, late frames and
// corrupted frames), kernel neighbour events, interface flaps and subnet
// changes, operator actions (kill switch, scans, descriptions, identify
// runs, reloads with valid and invalid files, SIGHUP), online and offline
// reads, and a simulated clock that jumps from seconds to more than a day.
//
// LS_CHAOS_SEED replays a run's choices (goroutine scheduling still
// varies); LS_CHAOS_DURATION sets its length (default 60s).
package chaos

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
	_ "modernc.org/sqlite"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/cli"
	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/daemon"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/platform/fake"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/scheduler"
	"lan-sentinel/internal/store"
	"lan-sentinel/test/frames"
)

// syncBuffer is a log the daemon and the test share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
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

// simHost is a device on a simulated LAN: a MAC and its current address.
type simHost struct {
	mac  net.HardwareAddr
	ip   netip.Addr
	name string
}

// lan is the simulated network of one interface. Its hosts change: an IP
// moves, a NIC is swapped, two devices claim one address.
type lan struct {
	iface  string
	prefix netip.Prefix
	mu     sync.Mutex
	hosts  []simHost
}

func (l *lan) pick(r *rand.Rand) simHost {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.hosts[r.IntN(len(l.hosts))]
}

func (l *lan) addr(n int) netip.Addr {
	a := l.prefix.Addr().As4()
	a[3] = byte(n)
	return netip.AddrFrom4(a)
}

// mutate changes the LAN: an address change, a NIC swap (new MAC on an
// address) or a duplicate (a second host claims another's address).
func (l *lan) mutate(r *rand.Rand) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	i := r.IntN(len(l.hosts))
	switch r.IntN(3) {
	case 0:
		l.hosts[i].ip = l.addr(10 + r.IntN(200))
		return "ip_change"
	case 1:
		l.hosts[i].mac = randomMAC(r)
		return "nic_swap"
	default:
		j := r.IntN(len(l.hosts))
		l.hosts[j].ip = l.hosts[i].ip
		return "duplicate_ip"
	}
}

func randomMAC(r *rand.Rand) net.HardwareAddr {
	m := make(net.HardwareAddr, 6)
	for i := range m {
		m[i] = byte(r.IntN(256))
	}
	m[0] = m[0]&0xfe | 0x02 // unicast, locally administered
	return m
}

type world struct {
	t                    *testing.T
	seed                 uint64
	dir, cfgPath, socket string
	offlineCfg           string // a valid file for the CLI: the daemon's may be invalid on purpose
	dbPath               string
	sim                  *clock.Sim
	capt                 *fake.Capturer
	neigh                *fake.Neighbors
	ifaces               *fake.Interfaces
	d                    *daemon.Daemon
	client               *api.Client
	signals              chan os.Signal
	errc                 chan error
	log                  *syncBuffer
	lans                 map[string]*lan

	mu          sync.Mutex
	counts      map[string]int
	failures    []string
	slowest     time.Duration
	slowestCall string
}

func (w *world) count(what string) {
	w.mu.Lock()
	w.counts[what]++
	w.mu.Unlock()
}

// fail records an invariant violation; the test reports all of them at the
// end with the seed.
func (w *world) fail(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.failures) < 50 {
		w.failures = append(w.failures, fmt.Sprintf(format, args...))
	}
}

// rng returns a generator for one actor, derived from the run's seed.
func (w *world) rng(actor uint64) *rand.Rand { return rand.New(rand.NewPCG(w.seed, actor)) }

func chaosDuration(t *testing.T) time.Duration {
	if s := os.Getenv("LS_CHAOS_DURATION"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			t.Fatalf("LS_CHAOS_DURATION: %v", err)
		}
		return d
	}
	return time.Minute
}

func chaosSeed(t *testing.T) uint64 {
	if s := os.Getenv("LS_CHAOS_SEED"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("LS_CHAOS_SEED: %v", err)
		}
		return v
	}
	return uint64(time.Now().UnixNano())
}

// configText is a valid configuration; variant chooses what a reload
// changes (active discovery, intervals, identification, log level,
// thresholds, and a restart-only key that must be kept).
func (w *world) configText(r *rand.Rand) string {
	on := func(p float64) string { return strconv.FormatBool(r.Float64() < p) }
	identify := []string{"[]", "[{name: http}]", "[{name: http}, {name: tls}, {name: ftp}]", "[{name: modbus}, {name: snmp, community: public}]"}
	levels := []string{"info", "debug", "warn"}
	return fmt.Sprintf(`version: 1
interfaces:
  - name: eth1
    active:
      enabled: %s
      networks: [192.168.110.0/26]
      exclude: [192.168.110.1]
      identify: %s
  - name: eth2
    active:
      enabled: %s
      networks: [10.20.0.0/28]
passive:
  protocols: { ipv6: %s }
active:
  startup_delay: 0s
  arp: { enabled: true, interval: %ds }
  icmp: { enabled: %s, interval: 20s }
  tcp: { enabled: %s, interval: 30s, targets: [{ port: 502, timeout: 500ms }] }
  udp: { enabled: %s, interval: 60s }
  identify: { interval: 30s, timeout: 300ms }
presence: { active: %dm, recent: 30m, stale: 24h }
identity: { proxy_arp_threshold: %d }
storage: { path: %s }
api: { socket: %s }
logging: { level: %s, format: text }
`, on(0.8), identify[r.IntN(len(identify))], on(0.5), on(0.2), 10+r.IntN(50), on(0.5), on(0.5), on(0.3),
		2+r.IntN(5), 4+r.IntN(20), w.dbPath, w.socket, levels[r.IntN(len(levels))])
}

// writeConfig replaces the file atomically, as an operator's editor would.
func (w *world) writeConfig(text string) {
	tmp := w.cfgPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		w.t.Fatal(err)
	}
	if err := os.Rename(tmp, w.cfgPath); err != nil {
		w.t.Fatal(err)
	}
}

func TestChaos(t *testing.T) {
	duration, seed := chaosDuration(t), chaosSeed(t)
	t.Logf("chaos: seed %d, %s (rerun: LS_CHAOS_SEED=%d)", seed, duration, seed)
	before := runtime.NumGoroutine()
	dir := t.TempDir()
	w := &world{
		t: t, seed: seed, dir: dir, cfgPath: filepath.Join(dir, "config.yaml"), socket: filepath.Join(dir, "api.sock"),
		offlineCfg: filepath.Join(dir, "cli.yaml"), dbPath: filepath.Join(dir, "hosts.db"), sim: clock.NewSim(time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)),
		signals: make(chan os.Signal, 4), errc: make(chan error, 1), log: &syncBuffer{}, counts: map[string]int{},
		lans: map[string]*lan{},
	}
	setup := w.rng(0)
	for name, p := range map[string]string{"eth1": "192.168.110.0/24", "eth2": "10.20.0.0/24"} {
		l := &lan{iface: name, prefix: netip.MustParsePrefix(p)}
		for i := range 30 {
			l.hosts = append(l.hosts, simHost{mac: randomMAC(setup), ip: l.addr(10 + i), name: fmt.Sprintf("%s-dev-%02d", name, i)})
		}
		w.lans[name] = l
	}
	// A device on both interfaces: two hosts, MAC_MOVED.
	w.lans["eth2"].hosts[0].mac = w.lans["eth1"].hosts[0].mac
	w.writeConfig(w.configText(setup))
	if err := os.WriteFile(w.offlineCfg, []byte(fmt.Sprintf("version: 1\ninterfaces:\n  - name: eth1\nstorage: { path: %s }\napi: { socket: %s }\n", w.dbPath, w.socket)), 0o600); err != nil {
		t.Fatal(err)
	}

	backends, capt, neigh, ifaces, tx := fake.Backends()
	w.capt, w.neigh, w.ifaces = capt, neigh, ifaces
	ifaces.SetLinks(w.links(true, "10.20.0.0/24"))
	w.scriptTransmitter(tx)
	d, err := daemon.New(daemon.Options{
		Load: config.LoadOptions{Path: w.cfgPath}, Stderr: w.log, Clock: w.sim, Backends: &backends,
		Notifier: nopNotifier{}, Signals: w.signals,
	})
	if err != nil {
		t.Fatalf("daemon: %v", err)
	}
	w.d = d
	go func() { w.errc <- d.Run(context.Background()) }()
	select {
	case <-d.Ready():
	case err := <-w.errc:
		t.Fatalf("daemon exited at start-up: %v\n%s", err, w.log)
	case <-time.After(20 * time.Second):
		t.Fatalf("daemon not ready\n%s", w.log)
	}
	w.client = api.NewClient(w.socket, 2*time.Minute) // call() judges hangs

	ctx, stop := context.WithTimeout(context.Background(), duration)
	var wg sync.WaitGroup
	actor := func(name string, id uint64, every time.Duration, fn func(context.Context, *rand.Rand)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := w.rng(id)
			for ctx.Err() == nil {
				fn(ctx, r)
				time.Sleep(time.Duration(r.Int64N(int64(every))) + time.Millisecond)
			}
		}()
	}
	// The clock keeps moving until the other actors are done: a scan or an
	// identify run in progress waits for simulated time.
	clockCtx, stopClock := context.WithCancel(context.Background())
	clockDone := make(chan struct{})
	go func() {
		defer close(clockDone)
		r := w.rng(1)
		for clockCtx.Err() == nil {
			w.tick(clockCtx, r)
			time.Sleep(time.Duration(r.Int64N(int64(40*time.Millisecond))) + time.Millisecond)
		}
	}()
	// About 150 frames a second, heavy for an OT LAN, with bursts that
	// overrun the bus now and then (it drops and counts, by design).
	traffic := func(iface string) func(context.Context, *rand.Rand) {
		return func(_ context.Context, r *rand.Rand) {
			n := 1
			if r.IntN(500) == 0 {
				n = 2000
				w.count("burst")
			}
			for range n {
				w.traffic(r, iface)
			}
		}
	}
	actor("traffic eth1", 2, 15*time.Millisecond, traffic("eth1"))
	actor("traffic eth2", 3, 30*time.Millisecond, traffic("eth2"))
	actor("lan changes", 4, 300*time.Millisecond, func(ctx context.Context, r *rand.Rand) {
		w.count(w.lans[[]string{"eth1", "eth2"}[r.IntN(2)]].mutate(r))
	})
	actor("neighbours", 5, 20*time.Millisecond, w.neighbour)
	actor("links", 6, 2*time.Second, w.link)
	actor("operator", 7, 150*time.Millisecond, w.operator)
	actor("reload", 8, 1500*time.Millisecond, w.reload)
	actor("reader 1", 9, 20*time.Millisecond, w.read)
	actor("reader 2", 10, 20*time.Millisecond, w.read)
	actor("offline reader", 11, 200*time.Millisecond, w.offline)
	actor("invariants", 12, 2*time.Second, func(ctx context.Context, r *rand.Rand) { w.checkInvariants() })
	wg.Wait()
	stop()
	stopClock()
	<-clockDone

	// Settle: interfaces up, probing stopped by the kill switch (so nothing
	// commits between the reads compared below), everything before it
	// committed.
	w.ifaces.SetLinks(w.links(true, "10.20.0.0/24"))
	// A busy daemon (503) is still draining the storm: ask again until the
	// barrier behind the kill switch passes.
	for range 20 {
		var busy bool
		w.call("final disable", func(ctx context.Context) error {
			_, err := w.client.DisableActive(ctx, "chaos done")
			busy = errors.Is(err, api.ErrBusy)
			return err
		})
		if !busy {
			break
		}
	}
	w.checkInvariants()
	w.compareOnlineOffline()

	w.signals <- syscall.SIGTERM
	select {
	case err := <-w.errc:
		if err != nil {
			w.fail("daemon stopped with %v", err)
		}
	case <-time.After(60 * time.Second):
		w.fail("daemon did not stop within 60s")
	}
	if _, err := os.Stat(w.dbPath + "-wal"); err == nil {
		w.fail("the WAL was left after a clean stop")
	}
	if ok := quickCheck(t, w.dbPath); ok != "ok" {
		w.fail("integrity after stop: %s", ok)
	}
	for _, line := range strings.Split(w.log.String(), "\n") {
		// A rejected reload is an operator's mistake, logged as an error on
		// purpose; any other error is a fault.
		if strings.Contains(line, "level=ERROR") && !strings.Contains(line, "configuration reload rejected") {
			w.fail("logged an error: %s", line)
		}
	}
	waitGoroutines(t, before)

	w.mu.Lock()
	defer w.mu.Unlock()
	t.Logf("chaos: %v", w.counts)
	t.Logf("chaos: slowest API answer %s (%s)", w.slowest.Round(time.Millisecond), w.slowestCall)
	if len(w.failures) > 0 {
		t.Errorf("%d invariant violations (LS_CHAOS_SEED=%d):\n  %s", len(w.failures), seed, strings.Join(w.failures, "\n  "))
		t.Logf("daemon log (last 4000 bytes):\n%s", tail(w.log.String(), 4000))
		w.keep(t)
	}
}

// keep copies the database and the whole daemon log of a failed run to
// LS_CHAOS_ARTIFACTS (default .build/chaos at the repository root), for
// lan-sentinel --offline or sqlite3.
func (w *world) keep(t *testing.T) {
	dir := os.Getenv("LS_CHAOS_ARTIFACTS")
	if dir == "" {
		dir = filepath.Join("..", "..", ".build", "chaos")
	}
	dir = filepath.Join(dir, strconv.FormatUint(w.seed, 10))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Logf("keep: %v", err)
		return
	}
	files := map[string][]byte{"daemon.log": []byte(w.log.String())}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if b, err := os.ReadFile(w.dbPath + suffix); err == nil {
			files["hosts.db"+suffix] = b
		}
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Logf("keep: %v", err)
		}
	}
	t.Logf("kept the database and the daemon log in %s", dir)
}

type nopNotifier struct{}

func (nopNotifier) Ready() error                    { return nil }
func (nopNotifier) Reloading() error                { return nil }
func (nopNotifier) Stopping() error                 { return nil }
func (nopNotifier) Watchdog() error                 { return nil }
func (nopNotifier) Status(string) error             { return nil }
func (nopNotifier) WatchdogInterval() (int64, bool) { return 0, false }

func (w *world) links(eth2Up bool, eth2Prefix string) []platform.Link {
	p := netip.MustParsePrefix(eth2Prefix)
	own := p.Addr().As4()
	own[3] = 2
	return []platform.Link{
		{Name: "eth1", Index: 2, MAC: frames.MAC("02:00:00:00:00:e1"), Up: true,
			Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.110.0/24")}, Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.110.2/24")}},
		{Name: "eth2", Index: 3, MAC: frames.MAC("02:00:00:00:00:e2"), Up: eth2Up,
			Prefixes: []netip.Prefix{p}, Addrs: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4(own), p.Bits())}},
	}
}

// scriptTransmitter makes the fake network answer probes: ARP for the
// LAN's hosts, echoes and UDP probes for some, TCP connects that succeed or
// are refused. Answers to UDP probes are sometimes garbage.
func (w *world) scriptTransmitter(tx *fake.Transmitter) {
	var mu sync.Mutex
	r := w.rng(100)
	tx.FrameReply = func(iface string, frame []byte) [][]byte {
		l := w.lans[iface]
		if l == nil || len(frame) < 42 {
			return nil
		}
		target, ok := netip.AddrFromSlice(frame[38:42])
		if !ok {
			return nil
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		for _, h := range l.hosts {
			if h.ip == target {
				return [][]byte{frames.ARP(layers.ARPReply, h.mac, h.ip.String(), frames.MAC("02:00:00:00:00:e1"), "192.168.110.2")}
			}
		}
		return nil
	}
	tx.EchoReply = func(dst netip.Addr, msg []byte) []byte {
		mu.Lock()
		defer mu.Unlock()
		if r.IntN(3) == 0 {
			return nil
		}
		return msg
	}
	tx.UDPReply = func(addr netip.AddrPort, payload []byte) []byte {
		mu.Lock()
		defer mu.Unlock()
		switch r.IntN(3) {
		case 0:
			return nil
		case 1:
			return payload // an echo: wrong for every protocol
		default:
			b := make([]byte, r.IntN(120))
			for i := range b {
				b[i] = byte(r.IntN(256))
			}
			return b
		}
	}
	tx.TCPResult = map[netip.AddrPort]error{}
	for _, l := range w.lans {
		for i, h := range l.hosts {
			if i%3 == 1 {
				tx.TCPResult[netip.AddrPortFrom(h.ip, 502)] = syscall.ECONNREFUSED
			}
		}
	}
}

// tick moves the simulated clock: mostly seconds, sometimes minutes, now
// and then more than a day (presence, expiry, compaction and retention).
func (w *world) tick(_ context.Context, r *rand.Rand) {
	var d time.Duration
	switch p := r.Float64(); {
	case p < 0.7:
		d = time.Duration(1+r.IntN(15)) * time.Second
	case p < 0.97:
		d = time.Duration(1+r.IntN(10)) * time.Minute
	default:
		d = time.Duration(1+r.IntN(30)) * time.Hour
		w.count("time_jump")
	}
	w.sim.Advance(d)
}

// traffic injects one captured frame: any decoded protocol from a LAN host,
// sometimes late, sometimes corrupted.
func (w *world) traffic(r *rand.Rand, iface string) {
	src := w.capt.Source(iface)
	if src == nil {
		return
	}
	l := w.lans[iface]
	h, other := l.pick(r), l.pick(r)
	ip, name := h.ip.String(), h.name
	var b []byte
	kind := r.IntN(14)
	switch kind {
	case 0:
		b = frames.ARP(layers.ARPReply, h.mac, ip, other.mac, other.ip.String())
	case 1:
		b = frames.ARP(layers.ARPRequest, h.mac, ip, frames.Broadcast, ip) // gratuitous
	case 2:
		b = frames.ARP(layers.ARPRequest, h.mac, "0.0.0.0", frames.Broadcast, ip) // probe
	case 3:
		b = frames.DHCP{Type: layers.DHCPMsgTypeRequest, Client: h.mac, ClientIP: ip, Hostname: name, VendorClass: "MSFT 5.0"}.Frame()
	case 4:
		b = frames.DHCP{Type: layers.DHCPMsgTypeAck, Client: h.mac, YourIP: ip, Server: other.mac, ServerIP: other.ip.String(),
			ServerID: other.ip.String(), LeaseSeconds: 3600}.Frame()
	case 5:
		b = frames.MDNS4(h.mac, ip, []layers.DNSResourceRecord{frames.A(name+".local", ip),
			frames.SRV(name+"._ipp._tcp.local", name+".local", 631)}, nil)
	case 6:
		b = frames.UDP4(other.mac, h.mac, other.ip.String(), ip, 53, 40000,
			frames.DNSResponse([]layers.DNSResourceRecord{frames.PTR(reverse(ip), name+".plant.example")}, nil))
	case 7:
		b = frames.LLDP{Source: h.mac, ChassisMAC: h.mac, PortID: "ge-0/0/" + strconv.Itoa(r.IntN(48)), TTL: 120,
			SystemName: name, SystemDesc: "fw " + strconv.Itoa(r.IntN(3)), Caps: 0x14}.Frame()
	case 8:
		b = frames.CDP{Source: h.mac, Holdtime: 180, DeviceID: name, PortID: "Gi1/0/" + strconv.Itoa(r.IntN(24)),
			Software: "IOS 15." + strconv.Itoa(r.IntN(3)), Platform: "cisco IE-4000", Caps: 0x28}.Frame()
	case 9:
		b = frames.NBNSRegistration(h.mac, ip, strings.ToUpper(name), byte([]int{0x00, 0x20, 0x1c, 0x03}[r.IntN(4)]), r.IntN(3) == 0)
	case 10:
		b = frames.Browser{Source: h.mac, IP: ip, Name: strings.ToUpper(name), Workgroup: "PLANT", Opcode: 0x01, OSMajor: 10,
			ServerType: 0x00001003}.Frame()
	case 11:
		b = frames.SSDPNotify(h.mac, ip, "urn:schemas-upnp-org:device:MediaRenderer:1", "uuid:"+name, "Linux/4.9 UPnP/1.0", "http://"+ip+"/d.xml")
	case 12:
		b = frames.WSDHello(h.mac, ip, "urn:uuid:"+name, "dn:NetworkVideoTransmitter", "onvif://www.onvif.org/hardware/CAM-"+name, "http://"+ip+"/onvif")
	default:
		b = frames.ICMPv4Echo(h.mac, other.mac, ip, other.ip.String())
	}
	if r.IntN(10) == 0 { // corrupted on the way
		b = append([]byte(nil), b...)
		for range 1 + r.IntN(4) {
			b[r.IntN(len(b))] = byte(r.IntN(256))
		}
		if r.IntN(2) == 0 {
			b = b[:r.IntN(len(b))+1]
		}
		w.count("corrupt_frame")
	}
	at := w.sim.Now()
	if r.IntN(10) == 0 {
		at = at.Add(-time.Duration(r.IntN(600)) * time.Second) // late
	}
	src.Inject(at, b)
	w.count("frame")
}

func reverse(ip string) string {
	p := strings.Split(ip, ".")
	return p[3] + "." + p[2] + "." + p[1] + "." + p[0] + ".in-addr.arpa"
}

// neighbour emits a kernel neighbour event: resolved, stale, failed,
// deleted, now and then a resync.
func (w *world) neighbour(_ context.Context, r *rand.Rand) {
	iface := []string{"eth1", "eth2"}[r.IntN(2)]
	h := w.lans[iface].pick(r)
	states := []string{"REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "INCOMPLETE"}
	w.neigh.Emit(platform.NeighborEvent{
		Time:     w.sim.Now(),
		Neighbor: platform.Neighbor{Interface: iface, IP: h.ip, MAC: h.mac, State: states[r.IntN(len(states))], ConfirmedAgo: time.Duration(r.IntN(300)) * time.Second},
		Deleted:  r.IntN(10) == 0,
		Resync:   r.IntN(50) == 0,
	})
	w.count("neighbour_event")
}

// link takes eth2 down and up, removes and re-adds it, and readdresses it.
func (w *world) link(_ context.Context, r *rand.Rand) {
	prefix := []string{"10.20.0.0/24", "10.20.0.0/24", "10.21.0.0/24"}[r.IntN(3)]
	up := r.IntN(3) != 0
	links := w.links(up, prefix)
	w.ifaces.SetLinks(links)
	w.ifaces.Emit(platform.LinkEvent{Time: w.sim.Now(), Link: links[1], Removed: r.IntN(8) == 0})
	if r.IntN(10) == 0 {
		w.ifaces.Emit(platform.LinkEvent{Time: w.sim.Now(), Link: links[0]}) // eth1 unchanged
	}
	w.count("link_event")
}

// call runs an API call; a server error (500), a broken connection or no
// answer within two minutes (a hang, not a slow answer under load) is a
// violation, refusals and conflicts are expected. The slowest answer is
// reported.
func (w *world) call(what string, fn func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	start := time.Now()
	err := fn(ctx)
	took := time.Since(start)
	w.count(what)
	w.mu.Lock()
	if took > w.slowest {
		w.slowest, w.slowestCall = took, what
	}
	w.mu.Unlock()
	var ae *api.Error
	switch {
	case err == nil:
	case errors.As(err, &ae) && ae.Status != 500, errors.Is(err, scheduler.ErrScanRefused):
		w.count(what + " refused")
	case errors.Is(err, context.DeadlineExceeded):
		w.fail("%s: no answer within 2 minutes", what)
	default:
		w.fail("%s: %v", what, err)
	}
}

func (w *world) someHost(ctx context.Context, r *rand.Rand) (store.HostSummary, bool) {
	hosts, err := w.client.Hosts(ctx, store.HostFilter{})
	if err != nil || len(hosts) == 0 {
		return store.HostSummary{}, false
	}
	return hosts[r.IntN(len(hosts))], true
}

// operator does what an operator does, often at the worst moment.
func (w *world) operator(_ context.Context, r *rand.Rand) {
	switch r.IntN(8) {
	case 0:
		w.call("active disable", func(ctx context.Context) error { _, err := w.client.DisableActive(ctx, "chaos"); return err })
	case 1:
		w.call("active enable", func(ctx context.Context) error { _, err := w.client.EnableActive(ctx, "chaos"); return err })
	case 2, 3:
		req := probe.Request{ARP: true, ICMP: r.IntN(2) == 0}
		if r.IntN(2) == 0 {
			req.TCP = []int{502}
		}
		if r.IntN(3) == 0 {
			req.Interfaces = []string{"eth2"}
		}
		w.call("scan", func(ctx context.Context) error { _, err := w.client.Scan(ctx, req); return err })
	case 4:
		w.call("scan plan", func(ctx context.Context) error {
			_, err := w.client.PlanScan(ctx, probe.Request{ARP: true})
			return err
		})
	case 5:
		w.call("describe", func(ctx context.Context) error {
			h, ok := w.someHost(ctx, r)
			if !ok {
				return nil
			}
			text := []string{"", "Line 3 PLC", "rooftop inverter", strings.Repeat("x", 300)}[r.IntN(4)]
			_, err := w.client.SetDescription(ctx, h.HostID, text)
			return err
		})
	case 6:
		w.call("identify run", func(ctx context.Context) error {
			h, ok := w.someHost(ctx, r)
			if !ok {
				return nil
			}
			_, err := w.client.IdentifyRun(ctx, h.HostID, config.IdentifyProbeNames[r.IntN(len(config.IdentifyProbeNames))], "")
			return err
		})
	default:
		w.signals <- syscall.SIGHUP
		w.count("sighup")
	}
}

// reload writes a new configuration, sometimes an invalid one, and asks
// the daemon to apply it.
func (w *world) reload(_ context.Context, r *rand.Rand) {
	text := w.configText(r)
	if r.IntN(6) == 0 {
		text = strings.Replace(text, "presence: {", "presence: { nonsense: 1, ", 1) // unknown key: rejected as a whole
		w.count("invalid config")
	}
	w.writeConfig(text)
	w.call("reload", func(ctx context.Context) error { _, err := w.client.ReloadConfig(ctx); return err })
}

// read asks the API what an operator or a dashboard would.
func (w *world) read(_ context.Context, r *rand.Rand) {
	l := w.lans[[]string{"eth1", "eth2"}[r.IntN(2)]]
	h := l.pick(r)
	at := w.sim.Now().Add(-time.Duration(r.IntN(48*3600)) * time.Second)
	queries := []string{h.ip.String(), h.mac.String(), h.name + ".local", h.name}
	q := queries[r.IntN(len(queries))]
	switch r.IntN(12) {
	case 0:
		w.call("read hosts", func(ctx context.Context) error {
			_, err := w.client.Hosts(ctx, store.HostFilter{Interface: l.iface, Live: r.IntN(2) == 0, Query: q})
			return err
		})
	case 1:
		w.call("read find", func(ctx context.Context) error { _, err := w.client.Find(ctx, store.FindQuery{Query: q}); return err })
	case 2:
		w.call("read find at", func(ctx context.Context) error {
			_, err := w.client.Find(ctx, store.FindQuery{Query: h.ip.String(), Interface: l.iface, At: &at})
			return err
		})
	case 3:
		w.call("read history", func(ctx context.Context) error {
			_, err := w.client.History(ctx, store.HistoryQuery{Query: q, Since: at})
			return err
		})
	case 4:
		w.call("read evidence", func(ctx context.Context) error {
			_, err := w.client.EvidenceFor(ctx, store.HostFilter{Query: h.mac.String()}, at)
			return err
		})
	case 5:
		w.call("read events", func(ctx context.Context) error {
			_, err := w.client.Events(ctx, store.EventFilter{Since: at, Limit: 200})
			return err
		})
	case 6:
		w.call("read observations", func(ctx context.Context) error {
			_, err := w.client.Observations(ctx, store.ObservationFilter{Interface: l.iface, Limit: 100})
			return err
		})
	case 7:
		w.call("read interfaces", func(ctx context.Context) error { _, err := w.client.Interfaces(ctx); return err })
	case 8:
		w.call("read status", func(ctx context.Context) error { _, err := w.client.Status(ctx); return err })
	case 9:
		w.call("read dhcp", func(ctx context.Context) error {
			_, err := w.client.DHCPServers(ctx, store.DHCPServerFilter{})
			return err
		})
	case 10:
		w.call("read services", func(ctx context.Context) error {
			_, err := w.client.Services(ctx, store.ServiceFilter{})
			return err
		})
	default:
		w.call("read db", func(ctx context.Context) error { _, err := w.client.DBInfo(ctx); return err })
	}
}

// offline runs CLI commands on the database file beside the running
// writer, as an operator with --offline would.
func (w *world) offline(_ context.Context, r *rand.Rand) {
	h := w.lans["eth1"].pick(r)
	cmds := [][]string{
		{"hosts", "list", "-o", "json"},
		{"hosts", "find", h.ip.String()},
		{"hosts", "history", h.mac.String()},
		{"events", "list", "--since", "2h"},
		{"interfaces", "list"},
		{"db", "check"},
	}
	args := append([]string{"--offline"}, cmds[r.IntN(len(cmds))]...)
	code, out := w.cli(args...)
	w.count("offline")
	if code != 0 && code != cli.ExitDegraded {
		w.fail("%s: exit %d: %s", strings.Join(args, " "), code, tail(out, 400))
	}
}

func (w *world) cli(args ...string) (int, string) {
	var out, errb bytes.Buffer
	code := cli.Execute(context.Background(), cli.Env{Args: args, Stdout: &out, Stderr: &errb, Location: time.UTC,
		Environ: []string{"LAN_SENTINEL_CONFIG=" + w.offlineCfg}})
	return code, out.String() + errb.String()
}

// invariants are statements about the stored model that must hold at any
// committed moment (docs/DATA_MODEL.md §3–§5).
var invariants = []struct{ name, query string }{
	{"one open name per host and type",
		`SELECT host_id || ' ' || name_type FROM names WHERE ended_at IS NULL GROUP BY host_id, name_type HAVING count(*) > 1`},
	{"two open bindings of one address on an interface are a conflict",
		`SELECT context_id || ' ' || ip FROM addresses WHERE ended_at IS NULL GROUP BY context_id, ip HAVING count(*) > 1 AND min(conflict) = 0`},
	{"bindings end after they start",
		`SELECT id FROM addresses WHERE ended_at IS NOT NULL AND ended_at < first_seen UNION ALL
		 SELECT id FROM names WHERE ended_at IS NOT NULL AND ended_at < first_seen`},
	{"bindings are last seen no earlier than first seen",
		`SELECT id FROM addresses WHERE last_seen < first_seen UNION ALL SELECT id FROM names WHERE last_seen < first_seen`},
	{"one current claim per host, field and source",
		`SELECT host_id || ' ' || field || ' ' || source FROM identifications WHERE current = 1 GROUP BY host_id, field, source HAVING count(*) > 1`},
	{"the preferred name is an open name of the host",
		`SELECT h.host_id || ' ' || h.preferred_name FROM hosts h WHERE h.preferred_name IS NOT NULL AND NOT EXISTS (
			SELECT 1 FROM names n WHERE n.host_id = h.host_id AND n.name = h.preferred_name AND n.ended_at IS NULL)`},
	{"the device type is a current device type claim",
		`SELECT h.host_id || ' ' || h.device_type FROM hosts h WHERE h.device_type IS NOT NULL AND NOT EXISTS (
			SELECT 1 FROM identifications i WHERE i.host_id = h.host_id AND i.field = 'device_type' AND i.value = h.device_type AND i.current = 1)`},
	{"one host per MAC on an interface",
		`SELECT context_id || ' ' || mac FROM hosts GROUP BY context_id, mac HAVING count(*) > 1`},
}

func (w *world) checkInvariants() {
	db, err := sql.Open("sqlite", "file:"+w.dbPath+"?mode=ro&_pragma=busy_timeout(10000)")
	if err != nil {
		w.fail("open for invariants: %v", err)
		return
	}
	defer db.Close()
	var ok string
	if err := db.QueryRow(`PRAGMA quick_check`).Scan(&ok); err != nil || ok != "ok" {
		w.fail("quick_check: %q %v", ok, err)
	}
	for _, inv := range invariants {
		rows, err := db.Query(inv.query)
		if err != nil {
			w.fail("%s: %v", inv.name, err)
			continue
		}
		var bad []string
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			bad = append(bad, s)
		}
		rows.Close()
		if len(bad) > 0 {
			w.fail("%s: %v", inv.name, bad)
		}
	}
	w.count("invariant check")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := w.client.Status(ctx); err != nil {
		w.fail("daemon unresponsive: %v", err)
	}
	select {
	case err := <-w.errc:
		w.fail("daemon exited during the run: %v", err)
		w.errc <- err
	default:
	}
}

// compareOnlineOffline: the API and --offline answer the same queries from
// the same committed data (docs/CLI.md §1).
func (w *world) compareOnlineOffline() {
	for _, args := range [][]string{{"hosts", "list", "-o", "json"}, {"events", "list", "-o", "json", "--limit", "500"}} {
		codeOn, on := w.cli(args...)
		codeOff, off := w.cli(append([]string{"--offline"}, args...)...)
		if codeOn != codeOff || on != off {
			w.fail("%s: online (exit %d) and offline (exit %d) answers differ:\n%s\n---\n%s", strings.Join(args, " "), codeOn, codeOff,
				tail(on, 600), tail(off, 600))
		}
	}
}

func quickCheck(t *testing.T, path string) string {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var ok string
	if err := db.QueryRow(`PRAGMA quick_check`).Scan(&ok); err != nil {
		return err.Error()
	}
	return ok
}

// waitGoroutines fails if the daemon left goroutines running after Run
// returned (allowing for the test's own and the runtime's).
func waitGoroutines(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > before+5 {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			n := runtime.Stack(buf, true)
			t.Errorf("%d goroutines after stop, %d before:\n%s", runtime.NumGoroutine(), before, buf[:n])
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func tail(s string, n int) string {
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}
