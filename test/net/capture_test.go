//go:build nettest

package nettest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"lan-sentinel/internal/collect/capture"
	"lan-sentinel/internal/collect/capture/decoders"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/daemon"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/test/frames"
)

// Simulated devices that exist only as injected frames.
var (
	injPLC  = frames.MAC("02:00:00:00:fb:01")
	injHMI  = frames.MAC("02:00:00:00:fb:02")
	injSRV  = frames.MAC("02:00:00:00:fb:03")
	injSW   = frames.MAC("02:00:00:00:fb:04")
	injFake = frames.MAC("02:00:00:00:fb:05")
)

// inject writes frames as a pcap file into the sync directory and asks
// run.sh to send them from another container repeat times.
func inject(t *testing.T, repeat int, fs ...[]byte) {
	t.Helper()
	name := fmt.Sprintf("frames-%d.pcap", time.Now().UnixNano())
	f, err := os.Create(filepath.Join(env(t, "LS_TEST_SYNC"), name))
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for _, fr := range fs {
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(fr), Length: len(fr)}, fr); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	request(t, "inject", name, strconv.Itoa(repeat))
}

// discoveryFrames are one frame of every decoded protocol. LLDP goes to
// the broadcast address: Linux bridges do not forward the 802.1D reserved
// group addresses (01:80:c2:00:00:0x) LLDP normally uses.
func discoveryFrames(t *testing.T, runnerMAC net.HardwareAddr, prefix netip.Prefix) [][]byte {
	ipOf := func(n byte) string {
		a := prefix.Masked().Addr().As4()
		a[3] = n
		return netip.AddrFrom4(a).String()
	}
	lldp := frames.LLDP{Source: injSW, ChassisMAC: injSW, PortID: "ge-0/0/23", TTL: 120, SystemName: "test-sw-01"}.Frame()
	copy(lldp[:6], frames.Broadcast)
	out := [][]byte{
		frames.ARP(layers.ARPRequest, injPLC, ipOf(101), frames.Broadcast, ipOf(101)), // gratuitous
		frames.DHCP{Type: layers.DHCPMsgTypeDiscover, Client: injHMI, Hostname: "HMI-TEST"}.Frame(),
		frames.MDNS4(injPLC, ipOf(101), []layers.DNSResourceRecord{
			frames.SRV("PLC._http._tcp.local", "plc-test.local", 80), frames.A("plc-test.local", ipOf(101)),
		}, nil),
		frames.UDP4(injSRV, runnerMAC, ipOf(103), ipOf(2), 53, 40000, frames.DNSResponse(
			[]layers.DNSResourceRecord{frames.PTR(reverse(ipOf(101)), "plc-test.plant.example.")}, nil)),
		lldp,
	}
	if os.Getenv("LS_TEST_IPV6") == "1" {
		out = append(out, frames.NeighborAdvertisement(injPLC, "fe80::ff:fe00:fb01", "fe80::ff:fe00:fb01", 0x20))
	}
	return out
}

func reverse(ip string) string {
	p := strings.Split(ip, ".")
	slices.Reverse(p)
	return strings.Join(p, ".") + ".in-addr.arpa"
}

func summary(o observation.Observation) string {
	parts := []string{string(o.Source)}
	if o.MAC != nil {
		parts = append(parts, o.MAC.String())
	}
	if o.IP.IsValid() {
		parts = append(parts, o.IP.String())
	}
	if o.Hostname != "" {
		parts = append(parts, string(o.NameType)+":"+o.Hostname)
	}
	return strings.Join(parts, " ")
}

// collect reads frames until every wanted summary was decoded or the
// timeout passes, calling poke while waiting; it returns every summary.
func collect(t *testing.T, src platform.FrameSource, iface string, want []string, timeout time.Duration, poke func()) []string {
	t.Helper()
	dec := capture.NewDecoder(decoders.All)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	seen := map[string]bool{}
	var all []string
	missing := func() []string {
		var m []string
		for _, w := range want {
			if !seen[w] {
				m = append(m, w)
			}
		}
		return m
	}
	next := time.Now()
	for len(missing()) > 0 {
		if poke != nil && time.Now().After(next) {
			poke()
			next = time.Now().Add(time.Second)
		}
		rctx, rcancel := context.WithTimeout(ctx, 500*time.Millisecond)
		f, err := src.ReadFrame(rctx)
		rcancel()
		if ctx.Err() != nil {
			t.Fatalf("not captured within %s:\n  %s\ncaptured:\n  %s", timeout, strings.Join(missing(), "\n  "), strings.Join(all, "\n  "))
		}
		if err != nil {
			continue
		}
		for _, o := range dec.Decode(f.Time, iface, f.Data) {
			s := summary(o)
			if !seen[s] {
				seen[s] = true
				all = append(all, s)
			}
		}
	}
	return all
}

func ownMAC(t *testing.T, iface string) net.HardwareAddr {
	t.Helper()
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		t.Fatal(err)
	}
	return ifi.HardwareAddr
}

func openCapture(t *testing.T, iface string, o platform.CaptureOptions) platform.FrameSource {
	t.Helper()
	filter, err := capture.Filter(decoders.All)
	if err != nil {
		t.Fatal(err)
	}
	o.Filter = filter
	src, err := platform.New().Capturer.Open(context.Background(), iface, o)
	if err != nil {
		t.Fatalf("open capture as uid %d: %v", os.Getuid(), err)
	}
	t.Cleanup(func() { _ = src.Close() })
	return src
}

// TestCaptureDecodesDiscoveryFrames: frames of every decoded protocol from
// other MACs pass the kernel filter and decode, as uid 65534 with only
// CAP_NET_RAW.
func TestCaptureDecodesDiscoveryFrames(t *testing.T) {
	iface := env(t, "LS_TEST_IFACE")
	prefix := netip.MustParsePrefix(env(t, "LS_TEST_PREFIX"))
	src := openCapture(t, iface, platform.CaptureOptions{})
	ipOf := func(n byte) string {
		a := prefix.Masked().Addr().As4()
		a[3] = n
		return netip.AddrFrom4(a).String()
	}
	want := []string{
		"passive_arp " + injPLC.String() + " " + ipOf(101),
		"passive_dhcp " + injHMI.String() + " dhcp:HMI-TEST",
		"passive_mdns " + injPLC.String() + " " + ipOf(101) + " mdns:plc-test.local",
		"passive_dns " + ipOf(101) + " dns_ptr:plc-test.plant.example", // DNS answers carry no MAC
		"passive_ipv4 " + injSRV.String() + " " + ipOf(103),
		"passive_lldp " + injSW.String() + " lldp:test-sw-01",
	}
	if os.Getenv("LS_TEST_IPV6") == "1" {
		want = append(want, "passive_ndp "+injPLC.String()+" fe80::ff:fe00:fb01")
	}
	// The ring keeps the frames until they are read.
	inject(t, 1, discoveryFrames(t, ownMAC(t, iface), prefix)...)
	got := collect(t, src, iface, want, 30*time.Second, nil)
	t.Logf("captured:\n  %s", strings.Join(got, "\n  "))
}

// TestCaptureIgnoresOwnFrames: the box's own frames are not captured
// (PACKET_OUTGOING, and broadcasts a hairpin bridge port reflects back),
// while replies from other hosts arrive. It pings hosts the neighbour tests
// do not need fresh: those expect to see entries appear.
func TestCaptureIgnoresOwnFrames(t *testing.T) {
	iface := env(t, "LS_TEST_IFACE")
	closed, plc := ip(t, "LS_TEST_CLOSED"), ip(t, "LS_TEST_PLC")
	closedMAC := env(t, "LS_TEST_CLOSED_MAC")
	own := ownMAC(t, iface).String()
	src := openCapture(t, iface, platform.CaptureOptions{})
	got := collect(t, src, iface, []string{"passive_ipv4 " + closedMAC + " " + closed.String()}, 20*time.Second, func() {
		ping(t, closed)
		ping(t, plc)
	})
	for _, s := range got {
		if strings.Contains(s, own) {
			t.Errorf("captured this host's own frame: %s", s)
		}
	}
}

// TestCaptureSkipsVLANFrames: the kernel strips 802.1Q tags before the
// filter runs, so frames of a VLAN would otherwise look untagged. The
// filter drops them (VLANs are out of scope) and keeps priority-tagged
// frames (VLAN ID 0), which belong to the untagged network.
func TestCaptureSkipsVLANFrames(t *testing.T) {
	iface := env(t, "LS_TEST_IFACE")
	vlanMAC, prioMAC := frames.MAC("02:00:00:00:fb:10"), frames.MAC("02:00:00:00:fb:11")
	tag := func(frame []byte, vid uint16) []byte {
		return slices.Concat(frame[:12], []byte{0x81, 0x00, 0xc0 | byte(vid>>8), byte(vid)}, frame[12:])
	}
	src := openCapture(t, iface, platform.CaptureOptions{})
	inject(t, 3,
		tag(frames.ARP(layers.ARPRequest, vlanMAC, "172.31.250.110", frames.Broadcast, "172.31.250.110"), 100),
		tag(frames.ARP(layers.ARPRequest, prioMAC, "172.31.250.111", frames.Broadcast, "172.31.250.111"), 0))
	got := collect(t, src, iface, []string{"passive_arp " + prioMAC.String() + " 172.31.250.111"}, 20*time.Second, nil)
	// Read what else arrived for a moment: the VLAN 100 frames must not.
	got = append(got, collectFor(src, iface, 2*time.Second)...)
	for _, s := range got {
		if strings.Contains(s, vlanMAC.String()) {
			t.Errorf("captured a VLAN 100 frame: %s", s)
		}
	}
}

// collectFor returns the summaries decoded from frames read for d.
func collectFor(src platform.FrameSource, iface string, d time.Duration) []string {
	dec := capture.NewDecoder(decoders.All)
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var out []string
	for ctx.Err() == nil {
		f, err := src.ReadFrame(ctx)
		if err != nil {
			continue
		}
		for _, o := range dec.Decode(f.Time, iface, f.Data) {
			out = append(out, summary(o))
		}
	}
	return out
}

// TestCaptureRefusesDownInterface: an administratively down interface is
// refused with ErrLinkDown (no socket, no promiscuous toggling) until it
// comes up.
func TestCaptureRefusesDownInterface(t *testing.T) {
	const name = "lsdown0"
	request(t, "down-iface-add", name)
	defer request(t, "down-iface-del", name)
	capt := platform.New().Capturer
	_, err := capt.Open(context.Background(), name, platform.CaptureOptions{Promiscuous: true})
	if !errors.Is(err, platform.ErrLinkDown) {
		t.Fatalf("open on a down interface: %v, want ErrLinkDown", err)
	}
	request(t, "down-iface-up", name)
	src, err := capt.Open(context.Background(), name, platform.CaptureOptions{})
	if err != nil {
		t.Fatalf("open after the interface came up: %v", err)
	}
	_ = src.Close()
}

// TestCapturePromiscuous: PACKET_ADD_MEMBERSHIP sets the interface
// promiscuous with only CAP_NET_RAW, and closing the socket clears it.
func TestCapturePromiscuous(t *testing.T) {
	iface := env(t, "LS_TEST_IFACE")
	flags := func() int64 {
		t.Helper()
		b, err := os.ReadFile("/sys/class/net/" + iface + "/flags")
		if err != nil {
			t.Fatal(err)
		}
		v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 0, 64)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if flags()&syscall.IFF_PROMISC != 0 {
		t.Skip("interface already promiscuous")
	}
	filter, _ := capture.Filter(decoders.All)
	src, err := platform.New().Capturer.Open(context.Background(), iface, platform.CaptureOptions{Filter: filter, Promiscuous: true})
	if err != nil {
		t.Fatal(err)
	}
	if flags()&syscall.IFF_PROMISC == 0 {
		t.Error("interface not promiscuous while capturing")
	}
	_ = src.Close()
	if flags()&syscall.IFF_PROMISC != 0 {
		t.Error("interface still promiscuous after close")
	}
}

// TestCaptureDropCounter: a full ring drops frames in the kernel and the
// drop counter reports them.
func TestCaptureDropCounter(t *testing.T) {
	iface := env(t, "LS_TEST_IFACE")
	src := openCapture(t, iface, platform.CaptureOptions{RingSize: 256 << 10})
	// Nobody reads: 20,000 frames overflow a 256 KiB ring.
	inject(t, 20000, frames.ARP(layers.ARPReply, injFake, "172.31.250.105", frames.Broadcast, "172.31.250.2"))
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, err := src.Stats()
		if err != nil {
			t.Fatal(err)
		}
		if st.Dropped > 0 && st.Received > st.Dropped {
			t.Logf("received %d, dropped %d", st.Received, st.Dropped)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no drops counted: %+v", st)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestDaemonCapturesNames: the daemon's capture collector turns injected
// frames into hosts with names, and reports the collector running.
func TestDaemonCapturesNames(t *testing.T) {
	iface := env(t, "LS_TEST_IFACE")
	prefix := netip.MustParsePrefix(env(t, "LS_TEST_PREFIX"))
	dir := t.TempDir()
	cfgPath, db := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "hosts.db")
	cfg := "version: 1\ninterfaces:\n  - name: " + iface + "\npassive: { protocols: { ipv6: true } }\n" +
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
	waitLog := func(want string, timeout time.Duration) bool {
		deadline := time.Now().Add(timeout)
		for !strings.Contains(log.String(), want) {
			if time.Now().After(deadline) {
				return false
			}
			time.Sleep(100 * time.Millisecond)
		}
		return true
	}
	if !waitLog("capture started", 30*time.Second) {
		t.Fatalf("capture did not start:\n%s", log)
	}
	wants := []string{
		"HOSTNAME_ADDED " + iface + " " + injPLC.String() + " mdns:plc-test.local",
		"HOSTNAME_ADDED " + iface + " " + injHMI.String() + " dhcp:HMI-TEST",
		"HOSTNAME_ADDED " + iface + " " + injSW.String() + " lldp:test-sw-01",
	}
	for attempt := 1; ; attempt++ {
		inject(t, 1, discoveryFrames(t, ownMAC(t, iface), prefix)...)
		missing := ""
		for _, want := range wants {
			if !waitLog(want, 10*time.Second) {
				missing = want
				break
			}
		}
		if missing == "" {
			break
		}
		if attempt == 3 {
			t.Fatalf("log never showed %q:\n%s", missing, log)
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
	var name string
	if err := conn.QueryRow(`SELECT preferred_name FROM hosts WHERE mac = ?`, injPLC.String()).Scan(&name); err != nil || name != "plc-test.local" {
		t.Errorf("preferred name of the PLC = %q, %v", name, err)
	}
	var dnsNames int
	if err := conn.QueryRow(`SELECT count(*) FROM names WHERE name_type = 'dns_ptr' AND name = 'plc-test.plant.example'`).Scan(&dnsNames); err != nil || dnsNames != 1 {
		t.Errorf("dns_ptr names = %d, %v; want the PTR answer attached to the PLC", dnsNames, err)
	}
}
