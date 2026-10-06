package capture

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/collect/capture/decoders"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/platform/fake"
	"lan-sentinel/test/frames"
)

var (
	t0     = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	plc    = frames.MAC("00:1b:1b:aa:bb:01")
	hmi    = frames.MAC("00:0e:8c:11:22:33")
	server = frames.MAC("02:00:00:00:00:53")
	sw     = frames.MAC("00:1e:c9:00:00:01")
)

func arpReply() []byte {
	return frames.ARP(layers.ARPReply, plc, "192.168.110.50", hmi, "192.168.110.20")
}

func TestFilter(t *testing.T) {
	big := make([]byte, 600) // payload so full and header snaps differ
	tcp := frames.Build(frames.Ethernet(hmi, plc, layers.EthernetTypeIPv4), frames.IPv4("192.168.110.20", "192.168.110.50", layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 40000, DstPort: 502}, gopacket.Payload(big))
	tcp6 := frames.Build(frames.Ethernet(hmi, plc, layers.EthernetTypeIPv6), frames.IPv6("fe80::2", "fe80::1", layers.IPProtocolTCP, 64),
		&layers.TCP{SrcPort: 40000, DstPort: 502}, gopacket.Payload(big))
	echo6 := frames.Build(frames.Ethernet(hmi, plc, layers.EthernetTypeIPv6), frames.IPv6("fe80::2", "fe80::1", layers.IPProtocolICMPv6, 64),
		&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}, &layers.ICMPv6Echo{}, gopacket.Payload(big))
	dhcp := frames.DHCP{Type: layers.DHCPMsgTypeDiscover, Client: hmi, Hostname: "hmi"}.Frame()
	dhcpReply := frames.DHCP{Type: layers.DHCPMsgTypeAck, Client: hmi, YourIP: "192.168.110.21", Server: server, ServerIP: "192.168.110.2"}.Frame()
	mdns := frames.MDNS4(plc, "192.168.110.50", []layers.DNSResourceRecord{frames.A("plc-1.local", "192.168.110.50")}, nil)
	mdns6 := frames.UDP6(plc, frames.MDNSv6, "fe80::1", "ff02::fb", 5353, 5353,
		frames.DNSResponse([]layers.DNSResourceRecord{frames.A("plc-1.local", "fe80::1")}, nil))
	dns := frames.UDP4(server, hmi, "192.168.110.2", "192.168.110.20", 53, 40000,
		frames.DNSResponse([]layers.DNSResourceRecord{frames.PTR("50.110.168.192.in-addr.arpa", "plc-1")}, nil))
	dnsQuery := frames.UDP4(hmi, server, "192.168.110.20", "192.168.110.2", 40000, 53, &layers.DNS{
		Questions: []layers.DNSQuestion{{Name: []byte("plc-1"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}})
	otherUDP := frames.UDP4(hmi, plc, "192.168.110.20", "192.168.110.50", 40000, 161, gopacket.Payload(big))
	fragment := frames.Build(frames.Ethernet(hmi, plc, layers.EthernetTypeIPv4),
		&layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, FragOffset: 100,
			SrcIP: frames.IP("192.168.110.20").To4(), DstIP: frames.IP("192.168.110.50").To4()}, gopacket.Payload(big))
	na := frames.NeighborAdvertisement(plc, "fe80::1", "fd5e:5e:1::50", 0x20)
	lldp := frames.LLDP{Source: sw, ChassisMAC: sw, PortID: "1", TTL: 120}.Frame()
	stp := frames.Build(frames.Ethernet(sw, frames.MAC("01:80:c2:00:00:00"), layers.EthernetType(0x0026)), gopacket.Payload(big))

	const (
		full   = snapFull
		header = snapHeader
		drop   = 0
	)
	tests := []struct {
		name  string
		p     decoders.Protocols
		frame []byte
		want  int
	}{
		{"arp", decoders.All, arpReply(), full},
		{"arp disabled", decoders.Protocols{IPv4: true}, arpReply(), drop},
		{"lldp", decoders.All, lldp, full},
		{"tcp header only", decoders.All, tcp, header},
		{"tcp without ipv4 learning", decoders.Protocols{DHCP: true}, tcp, drop},
		{"dhcp client", decoders.All, dhcp, full},
		{"dhcp server", decoders.Protocols{DHCP: true}, dhcpReply, full},
		{"dhcp disabled", decoders.Protocols{IPv4: true}, dhcp, header},
		{"mdns", decoders.Protocols{MDNS: true}, mdns, full},
		{"dns response", decoders.Protocols{DNS: true}, dns, full},
		{"dns query", decoders.Protocols{DNS: true, IPv4: true}, dnsQuery, header},
		{"other udp", decoders.All, otherUDP, header},
		{"fragment", decoders.All, fragment, header},
		{"ndp", decoders.All, na, full},
		{"icmpv6 echo", decoders.All, echo6, header},
		{"tcp over ipv6", decoders.All, tcp6, header},
		{"mdns over ipv6", decoders.All, mdns6, full},
		{"ipv6 disabled", decoders.Protocols{ARP: true, IPv4: true, MDNS: true}, na, drop},
		{"other ethertype", decoders.All, stp, drop},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog, err := assemble(tt.p, false)
			if err != nil {
				t.Fatal(err)
			}
			vm, err := bpf.NewVM(disassemble(t, prog))
			if err != nil {
				t.Fatal(err)
			}
			got, err := vm.Run(tt.frame)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("snap = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFilterDropsOutgoing(t *testing.T) {
	prog, err := Filter(decoders.All)
	if err != nil {
		t.Fatal(err)
	}
	ins := disassemble(t, prog)
	if ext, ok := ins[0].(bpf.LoadExtension); !ok || ext.Num != bpf.ExtType {
		t.Fatalf("first instruction = %v, want the packet-type load", ins[0])
	}
	jump, ok := ins[1].(bpf.JumpIf)
	if !ok || jump.Val != packetOutgoing {
		t.Fatalf("second instruction = %v", ins[1])
	}
	if ret, ok := ins[2+int(jump.SkipTrue)].(bpf.RetConstant); !ok || ret.Val != 0 {
		t.Errorf("outgoing frames jump to %v, want ret #0", ins[2+int(jump.SkipTrue)])
	}
	// Then the VLAN check: tagged frames with a VLAN ID are dropped.
	if ext, ok := ins[2].(bpf.LoadExtension); !ok || ext.Num != bpf.ExtVLANTagPresent {
		t.Fatalf("third instruction = %v, want the VLAN-present load", ins[2])
	}
	if ext, ok := ins[4].(bpf.LoadExtension); !ok || ext.Num != bpf.ExtVLANTag {
		t.Fatalf("fifth instruction = %v, want the VLAN tag load", ins[4])
	}
	vid, ok := ins[5].(bpf.JumpIf)
	if !ok || vid.Cond != bpf.JumpBitsSet || vid.Val != vlanIDMask {
		t.Fatalf("sixth instruction = %v", ins[5])
	}
	if ret, ok := ins[6+int(vid.SkipTrue)].(bpf.RetConstant); !ok || ret.Val != 0 {
		t.Errorf("VLAN frames jump to %v, want ret #0", ins[6+int(vid.SkipTrue)])
	}
	var a asm
	a.jump("nowhere")
	if _, err := a.assemble(); err == nil {
		t.Error("undefined label accepted")
	}
}

func disassemble(t *testing.T, prog []bpf.RawInstruction) []bpf.Instruction {
	t.Helper()
	ins, ok := bpf.Disassemble(prog)
	if !ok {
		t.Fatal("program does not disassemble")
	}
	return ins
}

func TestDecoderSuppressesRepeats(t *testing.T) {
	d := NewDecoder(decoders.All)
	frame := arpReply()
	if n := len(d.Decode(t0, "eth1", frame)); n != 1 {
		t.Fatalf("first frame: %d observations", n)
	}
	if n := len(d.Decode(t0.Add(time.Minute), "eth1", frame)); n != 0 {
		t.Errorf("repeat within the interval emitted %d", n)
	}
	if n := len(d.Decode(t0.Add(time.Minute), "eth2", frame)); n != 1 {
		t.Errorf("same frame on another interface emitted %d", n)
	}
	gratuitous := frames.ARP(layers.ARPRequest, plc, "192.168.110.50", frames.Broadcast, "192.168.110.50")
	if n := len(d.Decode(t0.Add(time.Minute), "eth1", gratuitous)); n != 1 {
		t.Errorf("different metadata emitted %d", n)
	}
	if n := len(d.Decode(t0.Add(RefreshInterval), "eth1", frame)); n != 1 {
		t.Errorf("refresh after the interval emitted %d", n)
	}
	if n := len(d.Decode(t0, "eth1", frame)); n != 1 {
		t.Errorf("a frame from before the last emission (clock step back) emitted %d", n)
	}
	if n := len(d.Decode(t0, "eth1", []byte{1})); n != 0 {
		t.Errorf("garbage emitted %d", n)
	}
}

func TestDecoderBoundsItsTable(t *testing.T) {
	d := NewDecoder(decoders.All)
	base := netip.MustParseAddr("10.0.0.0")
	ip := base
	for i := range maxTracked + 10 {
		ip = ip.Next()
		d.Decode(t0.Add(time.Duration(i)*time.Millisecond), "eth1", frames.ARP(layers.ARPReply, plc, ip.String(), hmi, "10.255.0.1"))
	}
	if len(d.last) >= maxTracked {
		t.Errorf("table has %d entries, want fewer than %d", len(d.last), maxTracked)
	}
	// Entries expire on the next prune.
	d.Decode(t0.Add(time.Hour), "eth1", arpReply())
	if len(d.last) != 1 {
		t.Errorf("after expiry: %d entries", len(d.last))
	}
}

func TestCollector(t *testing.T) {
	sim := clock.NewSim(t0)
	capt := fake.NewCapturer()
	bus := observation.NewBus(64)
	reg := platform.NewRegistry(sim.Now)
	c := New(Options{Capturer: capt, Bus: bus, Clock: sim, Registry: reg, Protocols: decoders.All, RingSize: 1 << 20,
		Interfaces: []Interface{{Name: "eth1", Promiscuous: true}}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()

	src := waitSource(t, capt, "eth1", 1)
	if !src.Options.Promiscuous || src.Options.RingSize != 1<<20 || len(src.Options.Filter) == 0 {
		t.Errorf("open options = %+v", src.Options)
	}
	waitFor(t, func() bool { return state(reg, "eth1") == platform.StateRunning })

	src.Inject(t0, arpReply())
	src.Inject(t0.Add(time.Second), arpReply()) // suppressed repeat
	src.Inject(t0.Add(2*time.Second), frames.ICMPv4Echo(hmi, plc, "192.168.110.20", "192.168.110.50"))
	got := []observation.Observation{next(t, bus), next(t, bus)}
	if got[0].Source != observation.PassiveARP || got[1].Source != observation.PassiveIPv4 || got[1].Interface != "eth1" {
		t.Fatalf("observations = %+v", got)
	}

	// The interface goes away: the source is closed and reopened after the
	// back-off, and the counters survive.
	src.LinkDown()
	waitFor(t, func() bool { return state(reg, "eth1") == platform.StateFailed && src.Closed() })
	waitFor(t, func() bool { return sim.Waiters() > 0 })
	sim.Advance(minRetry)
	src2 := waitSource(t, capt, "eth1", 2)
	waitFor(t, func() bool { return state(reg, "eth1") == platform.StateRunning })
	src2.Inject(t0.Add(time.Hour), arpReply())
	if o := next(t, bus); o.Source != observation.PassiveARP {
		t.Fatalf("after reopen: %+v", o)
	}
	st := c.Stats()
	if len(st) != 1 || st[0].Received != 4 || st[0].Observations != 3 || st[0].BusDropped != 0 {
		t.Errorf("stats = %+v", st)
	}
	cancel()
	<-done
	if !src2.Closed() {
		t.Error("source not closed on shutdown")
	}
}

func TestCollectorRetriesWithBackoff(t *testing.T) {
	sim := clock.NewSim(t0)
	capt := fake.NewCapturer()
	capt.SetOpenErr(errors.New("socket(AF_PACKET): operation not permitted"))
	bus := observation.NewBus(1)
	reg := platform.NewRegistry(sim.Now)
	var log syncBuffer
	c := New(Options{Capturer: capt, Bus: bus, Clock: sim, Registry: reg, Protocols: decoders.All,
		Interfaces: []Interface{{Name: "eth1"}}, Logger: slog.New(slog.NewTextHandler(&log, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()

	waitFor(t, func() bool { return state(reg, "eth1") == platform.StateFailed && sim.Waiters() > 0 })
	if s := reg.List()[0]; s.Error != "socket(AF_PACKET): operation not permitted" || s.Backend != "fake" {
		t.Errorf("status = %+v", s)
	}
	sim.Advance(minRetry) // retry 2 fails, next wait is 2 s
	waitFor(t, func() bool { return capt.Opens("eth1") == 2 && sim.Waiters() > 0 })
	sim.Advance(minRetry)
	time.Sleep(20 * time.Millisecond)
	if n := capt.Opens("eth1"); n != 2 {
		t.Fatalf("retried after 1 s instead of backing off: %d opens", n)
	}
	if n := strings.Count(log.String(), "capture unavailable"); n != 1 {
		t.Errorf("the same failure was logged %d times, want once:\n%s", n, log.String())
	}
	capt.SetOpenErr(nil)
	sim.Advance(minRetry)
	waitFor(t, func() bool { return state(reg, "eth1") == platform.StateRunning })

	// A full bus drops observations and counts them.
	src := capt.Source("eth1")
	src.Inject(t0, arpReply())
	src.Inject(t0, frames.ICMPv4Echo(hmi, plc, "192.168.110.20", "192.168.110.50"))
	waitFor(t, func() bool { st := c.Stats(); return st[0].Observations == 1 && st[0].BusDropped == 1 })
	cancel()
	<-done
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

// An interface that opens but fails at once (administratively down) backs
// off like a failed open instead of cycling every second, and the failure
// is logged once.
func TestCollectorBacksOffWhenSourceFailsAtOnce(t *testing.T) {
	sim := clock.NewSim(t0)
	capt := fake.NewCapturer()
	capt.SetStartDown(true)
	var log syncBuffer
	c := New(Options{Capturer: capt, Bus: observation.NewBus(8), Clock: sim, Protocols: decoders.All,
		Interfaces: []Interface{{Name: "eth1"}}, Logger: slog.New(slog.NewTextHandler(&log, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()
	// Opens at 0 s, 1 s, 3 s, 7 s: the waits double.
	for i, wait := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		waitFor(t, func() bool { return capt.Opens("eth1") == i+1 && sim.Waiters() > 0 })
		sim.Advance(wait - time.Millisecond)
		time.Sleep(10 * time.Millisecond)
		if n := capt.Opens("eth1"); n != i+1 {
			t.Fatalf("reopened after less than %s: %d opens", wait, n)
		}
		sim.Advance(time.Millisecond)
	}
	waitFor(t, func() bool { return capt.Opens("eth1") == 4 })
	if n := strings.Count(log.String(), "capture unavailable"); n != 1 {
		t.Errorf("failure logged %d times, want once:\n%s", n, log.String())
	}
	if n := strings.Count(log.String(), "capture started"); n > 2 {
		t.Errorf("start logged %d times:\n%s", n, log.String())
	}
	cancel()
	<-done
}

// An observation the full bus dropped is not suppressed as a repeat.
func TestDroppedObservationIsNotSuppressed(t *testing.T) {
	sim := clock.NewSim(t0)
	capt := fake.NewCapturer()
	bus := observation.NewBus(1)
	bus.Publish(observation.Observation{Time: t0, Source: observation.PassiveARP, Interface: "eth1",
		IP: netip.MustParseAddr("10.0.0.1")}) // the bus is full
	c := New(Options{Capturer: capt, Bus: bus, Clock: sim, Protocols: decoders.All, Interfaces: []Interface{{Name: "eth1"}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	src := waitSource(t, capt, "eth1", 1)
	src.Inject(t0, arpReply())
	waitFor(t, func() bool { return c.Stats()[0].BusDropped == 1 })
	<-bus.C() // room again
	src.Inject(t0.Add(time.Second), arpReply())
	if o := next(t, bus); o.Source != observation.PassiveARP || !o.Time.Equal(t0.Add(time.Second)) {
		t.Errorf("repeat of the dropped observation = %+v", o)
	}
}

func waitSource(t *testing.T, c *fake.Capturer, iface string, opens int) *fake.FrameSource {
	t.Helper()
	waitFor(t, func() bool { return c.Opens(iface) >= opens && c.Source(iface) != nil })
	return c.Source(iface)
}

func state(reg *platform.Registry, iface string) platform.State {
	for _, s := range reg.List() {
		if s.Interface == iface && s.Collector == platform.CollectorCapture {
			return s.State
		}
	}
	return ""
}

func next(t *testing.T, bus *observation.Bus) observation.Observation {
	t.Helper()
	select {
	case m := <-bus.C():
		return m.Observation
	case <-time.After(5 * time.Second):
		t.Fatal("no observation")
		return observation.Observation{}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(time.Millisecond)
	}
}
