package arp

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/platform/fake"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/probetest"
	"lan-sentinel/test/frames"
)

var (
	plcMAC   = frames.MAC("00:1b:1b:aa:bb:01")
	proxyMAC = frames.MAC("00:0c:29:00:00:99")
)

// network answers ARP requests like the hosts on a LAN would.
func network(hosts map[string][]net.HardwareAddr) func(string, []byte) [][]byte {
	return func(_ string, frame []byte) [][]byte {
		p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
		a, _ := p.Layer(layers.LayerTypeARP).(*layers.ARP)
		if a == nil || a.Operation != layers.ARPRequest {
			return nil
		}
		target := netip.AddrFrom4([4]byte(a.DstProtAddress)).String()
		sender := netip.AddrFrom4([4]byte(a.SourceProtAddress)).String()
		var out [][]byte
		for _, mac := range hosts[target] {
			out = append(out, frames.ARP(layers.ARPReply, mac, target, a.SourceHwAddress, sender))
		}
		if target == "192.168.110.30" {
			// Noise: a reply to someone else, a request, a broken frame,
			// a reply from an address that was not asked.
			out = append(out,
				frames.ARP(layers.ARPReply, plcMAC, target, frames.MAC("02:00:00:00:00:77"), sender),
				frames.ARP(layers.ARPRequest, plcMAC, target, make(net.HardwareAddr, 6), sender),
				[]byte{1, 2, 3},
				frames.ARP(layers.ARPReply, plcMAC, "192.168.110.99", a.SourceHwAddress, sender))
		}
		return out
	}
}

func TestRequestFrame(t *testing.T) {
	b, err := Request(probetest.OwnMAC, netip.MustParseAddr("192.168.110.10"), netip.MustParseAddr("192.168.110.20"))
	if err != nil {
		t.Fatal(err)
	}
	p := gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)
	eth := p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	a := p.Layer(layers.LayerTypeARP).(*layers.ARP)
	if eth.DstMAC.String() != "ff:ff:ff:ff:ff:ff" || eth.SrcMAC.String() != probetest.OwnMAC.String() {
		t.Errorf("ethernet %v -> %v", eth.SrcMAC, eth.DstMAC)
	}
	if a.Operation != layers.ARPRequest || net.IP(a.SourceProtAddress).String() != "192.168.110.10" ||
		net.IP(a.DstProtAddress).String() != "192.168.110.20" || net.HardwareAddr(a.DstHwAddress).String() != "00:00:00:00:00:00" {
		t.Errorf("arp = %+v", a)
	}
	if _, err := Request(net.HardwareAddr{1}, netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("10.0.0.1")); err == nil {
		t.Error("a bad MAC built a frame")
	}
}

func TestSweep(t *testing.T) {
	tx := &fake.Transmitter{FrameReply: network(map[string][]net.HardwareAddr{
		"192.168.110.20": {plcMAC},
		"192.168.110.30": {plcMAC, proxyMAC}, // duplicate IP or proxy: both are evidence
	})}
	sink := &probetest.Sink{}
	blocked := netip.MustParseAddr("192.168.110.40")
	targets := probetest.Addrs("192.168.110.20", "192.168.110.30", "192.168.110.40", "192.168.110.50")
	pass := probetest.Pass(targets, probetest.Block(nil, blocked), sink)
	results, err := Engine{TX: tx}.Run(context.Background(), pass)
	if err != nil {
		t.Fatal(err)
	}
	// One result per answer and per blocked address; the unanswered ones
	// are counted in one.
	want := []probe.Result{
		{Target: targets[2], State: probe.Blocked},
		{Target: targets[0], State: probe.Reply},
		{Target: targets[1], State: probe.Reply},
		{Count: 1, State: probe.NoReply},
	}
	if !slices.Equal(results, want) {
		t.Fatalf("results = %+v, want %+v", results, want)
	}
	if n := len(tx.SentFrames()); n != 3 {
		t.Errorf("%d requests sent, want 3 (the blocked target gets none)", n)
	}
	for _, f := range tx.SentFrames() {
		if f.Interface != "eth1" {
			t.Errorf("request sent on %s", f.Interface)
		}
	}
	got := map[string]bool{}
	for _, o := range sink.All() {
		if o.Source != observation.ARPScan || o.Interface != "eth1" || o.Time.IsZero() {
			t.Errorf("observation %+v", o)
		}
		got[o.IP.String()+" "+o.MAC.String()] = true
	}
	for _, k := range []string{"192.168.110.20 " + plcMAC.String(), "192.168.110.30 " + plcMAC.String(), "192.168.110.30 " + proxyMAC.String()} {
		if !got[k] {
			t.Errorf("no observation %s (got %v)", k, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("observations = %v", got)
	}
	if e := (Engine{}); e.Protocol() != probe.ARP {
		t.Error("protocol")
	}
}

func TestStreamedSweep(t *testing.T) {
	tx := &fake.Transmitter{FrameReply: network(map[string][]net.HardwareAddr{"192.168.110.7": {plcMAC}})}
	sink := &probetest.Sink{}
	pass := probetest.Pass(nil, nil, sink)
	sw := probe.NewSweep([]netip.Prefix{netip.MustParsePrefix("192.168.110.0/28")}, nil, pass.Link.Own())
	pass.Sweep, pass.InSweep = sw.Order(rand.New(rand.NewPCG(1, 2))), sw.Contains
	results, err := Engine{TX: tx}.Run(context.Background(), pass)
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.SentFrames()) != 13 { // .1-.14 without the own .10
		t.Errorf("%d requests, want 13", len(tx.SentFrames()))
	}
	want := []probe.Result{{Target: netip.MustParseAddr("192.168.110.7"), State: probe.Reply}, {Count: 12, State: probe.NoReply}}
	if !slices.Equal(results, want) {
		t.Errorf("results = %+v", results)
	}
	if len(sink.All()) != 1 {
		t.Errorf("observations = %+v", sink.All())
	}
}

func TestSweepStopsOnKillSwitch(t *testing.T) {
	stop := make(chan struct{})
	close(stop)
	tx := &fake.Transmitter{}
	results, err := Engine{TX: tx}.Run(context.Background(),
		probetest.Pass(probetest.Addrs("192.168.110.20", "192.168.110.21"), probetest.Block(stop), &probetest.Sink{}))
	if !errors.Is(err, probe.ErrDisabled) || len(results) != 0 || len(tx.SentFrames()) != 0 {
		t.Errorf("Run = %v, %v, %d frames sent", results, err, len(tx.SentFrames()))
	}
}

type failingTX struct {
	*fake.Transmitter
}

func (f failingTX) Frames(ctx context.Context, iface string, et uint16) (platform.FrameConn, error) {
	c, err := f.Transmitter.Frames(ctx, iface, et)
	if err == nil {
		_ = c.Close() // writes now fail
	}
	return c, err
}

func TestSweepErrors(t *testing.T) {
	targets := probetest.Addrs("192.168.110.20")
	if _, err := (Engine{TX: &fake.Transmitter{FramesErr: errors.New("no CAP_NET_RAW")}}).Run(context.Background(),
		probetest.Pass(targets, nil, &probetest.Sink{})); err == nil {
		t.Error("open failure not reported")
	}
	results, err := Engine{TX: failingTX{&fake.Transmitter{}}}.Run(context.Background(), probetest.Pass(targets, nil, &probetest.Sink{}))
	if err == nil || len(results) != 0 {
		t.Errorf("write failure: %v, %v", results, err)
	}
}

func TestParseReply(t *testing.T) {
	own := probetest.OwnMAC
	tests := []struct {
		name  string
		frame []byte
		ok    bool
	}{
		{"reply to us", frames.ARP(layers.ARPReply, plcMAC, "192.168.110.20", own, "192.168.110.10"), true},
		{"reply to another host", frames.ARP(layers.ARPReply, plcMAC, "192.168.110.20", proxyMAC, "192.168.110.10"), false},
		{"request", frames.ARP(layers.ARPRequest, plcMAC, "192.168.110.20", own, "192.168.110.10"), false},
		{"not arp", frames.ICMPv4Echo(plcMAC, own, "192.168.110.20", "192.168.110.10"), false},
		{"truncated", frames.ARP(layers.ARPReply, plcMAC, "192.168.110.20", own, "192.168.110.10")[:20], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, ok := ParseReply(tt.frame, own)
			if ok != tt.ok {
				t.Fatalf("ok = %v", ok)
			}
			if ok && (r.IP.String() != "192.168.110.20" || r.MAC.String() != plcMAC.String()) {
				t.Errorf("reply = %+v", r)
			}
		})
	}
}

func FuzzParseReply(f *testing.F) {
	f.Add(frames.ARP(layers.ARPReply, plcMAC, "192.168.110.20", probetest.OwnMAC, "192.168.110.10"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) {
		ParseReply(b, probetest.OwnMAC)
	})
}
