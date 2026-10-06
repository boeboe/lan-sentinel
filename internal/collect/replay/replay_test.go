package replay

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/collect/capture/decoders"
	"lan-sentinel/internal/observation"
	"lan-sentinel/test/frames"
)

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func line(ts, ip string) string {
	return `{"time":"` + ts + `","source":"passive_arp","mac":"00:1b:1b:00:00:01","ip":"` + ip + `"}` + "\n"
}

// consume plays p and returns what the correlator side would receive.
func consume(t *testing.T, p *Player, speed float64) ([]observation.Message, error) {
	t.Helper()
	bus := observation.NewBus(4)
	ctx, cancel := context.WithCancel(context.Background())
	var got []observation.Message
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-bus.C():
				if m.Barrier != nil {
					close(m.Barrier)
					return
				}
				got = append(got, m)
			}
		}
	}()
	p.speed = speed
	err := p.Run(ctx, bus)
	if err != nil {
		cancel()
	}
	<-done
	cancel()
	return got, err
}

func TestMergeInTimeOrder(t *testing.T) {
	a := write(t, "eth1.jsonl", line("2026-10-01T10:00:00Z", "10.0.0.1")+line("2026-10-01T10:00:02Z", "10.0.0.3"))
	b := write(t, "eth2.jsonl", line("2026-10-01T10:00:01Z", "10.1.0.2")+"\n"+line("2026-10-01T10:00:03Z", "10.1.0.4"))
	p, err := Open(Options{Sources: []Source{
		{Interface: "eth1", File: a, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
		{Interface: "eth2", File: b},
	}})
	if err != nil {
		t.Fatal(err)
	}
	first := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	if !p.First().Equal(first) {
		t.Fatalf("First = %v", p.First())
	}
	sim := clock.NewSim(first)
	p.SetClock(sim)
	got, err := consume(t, p, 0)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, m := range got {
		if m.Link != nil {
			order = append(order, "link "+m.Link.Interface)
			continue
		}
		order = append(order, m.Observation.Interface+" "+m.Observation.IP.String())
	}
	want := "link eth1|link eth2|eth1 10.0.0.1|eth2 10.1.0.2|eth1 10.0.0.3|eth2 10.1.0.4"
	if strings.Join(order, "|") != want {
		t.Errorf("order = %s\nwant    %s", strings.Join(order, "|"), want)
	}
	if !sim.Now().Equal(first.Add(3 * time.Second)) {
		t.Errorf("clock = %v, want the last observation's time", sim.Now())
	}
}

func TestRealTimeSpeed(t *testing.T) {
	// One simulated minute at speed 1200 takes 50 ms of wall time.
	f := write(t, "eth1.jsonl", line("2026-10-01T10:00:00Z", "10.0.0.1")+line("2026-10-01T10:01:00Z", "10.0.0.2"))
	p, err := Open(Options{Sources: []Source{{Interface: "eth1", File: f}}})
	if err != nil {
		t.Fatal(err)
	}
	p.SetClock(clock.NewSim(p.First()))
	start := time.Now()
	if _, err := consume(t, p, 1200); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 40*time.Millisecond || d > 5*time.Second {
		t.Errorf("real-time replay took %v, want about 50ms", d)
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name, file, content, wantErr string
		atRun                        bool
	}{
		{"unsupported type", "x.csv", "a,b", "unsupported file type", false},
		{"compressed jsonl", "x.jsonl.gz", "x", "compressed JSONL", false},
		{"not a capture", "x.pcap", "hello, world, this is not a capture file", "not a pcap or pcapng file", false},
		{"missing file", "", "", "no such file", false},
		{"bad first line", "x.jsonl", "{", "line 1", false},
		{"interface mismatch", "x.jsonl", line("2026-10-01T10:00:00Z", "10.0.0.1") +
			`{"time":"2026-10-01T10:00:01Z","source":"passive_arp","interface":"eth9","ip":"10.0.0.2"}` + "\n",
			"observation for eth9 in the replay file of eth1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "missing.jsonl")
			if tt.file != "" {
				path = write(t, tt.file, tt.content)
			}
			p, err := Open(Options{Sources: []Source{{Interface: "eth1", File: path}}})
			if tt.atRun {
				if err != nil {
					t.Fatal(err)
				}
				p.SetClock(clock.NewSim(p.First()))
				_, err = consume(t, p, 0)
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

type packet struct {
	at    time.Duration
	frame []byte
}

// writeCapture writes packets as a pcap or pcapng file.
func writeCapture(t *testing.T, name string, link layers.LinkType, pkts []packet) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	t0 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	write := func(w interface {
		WritePacket(gopacket.CaptureInfo, []byte) error
	}) {
		for _, p := range pkts {
			ci := gopacket.CaptureInfo{Timestamp: t0.Add(p.at), CaptureLength: len(p.frame), Length: len(p.frame)}
			if err := w.WritePacket(ci, p.frame); err != nil {
				t.Fatal(err)
			}
		}
	}
	if strings.HasSuffix(name, ".pcapng") {
		w, err := pcapgo.NewNgWriter(f, link)
		if err != nil {
			t.Fatal(err)
		}
		write(w)
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		return path
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, link); err != nil {
		t.Fatal(err)
	}
	write(w)
	return path
}

func TestPcapReplay(t *testing.T) {
	plc, hmi := frames.MAC("00:1b:1b:aa:bb:01"), frames.MAC("00:0e:8c:11:22:33")
	arp := frames.ARP(layers.ARPReply, plc, "192.168.110.50", hmi, "192.168.110.20")
	pkts := []packet{
		{0, arp},
		{time.Second, arp}, // repeat: suppressed like live capture
		{2 * time.Second, []byte{0xde, 0xad}},
		{3 * time.Second, frames.DHCP{Type: layers.DHCPMsgTypeDiscover, Client: hmi, Hostname: "HMI-3"}.Frame()},
		{4 * time.Second, frames.ICMPv4Echo(hmi, plc, "192.168.110.20", "192.168.110.50")},
	}
	for _, name := range []string{"site.pcap", "site.pcapng"} {
		t.Run(name, func(t *testing.T) {
			path := writeCapture(t, name, layers.LinkTypeEthernet, pkts)
			p, err := Open(Options{Sources: []Source{{Interface: "eth1", File: path}}, Protocols: decoders.All})
			if err != nil {
				t.Fatal(err)
			}
			first := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
			if !p.First().Equal(first) {
				t.Errorf("First = %v", p.First())
			}
			p.SetClock(clock.NewSim(p.First()))
			got, err := consume(t, p, 0)
			if err != nil {
				t.Fatal(err)
			}
			var seen []string
			for _, m := range got {
				if o := m.Observation; m.Link == nil {
					seen = append(seen, string(o.Source)+" "+o.Time.Format("15:04:05")+" "+o.Interface+" "+o.Hostname)
				}
			}
			want := "passive_arp 10:00:00 eth1 |passive_dhcp 10:00:03 eth1 HMI-3|passive_ipv4 10:00:04 eth1 "
			if strings.Join(seen, "|") != want {
				t.Errorf("observations:\n  %s\nwant\n  %s", strings.Join(seen, "|"), want)
			}
		})
	}
	// Protocols disabled in the configuration are not decoded.
	path := writeCapture(t, "site.pcap", layers.LinkTypeEthernet, pkts)
	p, err := Open(Options{Sources: []Source{{Interface: "eth1", File: path}}, Protocols: decoders.Protocols{DHCP: true}})
	if err != nil {
		t.Fatal(err)
	}
	p.SetClock(clock.NewSim(p.First()))
	got, _ := consume(t, p, 0)
	if len(got) != 2 || got[1].Observation.Source != observation.PassiveDHCP {
		t.Errorf("DHCP only: %+v", got)
	}
}

func TestPcapErrors(t *testing.T) {
	for _, name := range []string{"cooked.pcap", "cooked.pcapng"} {
		path := writeCapture(t, name, layers.LinkTypeLinuxSLL, nil)
		if _, err := Open(Options{Sources: []Source{{Interface: "eth1", File: path}}}); err == nil ||
			!strings.Contains(err.Error(), "only Ethernet captures") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A truncated record fails the replay at that packet.
	path := writeCapture(t, "cut.pcap", layers.LinkTypeEthernet, []packet{
		{0, frames.ARP(layers.ARPReply, frames.MAC("00:1b:1b:aa:bb:01"), "10.0.0.1", frames.MAC("00:1b:1b:aa:bb:02"), "10.0.0.2")},
		{time.Second, frames.ARP(layers.ARPReply, frames.MAC("00:1b:1b:aa:bb:03"), "10.0.0.3", frames.MAC("00:1b:1b:aa:bb:02"), "10.0.0.2")},
	})
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b[:len(b)-10], 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Open(Options{Sources: []Source{{Interface: "eth1", File: path}}, Protocols: decoders.All})
	if err != nil {
		t.Fatal(err)
	}
	p.SetClock(clock.NewSim(p.First()))
	if _, err := consume(t, p, 0); err == nil || !strings.Contains(err.Error(), "packet 2") {
		t.Errorf("truncated capture: err = %v", err)
	}
}

// A gzipped capture named .pcap.gz replays, and pcapng packets recorded as
// outbound (sent by the capturing host) are skipped like live capture's
// own frames.
func TestPcapGzipAndDirection(t *testing.T) {
	plc, hmi := frames.MAC("00:1b:1b:aa:bb:01"), frames.MAC("00:0e:8c:11:22:33")
	in := frames.ARP(layers.ARPReply, plc, "192.168.110.50", hmi, "192.168.110.20")
	out := frames.ARP(layers.ARPRequest, hmi, "192.168.110.20", frames.Broadcast, "192.168.110.50")
	t0 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	w, err := pcapgo.NewNgWriter(gz, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range []struct {
		frame []byte
		dir   pcapgo.NgEpbFlag
	}{{out, pcapgo.NgEpbFlagDirectionOutbound}, {in, pcapgo.NgEpbFlagDirectionInbound}} {
		ci := gopacket.CaptureInfo{Timestamp: t0.Add(time.Duration(i) * time.Second), CaptureLength: len(p.frame), Length: len(p.frame)}
		if err := w.WritePacketWithOptions(ci, p.frame, pcapgo.NgPacketOptions{Flags: &pcapgo.NgEpbFlags{Direction: p.dir}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	path := write(t, "site.pcapng.gz", buf.String())
	p, err := Open(Options{Sources: []Source{{Interface: "eth1", File: path}}, Protocols: decoders.All})
	if err != nil {
		t.Fatal(err)
	}
	p.SetClock(clock.NewSim(p.First()))
	got, err := consume(t, p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].Observation.MAC.String() != plc.String() {
		t.Errorf("messages = %+v, want the link state and the inbound reply only", got)
	}
}
