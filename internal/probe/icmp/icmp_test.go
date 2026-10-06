package icmp

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/platform/fake"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/probetest"
)

// echo answers a request as a host would: same identifier and sequence.
func echo(msg []byte, id, seqDelta uint16, typ uint8) []byte {
	var req layers.ICMPv4
	if err := req.DecodeFromBytes(msg, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}
	if id == 0 {
		id = req.Id
	}
	rep := layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(typ, 0), Id: id, Seq: req.Seq + seqDelta}
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true}, &rep, gopacket.Payload(req.Payload))
	return buf.Bytes()
}

func TestRequestAndParse(t *testing.T) {
	msg, err := Request(0x1234, 7)
	if err != nil {
		t.Fatal(err)
	}
	var m layers.ICMPv4
	if err := m.DecodeFromBytes(msg, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if m.TypeCode.Type() != layers.ICMPv4TypeEchoRequest || m.Id != 0x1234 || m.Seq != 7 || string(m.Payload) != "lan-sentinel" {
		t.Errorf("request = %+v", m)
	}
	if id, seq, ok := ParseReply(echo(msg, 0, 0, layers.ICMPv4TypeEchoReply)); !ok || id != 0x1234 || seq != 7 {
		t.Errorf("ParseReply = %d %d %v", id, seq, ok)
	}
	if _, _, ok := ParseReply(msg); ok {
		t.Error("a request parsed as a reply")
	}
	if _, _, ok := ParseReply([]byte{0}); ok {
		t.Error("garbage parsed")
	}
}

func FuzzParseReply(f *testing.F) {
	msg, _ := Request(1, 1)
	f.Add(echo(msg, 0, 0, layers.ICMPv4TypeEchoReply))
	f.Fuzz(func(_ *testing.T, b []byte) { ParseReply(b) })
}

func TestEcho(t *testing.T) {
	tx := &fake.Transmitter{EchoReply: func(dst netip.Addr, msg []byte) []byte {
		switch dst.String() {
		case "192.168.110.20":
			return echo(msg, 0, 0, layers.ICMPv4TypeEchoReply)
		case "192.168.110.21":
			return echo(msg, 0, 1, layers.ICMPv4TypeEchoReply) // another sequence: not ours
		case "192.168.110.22":
			return echo(msg, 0, 0, layers.ICMPv4TypeDestinationUnreachable)
		}
		return nil
	}}
	sink := &probetest.Sink{}
	targets := probetest.Addrs("192.168.110.20", "192.168.110.21", "192.168.110.22", "192.168.110.23", "192.168.110.24")
	results, err := Engine{TX: tx}.Run(context.Background(), probetest.Pass(targets, probetest.Block(nil, targets[4]), sink))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{probe.Reply, probe.NoReply, probe.NoReply, probe.NoReply, probe.Blocked}
	for i, r := range results {
		if r.Target != targets[i] || r.State != want[i] {
			t.Errorf("result %d = %+v, want %s", i, r, want[i])
		}
	}
	if len(tx.Echoes()) != 4 {
		t.Errorf("%d echoes sent, want 4", len(tx.Echoes()))
	}
	obs := sink.All()
	if len(obs) != 1 || obs[0].Source != observation.ICMPScan || obs[0].IP != targets[0] || obs[0].MAC != nil || obs[0].Interface != "eth1" {
		t.Errorf("observations = %+v", obs)
	}
	if (Engine{}).Protocol() != probe.ICMP {
		t.Error("protocol")
	}
}

// rawTX hands out an echo connection that behaves like a raw socket (it
// sees every echo reply, with its identifier) and can fail sends.
type rawTX struct {
	*fake.Transmitter
	failSend bool
}

type rawConn struct {
	platform.EchoConn
	failSend bool
}

func (r rawTX) ICMPConn(ctx context.Context, iface string) (platform.EchoConn, error) {
	c, err := r.Transmitter.ICMPConn(ctx, iface)
	return rawConn{c, r.failSend}, err
}

func (c rawConn) Ping() bool { return false }

func (c rawConn) WriteTo(msg []byte, dst netip.Addr) error {
	if c.failSend {
		return errors.New("no route to host")
	}
	return c.EchoConn.WriteTo(msg, dst)
}

func TestEchoOnRawSocket(t *testing.T) {
	tx := &fake.Transmitter{EchoReply: func(dst netip.Addr, msg []byte) []byte {
		if dst.String() == "192.168.110.21" {
			return echo(msg, 0xbeef, 0, layers.ICMPv4TypeEchoReply) // another process's ping
		}
		return echo(msg, 0, 0, layers.ICMPv4TypeEchoReply)
	}}
	sink := &probetest.Sink{}
	targets := probetest.Addrs("192.168.110.20", "192.168.110.21")
	results, err := Engine{TX: rawTX{Transmitter: tx}}.Run(context.Background(), probetest.Pass(targets, nil, sink))
	if err != nil {
		t.Fatal(err)
	}
	if results[0].State != probe.Reply || results[1].State != probe.NoReply {
		t.Errorf("results = %+v", results)
	}
	if len(sink.All()) != 1 {
		t.Errorf("observations = %+v", sink.All())
	}
}

func TestEchoErrors(t *testing.T) {
	targets := probetest.Addrs("192.168.110.20")
	if _, err := (Engine{TX: &fake.Transmitter{ICMPErr: errors.New("EPERM")}}).Run(context.Background(),
		probetest.Pass(targets, nil, &probetest.Sink{})); err == nil {
		t.Error("open failure not reported")
	}
	// A failed send is that target's no-reply; the pass goes on.
	results, err := Engine{TX: rawTX{Transmitter: &fake.Transmitter{}, failSend: true}}.Run(context.Background(),
		probetest.Pass(probetest.Addrs("192.168.110.20", "192.168.110.21"), nil, &probetest.Sink{}))
	if err != nil || len(results) != 2 || results[1].State != probe.NoReply {
		t.Errorf("send failure: %+v, %v", results, err)
	}
	stop := make(chan struct{})
	close(stop)
	if _, err := (Engine{TX: &fake.Transmitter{}}).Run(context.Background(),
		probetest.Pass(targets, probetest.Block(stop), &probetest.Sink{})); !errors.Is(err, probe.ErrDisabled) {
		t.Errorf("kill switch: %v", err)
	}
}
