package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"testing"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform/fake"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/probetest"
)

// ntpReply answers req like an NTP server at stratum with refID.
func ntpReply(req []byte, stratum byte, refID [4]byte) []byte {
	r := make([]byte, 48)
	r[0] = 0<<6 | 4<<3 | 4 // LI 0, version 4, mode 4 (server)
	r[1] = stratum
	binary.BigEndian.PutUint32(r[4:], 0x00000a3d) // root delay 2621/65536 s
	binary.BigEndian.PutUint32(r[8:], 0x00018000) // root dispersion 1.5 s
	copy(r[12:16], refID[:])
	copy(r[24:32], req[40:48]) // originate = the client's transmit
	return r
}

// enipReply answers req with a ListIdentity reply for a PLC.
func enipReply(req []byte, name string, withState bool) []byte {
	item := make([]byte, 0, 64)
	le := binary.LittleEndian
	item = le.AppendUint16(item, 1)                                                  // protocol version
	item = append(item, 0, 2, 0xaf, 0x12, 192, 168, 110, 20, 0, 0, 0, 0, 0, 0, 0, 0) // socket address
	item = le.AppendUint16(item, 1)                                                  // vendor: Rockwell
	item = le.AppendUint16(item, 0x0e)                                               // PLC
	item = le.AppendUint16(item, 166)                                                // product code
	item = append(item, 20, 11)                                                      // revision 20.11
	item = le.AppendUint16(item, 0x0030)                                             // status
	item = le.AppendUint32(item, 0x00c0ffee)                                         // serial
	item = append(item, byte(len(name)))
	item = append(item, name...)
	if withState {
		item = append(item, 3)
	}
	data := le.AppendUint16(nil, 2)                         // two items
	data = append(data, 0x86, 0x00, 0x02, 0x00, 0xaa, 0xbb) // an unknown item first
	data = le.AppendUint16(data, cipIdentityItem)
	data = le.AppendUint16(data, uint16(len(item)))
	data = append(data, item...)
	h := make([]byte, enipHeaderLen)
	le.PutUint16(h[0:], enipListIdentity)
	le.PutUint16(h[2:], uint16(len(data)))
	copy(h[12:20], req[12:20])
	return append(h, data...)
}

func TestProbersMatchConfig(t *testing.T) {
	names := slices.Sorted(maps.Keys(Probers))
	want := slices.Sorted(slices.Values(config.UDPProbeNames))
	if !slices.Equal(names, want) {
		t.Errorf("probers %v, config.UDPProbeNames %v", names, want)
	}
	for name, p := range Probers {
		if p.Name() != name || p.Port() == 0 {
			t.Errorf("prober %s: name %s port %d", name, p.Name(), p.Port())
		}
	}
}

func TestNTP(t *testing.T) {
	req, err := NTP{}.Request()
	if err != nil {
		t.Fatal(err)
	}
	if len(req) != 48 || req[0] != 0x23 {
		t.Fatalf("request = % x", req[:4])
	}
	req2, _ := NTP{}.Request()
	if string(req[40:48]) == string(req2[40:48]) {
		t.Error("transmit timestamps repeat")
	}
	tests := []struct {
		name  string
		reply []byte
		ok    bool
		want  map[string]string
	}{
		{"stratum 2", ntpReply(req, 2, [4]byte{192, 168, 1, 1}), true, map[string]string{
			"version": "4", "stratum": "2", "leap": "0", "reference_id": "192.168.1.1",
			"root_delay_ms": "39.993", "root_dispersion_ms": "1500.000",
		}},
		{"stratum 1 GPS", ntpReply(req, 1, [4]byte{'G', 'P', 'S', 0}), true, map[string]string{"reference_id": "GPS", "stratum": "1"}},
		{"kiss of death", ntpReply(req, 0, [4]byte{'R', 'A', 'T', 'E'}), true, map[string]string{"kiss_code": "RATE"}},
		{"binary reference", ntpReply(req, 1, [4]byte{1, 2, 3, 4}), true, map[string]string{"reference_id": "0x01020304"}},
		{"answer to another request", ntpReply(req2, 2, [4]byte{}), false, nil},
		{"client mode", func() []byte { r := ntpReply(req, 2, [4]byte{}); r[0] = 4<<3 | 3; return r }(), false, nil},
		{"version 0", func() []byte { r := ntpReply(req, 2, [4]byte{}); r[0] = 4; return r }(), false, nil},
		{"short", ntpReply(req, 2, [4]byte{})[:40], false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, ok := NTP{}.Parse(req, tt.reply)
			if ok != tt.ok {
				t.Fatalf("ok = %v", ok)
			}
			for k, v := range tt.want {
				if r.Details[k] != v {
					t.Errorf("%s = %q, want %q", k, r.Details[k], v)
				}
			}
			if len(r.Identity) != 0 {
				t.Errorf("NTP claims an identity: %v", r.Identity)
			}
		})
	}
}

func TestENIP(t *testing.T) {
	req, err := ENIP{}.Request()
	if err != nil {
		t.Fatal(err)
	}
	if len(req) != 24 || binary.LittleEndian.Uint16(req) != 0x63 || binary.LittleEndian.Uint16(req[2:]) != 0 {
		t.Fatalf("request = % x", req)
	}
	other, _ := ENIP{}.Request()
	good := enipReply(req, "1756-L71/B LOGIX5571\x00", true)
	tests := []struct {
		name  string
		reply []byte
		ok    bool
	}{
		{"identity", good, true},
		{"no state byte", enipReply(req, "1756-L71/B LOGIX5571", false), true},
		{"another sender context", enipReply(other, "x", true), false},
		{"error status", func() []byte { r := slices.Clone(good); r[8] = 1; return r }(), false},
		{"wrong command", func() []byte { r := slices.Clone(good); r[0] = 0x65; return r }(), false},
		{"length beyond the data", func() []byte { r := slices.Clone(good); r[2] = 0xff; return r }(), false},
		{"truncated item", good[:len(good)-10], false},
		{"no identity item", func() []byte {
			r := slices.Clone(good[:enipHeaderLen+2+6])
			binary.LittleEndian.PutUint16(r[2:], 2+6)
			binary.LittleEndian.PutUint16(r[enipHeaderLen:], 1)
			return r
		}(), false},
		{"empty data", func() []byte {
			r := slices.Clone(good[:enipHeaderLen+2])
			binary.LittleEndian.PutUint16(r[2:], 0)
			return r
		}(), false},
		{"header only", good[:enipHeaderLen], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, ok := ENIP{}.Parse(req, tt.reply)
			if ok != tt.ok {
				t.Fatalf("ok = %v (%+v)", ok, r)
			}
			if !ok {
				return
			}
			want := map[string]string{
				"vendor_id": "1", "device_type": "14", "product_code": "166", "revision": "20.11",
				"status": "0x0030", "serial_number": "0x00c0ffee", "product_name": "1756-L71/B LOGIX5571",
			}
			for k, v := range want {
				if r.Details[k] != v {
					t.Errorf("%s = %q, want %q", k, r.Details[k], v)
				}
			}
			if r.Identity["product"] != "1756-L71/B LOGIX5571" || r.Identity["device_type"] != "Programmable Logic Controller" {
				t.Errorf("identity = %v", r.Identity)
			}
		})
	}
	if DeviceType(0x99) != "CIP device type 0x99" {
		t.Errorf("DeviceType(0x99) = %q", DeviceType(0x99))
	}
	// A nameless device claims a device type only.
	r, ok := ENIP{}.Parse(req, enipReply(req, "", true))
	if !ok || r.Identity["product"] != "" || r.Identity["device_type"] == "" {
		t.Errorf("nameless identity = %v, %v", r.Identity, ok)
	}
}

func FuzzNTPParse(f *testing.F) {
	req, _ := NTP{}.Request()
	f.Add(ntpReply(req, 2, [4]byte{10, 0, 0, 1}))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) {
		NTP{}.Parse(req, b)
		if len(b) >= 48 {
			r := slices.Clone(b)
			copy(r[24:32], req[40:48])
			NTP{}.Parse(req, r)
		}
	})
}

func FuzzENIPParse(f *testing.F) {
	req, _ := ENIP{}.Request()
	f.Add(enipReply(req, "PLC", true))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) {
		ENIP{}.Parse(req, b)
		if len(b) >= enipHeaderLen {
			r := slices.Clone(b)
			copy(r[12:20], req[12:20])
			binary.LittleEndian.PutUint16(r[0:], enipListIdentity)
			binary.LittleEndian.PutUint32(r[8:], 0)
			ENIP{}.Parse(req, r)
		}
	})
}

func TestMeta(t *testing.T) {
	m := Meta("enip", Response{Details: map[string]string{"vendor_id": "1"}, Identity: map[string]string{"product": "X"}})
	want := map[string]string{"vendor_id": "1", observation.MetaIdentityPrefix + "product": "X", observation.MetaProbe: "enip"}
	if !maps.Equal(m, want) {
		t.Errorf("Meta = %v", m)
	}
}

func TestProbeEngine(t *testing.T) {
	tx := &fake.Transmitter{UDPReply: func(addr netip.AddrPort, payload []byte) []byte {
		switch addr.String() {
		case "192.168.110.20:123":
			return ntpReply(payload, 2, [4]byte{10, 0, 0, 1})
		case "192.168.110.21:123":
			return []byte("not ntp") // ignored; then the timeout
		case "192.168.110.20:44818":
			return enipReply(payload, "PLC-5", true)
		}
		return nil
	}}
	sink := &probetest.Sink{}
	targets := probetest.Addrs("192.168.110.20", "192.168.110.21", "192.168.110.22")
	pass := probetest.Pass(targets, probetest.Block(nil, targets[2]), sink)
	pass.UDP = []string{"enip", "ntp"}
	results, err := Engine{TX: tx}.Run(context.Background(), pass)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range results {
		got[r.Probe+" "+r.Target.String()] = r.State
	}
	want := map[string]string{
		"ntp 192.168.110.20": probe.Reply, "ntp 192.168.110.21": probe.NoReply, "ntp 192.168.110.22": probe.Blocked,
		"enip 192.168.110.20": probe.Reply, "enip 192.168.110.21": probe.NoReply, "enip 192.168.110.22": probe.Blocked,
	}
	if !maps.Equal(got, want) {
		t.Errorf("results = %v", got)
	}
	if len(tx.Datagrams()) != 4 {
		t.Errorf("%d datagrams, want 4", len(tx.Datagrams()))
	}
	obs := sink.All()
	if len(obs) != 2 {
		t.Fatalf("observations = %+v (no reply must emit nothing)", obs)
	}
	for _, o := range obs {
		if o.Source != observation.UDPProbe || o.IP != targets[0] || o.Service == nil || o.Service.State != observation.ServiceOpen ||
			o.Service.Proto != "udp" || o.Meta[observation.MetaProbe] == "" {
			t.Errorf("observation %+v", o)
		}
		if o.Meta[observation.MetaProbe] == "enip" && (o.Service.Port != 44818 || o.Meta["id.product"] != "PLC-5") {
			t.Errorf("enip observation %+v", o)
		}
		if o.Meta[observation.MetaProbe] == "ntp" && (o.Service.Port != 123 || o.Meta["stratum"] != "2") {
			t.Errorf("ntp observation %+v", o)
		}
	}
	if (Engine{}).Protocol() != probe.UDP {
		t.Error("protocol")
	}
}

type badProber struct{ NTP }

func (badProber) Name() string             { return "bad" }
func (badProber) Request() ([]byte, error) { return nil, errors.New("no randomness") }

type dialFailTX struct{ *fake.Transmitter }

func (dialFailTX) DialUDP(context.Context, string, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("no route")
}

func TestProbeEngineErrors(t *testing.T) {
	targets := probetest.Addrs("192.168.110.20")
	pass := probetest.Pass(targets, nil, &probetest.Sink{})
	pass.UDP = []string{"snmp"}
	if _, err := (Engine{TX: &fake.Transmitter{}}).Run(context.Background(), pass); err == nil {
		t.Error("unknown probe accepted")
	}
	Probers["bad"] = badProber{}
	defer delete(Probers, "bad")
	for _, tt := range []struct {
		name string
		tx   Engine
		pr   string
	}{
		{"request fails", Engine{TX: &fake.Transmitter{}}, "bad"},
		{"dial fails", Engine{TX: dialFailTX{&fake.Transmitter{}}}, "ntp"},
	} {
		pass.UDP = []string{tt.pr}
		results, err := tt.tx.Run(context.Background(), pass)
		if err != nil || len(results) != 1 || results[0].State != probe.NoReply {
			t.Errorf("%s: %+v, %v", tt.name, results, err)
		}
	}
	stop := make(chan struct{})
	close(stop)
	pass = probetest.Pass(targets, probetest.Block(stop), &probetest.Sink{})
	pass.UDP = []string{"ntp"}
	if _, err := (Engine{TX: &fake.Transmitter{}}).Run(context.Background(), pass); !errors.Is(err, probe.ErrDisabled) {
		t.Errorf("kill switch: %v", err)
	}
}
