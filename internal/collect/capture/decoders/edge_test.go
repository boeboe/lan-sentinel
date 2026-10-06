package decoders

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"lan-sentinel/test/frames"
)

// tlv encodes one LLDP TLV.
func tlv(typ byte, v ...byte) []byte {
	return append([]byte{typ<<1 | byte(len(v)>>8), byte(len(v))}, v...)
}

func TestLLDPIdentifiers(t *testing.T) {
	ttl := tlv(lldpTTL, 0, 120)
	tests := []struct {
		name string
		pdu  [][]byte
		want string
	}{
		{"network-address chassis, MAC port, IPv6 management address",
			[][]byte{
				tlv(lldpChassisID, lldpChassisNetwork, 1, 192, 168, 110, 2),
				tlv(lldpPortID, lldpPortMAC, 0x00, 0x1e, 0xc9, 0, 0, 0x17),
				ttl,
				tlv(lldpMgmtAddress, append([]byte{17, 2}, frames.IP("fd00::2")...)...),
				tlv(lldpMgmtAddress, 5, 1, 10, 0, 0, 2), // a second address is ignored
				tlv(lldpEnd),
				tlv(lldpSystemName, 'x'), // after the end TLV
			},
			"passive_lldp mac=00:00:00:00:00:01 chassis_id=192.168.110.2 management_ip=fd00::2 port_id=00:1e:c9:00:00:17"},
		{"network-address port id, bad management address",
			[][]byte{
				tlv(lldpChassisID, 7, 'S', 'N', '1'),
				tlv(lldpPortID, lldpPortNetwork, 1, 10, 0, 0, 9),
				ttl,
				tlv(lldpMgmtAddress, 9, 1, 10, 0),
				tlv(lldpSysCaps, 0, 0xff),
			},
			"passive_lldp mac=00:00:00:00:00:01 chassis_id=SN1 port_id=10.0.0.9"},
		{"multicast chassis MAC falls back to the frame source",
			[][]byte{tlv(lldpChassisID, lldpChassisMAC, 0x01, 0, 0x5e, 0, 0, 1), tlv(lldpPortID, 5, 'p'), ttl},
			"passive_lldp mac=00:00:00:00:00:01 chassis_id=01:00:5e:00:00:01 port_id=p"},
		{"short chassis id", [][]byte{tlv(lldpChassisID, 4), ttl}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &frame{p: All, time: t0, iface: "eth1", src: frames.MAC("00:00:00:00:00:01")}
			f.lldp(slices.Concat(tt.pdu...))
			got := strings.Join(summaries(f.out), "|")
			if got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestDHCPOptions(t *testing.T) {
	opts := dhcpOptions([]byte{
		dhcpOptPad, dhcpOptPad,
		dhcpOptHostname, 3, 'p', 'l', 'c',
		dhcpOptHostname, 2, '-', '1', // concatenated (RFC 3396)
		dhcpOptMessageType, 1, dhcpRequest,
		dhcpOptClientID, 9, 1, 2, // truncated: parsing stops
		dhcpOptVendorClass, 1, 'x',
	})
	if string(opts[dhcpOptHostname]) != "plc-1" || len(opts[dhcpOptMessageType]) != 1 || opts[dhcpOptClientID] != nil ||
		opts[dhcpOptVendorClass] != nil {
		t.Errorf("options = %q", opts)
	}
	if got := dhcpOptions([]byte{dhcpOptHostname, 1, 'a', dhcpOptEnd, dhcpOptVendorClass, 1, 'b'}); got[dhcpOptVendorClass] != nil {
		t.Error("options after the end option were read")
	}
	// The op code must agree with the message type.
	b := frames.DHCP{Type: layers.DHCPMsgTypeAck, Client: hmi, YourIP: "10.0.0.5", Server: server, ServerIP: "10.0.0.2"}.Frame()[14+20+8:]
	b = slices.Clone(b)
	b[0] = 1 // BOOTREQUEST carrying an ACK
	f := &frame{p: All, time: t0, iface: "eth1"}
	f.dhcp(b)
	if len(f.out) != 0 {
		t.Errorf("mismatched op accepted: %v", summaries(f.out))
	}
}

func TestNDPOptions(t *testing.T) {
	mac := frames.MAC("00:1b:1b:aa:bb:01")
	nonce := []byte{14, 1, 1, 2, 3, 4, 5, 6} // RFC 3971 nonce option, skipped
	slla := append([]byte{ndpOptSourceLL, 1}, mac...)
	if got := linkLayerOption(slices.Concat(nonce, slla), ndpOptSourceLL); got.String() != mac.String() {
		t.Errorf("option after a nonce = %v", got)
	}
	if got := linkLayerOption(slices.Concat([]byte{14, 0, 0, 0, 0, 0, 0, 0}, slla), ndpOptSourceLL); got != nil {
		t.Errorf("zero-length option not rejected: %v", got)
	}
	if got := linkLayerOption([]byte{ndpOptSourceLL, 2, 1, 2, 3}, ndpOptSourceLL); got != nil {
		t.Errorf("option longer than the message accepted: %v", got)
	}
	if got := linkLayerOption(slla, ndpOptTargetLL); got != nil {
		t.Errorf("wrong option type matched: %v", got)
	}
	// Router advertisements and solicitations shorter than their fixed part
	// are ignored, and so are unknown NDP types (redirect).
	for _, b := range [][]byte{{134, 0, 0, 0, 0, 0, 0, 0}, {135, 0, 0, 0, 0, 0, 0, 0}, {136, 0, 0, 0, 0, 0, 0, 0}, {137, 0, 0, 0, 0, 0, 0, 0}} {
		f := newFrame()
		f.ndp(addr16(frames.IP("fe80::1")), 255, b)
		if len(f.out) != 0 {
			t.Errorf("type %d: %v", b[0], summaries(f.out))
		}
	}
}

func TestMDNSServiceLimit(t *testing.T) {
	var records []layers.DNSResourceRecord
	for i := range maxServices + 4 {
		records = append(records, frames.PTR(fmt.Sprintf("_s%d._tcp.local", i), fmt.Sprintf("x._s%d._tcp.local", i)))
	}
	records = append(records, frames.SRV("x._s0._tcp.local", "plc.local", 80), frames.PTR("_s0._tcp.local", "x._s0._tcp.local"))
	f := newFrame()
	f.mdns(addr4(frames.IP("10.0.0.5").To4()), frames.MDNS4(plc, "10.0.0.5", records, nil)[14+20+8:])
	if len(f.out) != 1 {
		t.Fatalf("observations = %v", summaries(f.out))
	}
	m := f.out[0].Meta
	if n := len(strings.Split(m["services"], ",")); n != maxServices {
		t.Errorf("%d services kept, want %d", n, maxServices)
	}
	// A PTR after the SRV does not erase the port.
	if m["service_ports"] != "_s0._tcp=80" || f.out[0].Hostname != "plc.local" {
		t.Errorf("meta = %v, name %q", m, f.out[0].Hostname)
	}
}

// IPv6 packets with extension headers (MLD hop-by-hop) only teach the
// source address; truncated UDP headers teach nothing more.
func TestIPv6ExtensionHeadersAndShortUDP(t *testing.T) {
	ip6 := frames.Build(frames.Ethernet(plc, frames.MAC("33:33:00:00:00:16"), layers.EthernetTypeIPv6),
		frames.IPv6("fe80::21b:1bff:feaa:bb01", "ff02::16", layers.IPProtocolIPv6HopByHop, 1))
	if got := summaries(Decode(All, t0, "eth1", ip6)); len(got) != 1 || !strings.HasPrefix(got[0], "passive_ipv6") {
		t.Errorf("hop-by-hop: %v", got)
	}
	f := newFrame()
	f.udp(addr4(frames.IP("10.0.0.5").To4()), []byte{0, 53, 0, 1})
	if len(f.out) != 0 {
		t.Errorf("short UDP: %v", summaries(f.out))
	}
}

// Records of types the decoder does not read (here URI; in the field NSEC,
// HINFO or OPT) are skipped in every section, so addresses after them are
// still read.
func TestMDNSSkipsUnknownRecords(t *testing.T) {
	other := layers.DNSResourceRecord{Name: []byte("plc-a.local"), Type: layers.DNSTypeURI, Class: layers.DNSClassIN, TTL: 120,
		URI: layers.DNSURI{Priority: 1, Weight: 1, Target: []byte("http://plc-a.local/")}}
	b := frames.MDNS4(plc, "10.0.0.5",
		[]layers.DNSResourceRecord{other, frames.PTR("_http._tcp.local", "x._http._tcp.local")},
		[]layers.DNSResourceRecord{other, frames.A("plc-a.local", "10.0.0.5")})
	f := newFrame()
	f.mdns(addr4(frames.IP("10.0.0.5").To4()), b[14+20+8:])
	if got := strings.Join(summaries(f.out), "|"); got != "passive_mdns mac=00:1b:1b:aa:bb:01 ip=10.0.0.5 name=mdns:plc-a.local services=_http._tcp" {
		t.Errorf("got %s", got)
	}
}
