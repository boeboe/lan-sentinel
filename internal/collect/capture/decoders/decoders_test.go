package decoders

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"lan-sentinel/internal/observation"
	"lan-sentinel/test/frames"
)

var (
	t0     = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	plc    = frames.MAC("00:1b:1b:aa:bb:01")
	hmi    = frames.MAC("00:0e:8c:11:22:33")
	router = frames.MAC("00:00:5e:00:01:01")
	server = frames.MAC("02:00:00:00:00:53")
	sw     = frames.MAC("00:1e:c9:00:00:01")
	swPort = frames.MAC("00:1e:c9:00:00:17")
	nobody = frames.MAC("00:00:00:00:00:00")
	bcast  = frames.Broadcast
)

// summary renders an observation compactly and deterministically.
func summary(o observation.Observation) string {
	parts := []string{string(o.Source)}
	if o.MAC != nil {
		parts = append(parts, "mac="+o.MAC.String())
	}
	if o.IP.IsValid() {
		parts = append(parts, "ip="+o.IP.String())
	}
	if o.Hostname != "" {
		parts = append(parts, fmt.Sprintf("name=%s:%s", o.NameType, o.Hostname))
	}
	keys := make([]string, 0, len(o.Meta))
	for k := range o.Meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+"="+o.Meta[k])
	}
	return strings.Join(parts, " ")
}

func summaries(obs []observation.Observation) []string {
	out := make([]string, len(obs))
	for i, o := range obs {
		out[i] = summary(o)
		if !o.Time.Equal(t0) || o.Interface != "eth1" {
			out[i] += " (bad time or interface)"
		}
	}
	return out
}

func TestDecode(t *testing.T) {
	pcPRL := []byte{1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252}
	tests := []struct {
		name  string
		frame []byte
		p     Protocols
		want  []string
	}{
		{"arp request", frames.ARP(layers.ARPRequest, plc, "192.168.110.50", nobody, "192.168.110.1"), All,
			[]string{"passive_arp mac=00:1b:1b:aa:bb:01 ip=192.168.110.50 arp=request"}},
		{"arp reply", frames.ARP(layers.ARPReply, plc, "192.168.110.50", hmi, "192.168.110.20"), All,
			[]string{"passive_arp mac=00:1b:1b:aa:bb:01 ip=192.168.110.50 arp=reply"}},
		{"gratuitous arp", frames.ARP(layers.ARPRequest, plc, "192.168.110.51", bcast, "192.168.110.51"), All,
			[]string{"passive_arp mac=00:1b:1b:aa:bb:01 ip=192.168.110.51 arp=gratuitous"}},
		{"gratuitous arp reply form", frames.ARP(layers.ARPReply, plc, "192.168.110.51", bcast, "192.168.110.51"), All,
			[]string{"passive_arp mac=00:1b:1b:aa:bb:01 ip=192.168.110.51 arp=gratuitous"}},
		{"arp probe", frames.ARP(layers.ARPRequest, plc, "0.0.0.0", nobody, "192.168.110.52"), All,
			[]string{"passive_arp mac=00:1b:1b:aa:bb:01 arp=probe target=192.168.110.52"}},
		{"arp disabled", frames.ARP(layers.ARPRequest, plc, "192.168.110.50", nobody, "192.168.110.1"), Protocols{IPv4: true}, nil},
		{"arp from multicast sender", frames.ARP(layers.ARPReply, frames.MDNSv4, "192.168.110.50", hmi, "192.168.110.20"), All, nil},

		{"ipv4 source", frames.ICMPv4Echo(hmi, plc, "192.168.110.20", "192.168.110.50"), All,
			[]string{"passive_ipv4 mac=00:0e:8c:11:22:33 ip=192.168.110.20"}},
		{"ipv4 source disabled", frames.ICMPv4Echo(hmi, plc, "192.168.110.20", "192.168.110.50"), Protocols{ARP: true}, nil},
		{"routed source is still reported", frames.ICMPv4Echo(router, plc, "8.8.8.8", "192.168.110.50"), All,
			[]string{"passive_ipv4 mac=00:00:5e:00:01:01 ip=8.8.8.8"}},

		{"dhcp discover", frames.DHCP{Type: layers.DHCPMsgTypeDiscover, Client: hmi, Hostname: "HMI-Line3",
			ClientID: append([]byte{1}, hmi...), ParamRequest: pcPRL, VendorClass: "MSFT 5.0"}.Frame(), All,
			[]string{"passive_dhcp mac=00:0e:8c:11:22:33 name=dhcp:HMI-Line3 client_id=01:00:0e:8c:11:22:33 dhcp=discover " +
				"parameter_request_list=1,3,6,15,31,33,43,44,46,47,119,121,249,252 vendor_class=MSFT 5.0"}},
		{"dhcp ack is a lease for yiaddr", frames.DHCP{Type: layers.DHCPMsgTypeAck, Client: hmi, YourIP: "192.168.110.21",
			Server: server, ServerIP: "192.168.110.2"}.Frame(), All,
			[]string{"passive_dhcp_lease mac=00:0e:8c:11:22:33 ip=192.168.110.21 dhcp=ack",
				"passive_dhcp_server mac=02:00:00:00:00:53 ip=192.168.110.2 dhcp=ack"}},
		{"dhcp ack with server options", frames.DHCP{Type: layers.DHCPMsgTypeAck, Client: hmi, YourIP: "192.168.110.21",
			Server: server, ServerIP: "192.168.110.2", ServerID: "192.168.110.2", Router: []string{"192.168.110.1"},
			DNS: []string{"192.168.110.2", "9.9.9.9"}, SubnetMask: "255.255.255.0", LeaseSeconds: 86400}.Frame(), All,
			[]string{"passive_dhcp_lease mac=00:0e:8c:11:22:33 ip=192.168.110.21 dhcp=ack lease_seconds=86400 server_id=192.168.110.2",
				"passive_dhcp_server mac=02:00:00:00:00:53 ip=192.168.110.2 dhcp=ack dns=192.168.110.2,9.9.9.9 router=192.168.110.1 " +
					"server_id=192.168.110.2 subnet_mask=255.255.255.0"}},
		{"dhcp relayed offer: the sender is the relay", frames.DHCP{Type: layers.DHCPMsgTypeOffer, Client: hmi, YourIP: "192.168.110.21",
			Server: router, ServerIP: "192.168.110.1", ServerID: "10.1.0.5", Relay: "192.168.110.1", RelayAgent: []byte{1, 2, 'p', '7'},
			Router: []string{"192.168.110.1"}}.Frame(), Protocols{DHCP: true},
			[]string{"passive_dhcp mac=00:0e:8c:11:22:33 dhcp=offer server_id=10.1.0.5",
				"passive_dhcp_server mac=00:00:5e:00:01:01 ip=192.168.110.1 dhcp=offer relay=192.168.110.1 relay_agent=true " +
					"router=192.168.110.1 server_id=10.1.0.5"}},
		{"dhcp nak advertises nothing", frames.DHCP{Type: layers.DHCPMsgTypeNak, Client: hmi, Server: server, ServerIP: "192.168.110.2",
			ServerID: "192.168.110.2", Router: []string{"192.168.110.1"}}.Frame(), Protocols{DHCP: true},
			[]string{"passive_dhcp mac=00:0e:8c:11:22:33 dhcp=nak server_id=192.168.110.2",
				"passive_dhcp_server mac=02:00:00:00:00:53 ip=192.168.110.2 dhcp=nak server_id=192.168.110.2"}},
		{"dhcp ack to an inform: configuration only", frames.DHCP{Type: layers.DHCPMsgTypeAck, Client: hmi, ClientIP: "192.168.110.30",
			Server: server, ServerIP: "192.168.110.2", ServerID: "192.168.110.2", DNS: []string{"192.168.110.2"}}.Frame(), Protocols{DHCP: true},
			[]string{"passive_dhcp mac=00:0e:8c:11:22:33 dhcp=ack server_id=192.168.110.2",
				"passive_dhcp_server mac=02:00:00:00:00:53 ip=192.168.110.2 config_only=true dhcp=ack dns=192.168.110.2 server_id=192.168.110.2"}},
		{"dhcp invalid server identifier: identity unknown", frames.DHCP{Type: layers.DHCPMsgTypeOffer, Client: hmi, YourIP: "192.168.110.21",
			Server: server, ServerIP: "192.168.110.2", ServerID: "255.255.255.255", LeaseSeconds: 0xffffffff}.Frame(), Protocols{DHCP: true},
			[]string{"passive_dhcp mac=00:0e:8c:11:22:33 dhcp=offer", "passive_dhcp_server mac=02:00:00:00:00:53 ip=192.168.110.2 dhcp=offer"}},
		{"dhcp infinite lease", frames.DHCP{Type: layers.DHCPMsgTypeAck, Client: hmi, YourIP: "192.168.110.21",
			Server: server, ServerIP: "192.168.110.2", LeaseSeconds: 0xffffffff}.Frame(), Protocols{DHCP: true},
			[]string{"passive_dhcp_lease mac=00:0e:8c:11:22:33 ip=192.168.110.21 dhcp=ack lease_seconds=infinite",
				"passive_dhcp_server mac=02:00:00:00:00:53 ip=192.168.110.2 dhcp=ack"}},
		{"dhcp renewing request: the client's claim", frames.DHCP{Type: layers.DHCPMsgTypeRequest, Client: hmi, ClientIP: "192.168.110.21"}.Frame(), All,
			[]string{"passive_dhcp mac=00:0e:8c:11:22:33 ip=192.168.110.21 dhcp=request"}},
		{"dhcp inform: an address the client already has", frames.DHCP{Type: layers.DHCPMsgTypeInform, Client: hmi, ClientIP: "192.168.110.30"}.Frame(), Protocols{DHCP: true},
			[]string{"passive_dhcp mac=00:0e:8c:11:22:33 ip=192.168.110.30 dhcp=inform"}},
		{"dhcp offer binds nothing", frames.DHCP{Type: layers.DHCPMsgTypeOffer, Client: hmi, YourIP: "192.168.110.21",
			Server: server, ServerIP: "192.168.110.2"}.Frame(), Protocols{DHCP: true},
			[]string{"passive_dhcp mac=00:0e:8c:11:22:33 dhcp=offer", "passive_dhcp_server mac=02:00:00:00:00:53 ip=192.168.110.2 dhcp=offer"}},
		{"dhcp release binds nothing", frames.DHCP{Type: layers.DHCPMsgTypeRelease, Client: hmi, ClientIP: "192.168.110.21"}.Frame(), Protocols{DHCP: true},
			[]string{"passive_dhcp mac=00:0e:8c:11:22:33 dhcp=release"}},
		{"dhcp disabled", frames.DHCP{Type: layers.DHCPMsgTypeDiscover, Client: hmi}.Frame(), Protocols{IPv4: true}, nil},

		{"mdns announcement", frames.MDNS4(plc, "192.168.110.50",
			[]layers.DNSResourceRecord{
				frames.PTR("_services._dns-sd._udp.local", "_http._tcp.local"),
				frames.PTR("_http._tcp.local", "PLC 1._http._tcp.local"),
				frames.SRV("PLC 1._http._tcp.local", "plc-1.local", 80),
				frames.TXT("PLC 1._http._tcp.local", "model=S7-1500", "path=/"),
				frames.A("plc-1.local", "192.168.110.50"),
			},
			[]layers.DNSResourceRecord{frames.A("plc-1.local", "fe80::21b:1bff:feaa:bb01"), frames.SRV("x._modbus._tcp.local", "plc-1.local", 502)}), All,
			[]string{
				"passive_mdns mac=00:1b:1b:aa:bb:01 ip=192.168.110.50 name=mdns:plc-1.local service_ports=_http._tcp=80,_modbus._tcp=502 services=_http._tcp,_modbus._tcp txt=model=S7-1500;path=/",
				"passive_mdns mac=00:1b:1b:aa:bb:01 ip=fe80::21b:1bff:feaa:bb01 name=mdns:plc-1.local service_ports=_http._tcp=80,_modbus._tcp=502 services=_http._tcp,_modbus._tcp txt=model=S7-1500;path=/",
			}},
		{"mdns alias does not replace the hostname", frames.MDNS4(plc, "192.168.110.50",
			[]layers.DNSResourceRecord{frames.A("alias.local", "192.168.110.60"), frames.A("plc-1.local", "192.168.110.50")}, nil), Protocols{MDNS: true},
			[]string{"passive_mdns mac=00:1b:1b:aa:bb:01 ip=192.168.110.60", "passive_mdns mac=00:1b:1b:aa:bb:01 ip=192.168.110.50 name=mdns:plc-1.local"}},
		{"mdns services only", frames.MDNS4(plc, "192.168.110.50",
			[]layers.DNSResourceRecord{frames.SRV("x._workstation._tcp.local", "plc-1.local.", 9)}, nil), Protocols{MDNS: true},
			[]string{"passive_mdns mac=00:1b:1b:aa:bb:01 ip=192.168.110.50 name=mdns:plc-1.local service_ports=_workstation._tcp=9 services=_workstation._tcp"}},
		{"mdns over ipv6", frames.UDP6(plc, frames.MDNSv6, "fe80::21b:1bff:feaa:bb01", "ff02::fb", 5353, 5353,
			frames.DNSResponse([]layers.DNSResourceRecord{frames.A("plc-1.local", "fe80::21b:1bff:feaa:bb01")}, nil)), All,
			[]string{"passive_mdns mac=00:1b:1b:aa:bb:01 ip=fe80::21b:1bff:feaa:bb01 name=mdns:plc-1.local"}},
		{"mdns over ipv6 with ipv6 disabled", frames.UDP6(plc, frames.MDNSv6, "fe80::21b:1bff:feaa:bb01", "ff02::fb", 5353, 5353,
			frames.DNSResponse([]layers.DNSResourceRecord{frames.A("plc-1.local", "fe80::21b:1bff:feaa:bb01")}, nil)), Protocols{MDNS: true}, nil},
		{"mdns query is ignored", frames.UDP4(plc, frames.MDNSv4, "192.168.110.50", "224.0.0.251", 5353, 5353, &layers.DNS{
			Questions: []layers.DNSQuestion{{Name: []byte("plc-1.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}), Protocols{MDNS: true}, nil},

		{"dns ptr answers", frames.UDP4(server, hmi, "192.168.110.2", "192.168.110.20", 53, 40000, frames.DNSResponse(
			[]layers.DNSResourceRecord{
				frames.PTR("50.110.168.192.in-addr.arpa", "plc-1.plant.example."),
				frames.PTR("1.0.b.b.a.a.e.f.f.f.b.1.b.1.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa", "plc-1.plant.example."),
				frames.A("plc-1.plant.example", "192.168.110.50"),
			}, nil)), Protocols{DNS: true},
			[]string{"passive_dns ip=192.168.110.50 name=dns_ptr:plc-1.plant.example", "passive_dns ip=fe80::21b:1bff:feaa:bb01 name=dns_ptr:plc-1.plant.example"}},
		{"dns ptr for a non-reverse name", frames.UDP4(server, hmi, "192.168.110.2", "192.168.110.20", 53, 40000, frames.DNSResponse(
			[]layers.DNSResourceRecord{frames.PTR("_http._tcp.example", "x._http._tcp.example")}, nil)), Protocols{DNS: true}, nil},

		{"ndp neighbour advertisement", frames.NeighborAdvertisement(plc, "fe80::21b:1bff:feaa:bb01", "fd5e:5e:1::50", 0xa0), All,
			[]string{"passive_ndp mac=00:1b:1b:aa:bb:01 ip=fd5e:5e:1::50 flags=router,override ndp=neighbor_advertisement",
				"passive_ipv6 mac=00:1b:1b:aa:bb:01 ip=fe80::21b:1bff:feaa:bb01"}},
		{"ndp neighbour solicitation", frames.NeighborSolicitation(hmi, "fe80::20e:8cff:fe11:2233", "fe80::1"), All,
			[]string{"passive_ndp mac=00:0e:8c:11:22:33 ip=fe80::20e:8cff:fe11:2233 ndp=neighbor_solicitation"}},
		{"ndp duplicate address detection", frames.NeighborSolicitation(hmi, "::", "fd5e:5e:1::20"), All,
			[]string{"passive_ndp mac=00:0e:8c:11:22:33 ndp=dad target=fd5e:5e:1::20"}},
		{"ndp router advertisement", frames.RouterAdvertisement(router, "fe80::1"), All,
			[]string{"passive_ndp mac=00:00:5e:00:01:01 ip=fe80::1 ndp=router_advertisement"}},
		{"ipv6 disabled", frames.RouterAdvertisement(router, "fe80::1"), Protocols{ARP: true, IPv4: true}, nil},

		{"lldp from a switch", frames.LLDP{Source: swPort, ChassisMAC: sw, PortID: "ge-0/0/23", TTL: 120,
			SystemName: "plant-sw-01", SystemDesc: "Industrial Ethernet Switch\x00", PortDesc: "PLC line 3", Caps: 0x14,
			MgmtIP: "192.168.110.2"}.Frame(), All,
			[]string{"passive_lldp mac=00:1e:c9:00:00:01 name=lldp:plant-sw-01 capabilities=bridge,router chassis_id=00:1e:c9:00:00:01 " +
				"management_ip=192.168.110.2 port_description=PLC line 3 port_id=ge-0/0/23 system_description=Industrial Ethernet Switch"}},
		{"lldp with a local chassis id", frames.LLDP{Source: swPort, ChassisText: "SN1234", PortID: "X1 P1", TTL: 20}.Frame(), All,
			[]string{"passive_lldp mac=00:1e:c9:00:00:17 chassis_id=SN1234 port_id=X1 P1"}},
		{"lldp shutdown", frames.LLDP{Source: swPort, ChassisMAC: sw, PortID: "1", TTL: 0, SystemName: "x"}.Frame(), All, nil},
		{"lldp disabled", frames.LLDP{Source: swPort, ChassisMAC: sw, PortID: "1", TTL: 120}.Frame(), Protocols{ARP: true}, nil},

		{"runt frame", []byte{1, 2, 3}, All, nil},
		{"vlan tagged frame", tagged(frames.ARP(layers.ARPReply, plc, "192.168.110.50", hmi, "192.168.110.20"), 100), All, nil},
		{"priority-tagged frame", tagged(frames.ARP(layers.ARPReply, plc, "192.168.110.50", hmi, "192.168.110.20"), 0), All,
			[]string{"passive_arp mac=00:1b:1b:aa:bb:01 ip=192.168.110.50 arp=reply"}},
		{"truncated tag", append(append(slices.Clone(bcast), plc...), 0x81, 0x00, 0), All, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summaries(Decode(tt.p, t0, "eth1", tt.frame))
			if !slices.Equal(got, tt.want) {
				t.Errorf("got\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(tt.want, "\n  "))
			}
		})
	}
}

// tagged inserts an 802.1Q tag with priority 6 and the VLAN ID vid.
func tagged(frame []byte, vid uint16) []byte {
	tag := []byte{0x81, 0x00, 0xc0 | byte(vid>>8), byte(vid)}
	return slices.Concat(frame[:12], tag, frame[12:])
}

// Malformed and truncated frames produce nothing (and never panic; see the
// fuzz targets).
func TestDecodeMalformed(t *testing.T) {
	arp := frames.ARP(layers.ARPReply, plc, "192.168.110.50", hmi, "192.168.110.20")
	dhcp := frames.DHCP{Type: layers.DHCPMsgTypeAck, Client: hmi, YourIP: "192.168.110.21", Server: server, ServerIP: "192.168.110.2"}.Frame()
	mdns := frames.MDNS4(plc, "192.168.110.50", []layers.DNSResourceRecord{frames.A("plc-1.local", "192.168.110.50")}, nil)
	na := frames.NeighborAdvertisement(plc, "fe80::21b:1bff:feaa:bb01", "fd5e:5e:1::50", 0x20)
	lldp := frames.LLDP{Source: swPort, ChassisMAC: sw, PortID: "1", TTL: 120, SystemName: "sw"}.Frame()
	set := func(b []byte, off int, v ...byte) []byte {
		b = slices.Clone(b)
		copy(b[off:], v)
		return b
	}
	tests := []struct {
		name  string
		frame []byte
	}{
		{"arp truncated", arp[:14+27]},
		{"arp wrong hardware type", set(arp, 14, 0, 6)},
		{"arp unknown op", set(arp, 14+6, 0, 9)},
		{"ipv4 bad version", set(dhcp, 14, 0x65)},
		{"ipv4 bad ihl", set(dhcp, 14, 0x41)},
		{"ipv4 total shorter than header", set(dhcp, 14+2, 0, 10)},
		{"dhcp bad magic", set(dhcp, 14+20+8+236, 0)},
		{"dhcp truncated", dhcp[:14+20+8+200]},
		{"ndp hop limit not 255", set(na, 14+7, 64)},
		{"ndp non-zero code", set(na, 14+40+1, 1)},
		{"ndp truncated", na[:14+40+20]},
		{"lldp truncated tlv", lldp[:14+5]},
		{"lldp without ttl", frames.Build(frames.Ethernet(swPort, frames.LLDPDst, layers.EthernetTypeLinkLayerDiscovery),
			gopacket.Payload{0x02, 0x07, 4, 0, 0x1e, 0xc9, 0, 0, 1, 0, 0})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decode(All, t0, "eth1", tt.frame)
			// Only the IPv4/IPv6 header learning may survive damage to an
			// upper layer.
			for _, o := range got {
				if o.Source != observation.PassiveIPv4 && o.Source != observation.PassiveIPv6 {
					t.Errorf("unexpected %s", summary(o))
				}
			}
		})
	}
	// A broken mDNS record after a good one keeps the good one.
	broken := slices.Clone(mdns)
	broken = broken[:len(broken)-2]
	binary.BigEndian.PutUint16(broken[14+4:], uint16(len(broken)-14))
	binary.BigEndian.PutUint16(broken[14+20+4:], uint16(len(broken)-14-20))
	if got := summaries(Decode(Protocols{MDNS: true}, t0, "eth1", broken)); len(got) != 0 {
		t.Errorf("truncated A record: %v", got)
	}
}

func TestText(t *testing.T) {
	for in, want := range map[string]string{
		"  plc-1\x00 ":           "plc-1",
		"a\tb\nc":                "a b c",
		"\xff\xfeok":             "ok",
		strings.Repeat("x", 300): strings.Repeat("x", maxText),
		"Läufer-PLC":             "Läufer-PLC",
	} {
		if got := text([]byte(in), maxText); got != want {
			t.Errorf("text(%q) = %q, want %q", in, got, want)
		}
	}
	if got := hostname("plc-1.local."); got != "plc-1.local" {
		t.Errorf("hostname = %q", got)
	}
	if got := text([]byte("ääää"), 5); got != "ää" {
		t.Errorf("text cut inside a rune = %q", got)
	}
}

func TestReverseAddr(t *testing.T) {
	for in, want := range map[string]string{
		"50.110.168.192.in-addr.arpa.": "192.168.110.50",
		"50.110.168.192.IN-ADDR.ARPA":  "192.168.110.50",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa": "fe80::1",
		"110.168.192.in-addr.arpa":   "",
		"x.110.168.192.in-addr.arpa": "",
		"1.0.ip6.arpa":               "",
		"g.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa": "",
		"plc.example": "",
	} {
		ip, ok := reverseAddr(in)
		if got := ""; ok {
			got = ip.String()
			if got != want {
				t.Errorf("reverseAddr(%q) = %s, want %q", in, got, want)
			}
		} else if want != "" {
			t.Errorf("reverseAddr(%q) failed, want %s", in, want)
		}
	}
	_ = netip.Addr{}
}

func TestServiceType(t *testing.T) {
	for in, want := range map[string]string{
		"PLC 1._http._tcp.local.":       "_http._tcp",
		"_printer._sub._ipp._tcp.local": "_ipp._tcp",
		"_services._dns-sd._udp.local":  "_dns-sd._udp",
		"plc-1.local":                   "",
		"_._tcp.local":                  "",
	} {
		if got := serviceType(in); got != want {
			t.Errorf("serviceType(%q) = %q, want %q", in, got, want)
		}
	}
}
