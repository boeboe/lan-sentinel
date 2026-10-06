// Package frames builds Ethernet frames for tests, the pcap fixture
// generator (test/fixtures/gen) and the Docker frame injector
// (test/net/inject). It serialises with gopacket's layers, an encoder
// independent of LAN Sentinel's decoders.
package frames

import (
	"net"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Well-known destination MACs.
var (
	Broadcast = MAC("ff:ff:ff:ff:ff:ff")
	MDNSv4    = MAC("01:00:5e:00:00:fb")
	MDNSv6    = MAC("33:33:00:00:00:fb")
	AllNodes  = MAC("33:33:00:00:00:01")
	LLDPDst   = MAC("01:80:c2:00:00:0e")
)

// MAC parses a MAC address and panics on error (test input only).
func MAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// IP parses an address and panics on error (test input only).
func IP(s string) net.IP { return netip.MustParseAddr(s).AsSlice() }

// Build serialises layers with computed lengths and checksums.
func Build(ls ...gopacket.SerializableLayer) []byte {
	for i, l := range ls {
		var nl gopacket.NetworkLayer
		if i > 0 {
			nl, _ = ls[i-1].(gopacket.NetworkLayer)
		}
		switch x := l.(type) {
		case *layers.UDP:
			if nl != nil {
				_ = x.SetNetworkLayerForChecksum(nl)
			}
		case *layers.TCP:
			if nl != nil {
				_ = x.SetNetworkLayerForChecksum(nl)
			}
		case *layers.ICMPv6:
			if nl != nil {
				_ = x.SetNetworkLayerForChecksum(nl)
			}
		}
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// Ethernet returns an Ethernet II header.
func Ethernet(src, dst net.HardwareAddr, t layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: t}
}

// ARP builds an ARP frame. op is layers.ARPRequest or layers.ARPReply.
func ARP(op uint16, sha net.HardwareAddr, spa string, tha net.HardwareAddr, tpa string) []byte {
	dst := Broadcast
	if op == layers.ARPReply {
		dst = tha
	}
	return Build(Ethernet(sha, dst, layers.EthernetTypeARP), &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
		Operation: op, SourceHwAddress: sha, SourceProtAddress: IP(spa).To4(),
		DstHwAddress: tha, DstProtAddress: IP(tpa).To4(),
	})
}

// IPv4 returns an IPv4 header carrying proto.
func IPv4(src, dst string, proto layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: proto, SrcIP: IP(src).To4(), DstIP: IP(dst).To4()}
}

// IPv6 returns an IPv6 header carrying next.
func IPv6(src, dst string, next layers.IPProtocol, hopLimit uint8) *layers.IPv6 {
	return &layers.IPv6{Version: 6, NextHeader: next, HopLimit: hopLimit, SrcIP: IP(src), DstIP: IP(dst)}
}

// UDP4 builds an Ethernet/IPv4/UDP frame around payload.
func UDP4(srcMAC, dstMAC net.HardwareAddr, src, dst string, sport, dport uint16, payload gopacket.SerializableLayer) []byte {
	return Build(Ethernet(srcMAC, dstMAC, layers.EthernetTypeIPv4), IPv4(src, dst, layers.IPProtocolUDP),
		&layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}, payload)
}

// UDP6 builds an Ethernet/IPv6/UDP frame around payload.
func UDP6(srcMAC, dstMAC net.HardwareAddr, src, dst string, sport, dport uint16, payload gopacket.SerializableLayer) []byte {
	return Build(Ethernet(srcMAC, dstMAC, layers.EthernetTypeIPv6), IPv6(src, dst, layers.IPProtocolUDP, 255),
		&layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}, payload)
}

// ICMPv4Echo builds an echo reply, for IPv4 source-address learning.
func ICMPv4Echo(srcMAC, dstMAC net.HardwareAddr, src, dst string) []byte {
	return Build(Ethernet(srcMAC, dstMAC, layers.EthernetTypeIPv4), IPv4(src, dst, layers.IPProtocolICMPv4),
		&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0), Id: 1, Seq: 1})
}

// DHCP describes a DHCPv4 message.
type DHCP struct {
	Type         layers.DHCPMsgType
	Client       net.HardwareAddr
	ClientIP     string // ciaddr
	YourIP       string // yiaddr
	Hostname     string
	ClientID     []byte
	ParamRequest []byte
	VendorClass  string
	Server       net.HardwareAddr // frame source for server messages
	ServerIP     string
}

// Frame builds the DHCP message as a client (discover, request, decline,
// release, inform) or server (offer, ack, nak) frame.
func (d DHCP) Frame() []byte {
	msg := &layers.DHCPv4{
		Operation: layers.DHCPOpRequest, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6, Xid: 0x5e5e,
		ClientHWAddr: d.Client, ClientIP: net.IPv4zero, YourClientIP: net.IPv4zero,
		Options: layers.DHCPOptions{layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(d.Type)})},
	}
	if d.ClientIP != "" {
		msg.ClientIP = IP(d.ClientIP).To4()
	}
	if d.YourIP != "" {
		msg.YourClientIP = IP(d.YourIP).To4()
	}
	add := func(t layers.DHCPOpt, v []byte) {
		if len(v) > 0 {
			msg.Options = append(msg.Options, layers.NewDHCPOption(t, v))
		}
	}
	add(layers.DHCPOptHostname, []byte(d.Hostname))
	add(layers.DHCPOptClientID, d.ClientID)
	add(layers.DHCPOptParamsRequest, d.ParamRequest)
	add(layers.DHCPOptClassID, []byte(d.VendorClass))
	switch d.Type {
	case layers.DHCPMsgTypeOffer, layers.DHCPMsgTypeAck, layers.DHCPMsgTypeNak:
		msg.Operation = layers.DHCPOpReply
		return UDP4(d.Server, Broadcast, d.ServerIP, "255.255.255.255", 67, 68, msg)
	}
	src := "0.0.0.0"
	if d.ClientIP != "" {
		src = d.ClientIP
	}
	return UDP4(d.Client, Broadcast, src, "255.255.255.255", 68, 67, msg)
}

// A returns an mDNS/DNS A or AAAA record.
func A(name, ip string) layers.DNSResourceRecord {
	t := layers.DNSTypeA
	if netip.MustParseAddr(ip).Is6() {
		t = layers.DNSTypeAAAA
	}
	return layers.DNSResourceRecord{Name: []byte(name), Type: t, Class: layers.DNSClassIN, TTL: 120, IP: IP(ip)}
}

// PTR returns a PTR record.
func PTR(name, target string) layers.DNSResourceRecord {
	return layers.DNSResourceRecord{Name: []byte(name), Type: layers.DNSTypePTR, Class: layers.DNSClassIN, TTL: 120, PTR: []byte(target)}
}

// SRV returns an SRV record.
func SRV(name, target string, port uint16) layers.DNSResourceRecord {
	return layers.DNSResourceRecord{Name: []byte(name), Type: layers.DNSTypeSRV, Class: layers.DNSClassIN, TTL: 120,
		SRV: layers.DNSSRV{Name: []byte(target), Port: port}}
}

// TXT returns a TXT record.
func TXT(name string, txt ...string) layers.DNSResourceRecord {
	r := layers.DNSResourceRecord{Name: []byte(name), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN, TTL: 120}
	for _, s := range txt {
		r.TXTs = append(r.TXTs, []byte(s))
	}
	return r
}

// DNSResponse returns a response message with answers and additional
// records.
func DNSResponse(answers, additionals []layers.DNSResourceRecord) *layers.DNS {
	return &layers.DNS{QR: true, AA: true, OpCode: layers.DNSOpCodeQuery, Answers: answers, Additionals: additionals}
}

// MDNS4 builds an IPv4 mDNS response from src.
func MDNS4(srcMAC net.HardwareAddr, src string, answers, additionals []layers.DNSResourceRecord) []byte {
	return UDP4(srcMAC, MDNSv4, src, "224.0.0.251", 5353, 5353, DNSResponse(answers, additionals))
}

// NDP builds an ICMPv6 neighbour discovery frame with hop limit 255.
func NDP(srcMAC, dstMAC net.HardwareAddr, src, dst string, typ uint8, msg gopacket.SerializableLayer) []byte {
	return Build(Ethernet(srcMAC, dstMAC, layers.EthernetTypeIPv6), IPv6(src, dst, layers.IPProtocolICMPv6, 255),
		&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(typ, 0)}, msg)
}

// NeighborAdvertisement builds an unsolicited NA for target with the
// target link-layer address option.
func NeighborAdvertisement(mac net.HardwareAddr, src, target string, flags uint8) []byte {
	return NDP(mac, AllNodes, src, "ff02::1", layers.ICMPv6TypeNeighborAdvertisement, &layers.ICMPv6NeighborAdvertisement{
		Flags: flags, TargetAddress: IP(target),
		Options: layers.ICMPv6Options{{Type: layers.ICMPv6OptTargetAddress, Data: mac}},
	})
}

// NeighborSolicitation builds an NS for target; from "::" it is duplicate
// address detection (no source link-layer option).
func NeighborSolicitation(mac net.HardwareAddr, src, target string) []byte {
	msg := &layers.ICMPv6NeighborSolicitation{TargetAddress: IP(target)}
	if src != "::" {
		msg.Options = layers.ICMPv6Options{{Type: layers.ICMPv6OptSourceAddress, Data: mac}}
	}
	return NDP(mac, MAC("33:33:ff:00:00:01"), src, "ff02::1:ff00:1", layers.ICMPv6TypeNeighborSolicitation, msg)
}

// RouterAdvertisement builds an RA from a router's link-local address.
func RouterAdvertisement(mac net.HardwareAddr, src string) []byte {
	return NDP(mac, AllNodes, src, "ff02::1", layers.ICMPv6TypeRouterAdvertisement, &layers.ICMPv6RouterAdvertisement{
		HopLimit: 64, RouterLifetime: 1800,
		Options: layers.ICMPv6Options{{Type: layers.ICMPv6OptSourceAddress, Data: mac}},
	})
}

// LLDP describes an LLDPDU.
type LLDP struct {
	Source      net.HardwareAddr
	ChassisMAC  net.HardwareAddr // chassis ID subtype MAC; nil uses a locally assigned ID
	ChassisText string
	PortID      string
	TTL         uint16
	SystemName  string
	SystemDesc  string
	PortDesc    string
	Caps        uint16 // enabled capabilities
	MgmtIP      string
}

// Frame builds the LLDPDU.
func (l LLDP) Frame() []byte {
	d := &layers.LinkLayerDiscovery{
		ChassisID: layers.LLDPChassisID{Subtype: layers.LLDPChassisIDSubTypeLocal, ID: []byte(l.ChassisText)},
		PortID:    layers.LLDPPortID{Subtype: layers.LLDPPortIDSubtypeIfaceName, ID: []byte(l.PortID)},
		TTL:       l.TTL,
	}
	if l.ChassisMAC != nil {
		d.ChassisID = layers.LLDPChassisID{Subtype: layers.LLDPChassisIDSubTypeMACAddr, ID: l.ChassisMAC}
	}
	tlv := func(t layers.LLDPTLVType, v []byte) {
		if len(v) > 0 {
			d.Values = append(d.Values, layers.LinkLayerDiscoveryValue{Type: t, Length: uint16(len(v)), Value: v})
		}
	}
	tlv(layers.LLDPTLVPortDescription, []byte(l.PortDesc))
	tlv(layers.LLDPTLVSysName, []byte(l.SystemName))
	tlv(layers.LLDPTLVSysDescription, []byte(l.SystemDesc))
	if l.Caps != 0 {
		tlv(layers.LLDPTLVSysCapabilities, []byte{byte(l.Caps >> 8), byte(l.Caps), byte(l.Caps >> 8), byte(l.Caps)})
	}
	if l.MgmtIP != "" {
		ip := netip.MustParseAddr(l.MgmtIP)
		family := byte(1)
		if ip.Is6() {
			family = 2
		}
		addr := ip.AsSlice()
		v := append([]byte{byte(1 + len(addr)), family}, addr...)
		v = append(v, 1, 0, 0, 0, 0, 0) // interface numbering: ifIndex 0, no OID
		tlv(layers.LLDPTLVMgmtAddress, v)
	}
	return Build(Ethernet(l.Source, LLDPDst, layers.EthernetTypeLinkLayerDiscovery), d)
}
