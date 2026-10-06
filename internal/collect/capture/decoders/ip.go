package decoders

import (
	"net/netip"

	"lan-sentinel/internal/observation"
)

const (
	protoICMPv6 = 58
	protoUDP    = 17
)

// ipv4 decodes the IPv4 header (source-address learning) and the UDP
// protocols carried over it.
func (f *frame) ipv4(b []byte) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(be16(b[2:]))
	if ihl < 20 || len(b) < ihl || total < ihl {
		return
	}
	if total < len(b) {
		b = b[:total] // Ethernet padding
	}
	src := addr4(b[12:16])
	fragment := be16(b[6:])
	// Only an unfragmented datagram has the whole UDP payload.
	if b[9] == protoUDP && fragment&0x3fff == 0 {
		f.udp(src, b[ihl:])
	}
	if f.p.IPv4 {
		f.source(observation.PassiveIPv4, src)
	}
}

// ipv6 decodes the IPv6 header (source-address learning), NDP and the UDP
// protocols carried directly over it. Extension headers are not followed:
// NDP never has them, and mDNS and DNS rarely do.
func (f *frame) ipv6(b []byte) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return
	}
	payload := b[40:]
	if n := int(be16(b[4:])); n < len(payload) {
		payload = payload[:n]
	}
	src := addr16(b[8:24])
	switch b[6] {
	case protoICMPv6:
		f.ndp(src, b[7], payload)
	case protoUDP:
		f.udp(src, payload)
	}
	f.source(observation.PassiveIPv6, src)
}

// udp dispatches DHCP (IPv4 only), mDNS responses and DNS responses.
func (f *frame) udp(src netip.Addr, b []byte) {
	if len(b) < 8 {
		return
	}
	sport, dport := be16(b[0:]), be16(b[2:])
	if n := int(be16(b[4:])); n >= 8 && n < len(b) {
		b = b[:n]
	}
	payload := b[8:]
	switch {
	case f.p.DHCP && src.Is4() && (sport == PortDHCPClient && dport == PortDHCPServer || sport == PortDHCPServer && dport == PortDHCPClient):
		f.dhcp(payload)
	case f.p.MDNS && sport == PortMDNS:
		f.mdns(src, payload)
	case f.p.DNS && sport == PortDNS:
		f.dns(payload)
	}
}
