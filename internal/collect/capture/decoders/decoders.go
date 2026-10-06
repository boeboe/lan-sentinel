// Package decoders turns captured Ethernet frames into observations
// (docs/ARCHITECTURE.md §3, Passive capture). Decoders are pure functions
// of the frame: live capture and pcap replay share them, and every one has
// a fuzz target. They never panic and never trust lengths in the frame.
//
// Every observation carries the frame's MAC evidence: the sender hardware
// address for ARP, the link-layer address option for NDP, chaddr for DHCP,
// the chassis MAC for LLDP and the source MAC otherwise. DNS PTR answers are
// the exception: they describe other hosts, so they carry no MAC (see
// docs/DATA_MODEL.md §5.1).
package decoders

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"lan-sentinel/internal/identify"
	"lan-sentinel/internal/observation"
)

// EtherTypes the decoders handle.
const (
	EtherTypeIPv4  = 0x0800
	EtherTypeARP   = 0x0806
	EtherTypeIPv6  = 0x86dd
	EtherTypeLLDP  = 0x88cc
	EtherTypeDot1Q = 0x8100
)

// UDP ports the decoders handle.
const (
	PortDNS        = 53
	PortDHCPServer = 67
	PortDHCPClient = 68
	PortMDNS       = 5353
)

// Protocols selects the decoders (config passive.protocols). IPv6 gates
// every IPv6 frame, including NDP and mDNS or DNS over IPv6.
type Protocols struct {
	ARP  bool
	IPv4 bool
	IPv6 bool
	DHCP bool
	MDNS bool
	DNS  bool
	LLDP bool
}

// All enables every decoder.
var All = Protocols{ARP: true, IPv4: true, IPv6: true, DHCP: true, MDNS: true, DNS: true, LLDP: true}

// Limits on text copied from frames into observations.
const (
	maxName = 253 // a DNS name
	maxText = 256 // descriptions, TXT data
)

// frame is the decoding state of one Ethernet frame.
type frame struct {
	p     Protocols
	time  time.Time
	iface string
	src   net.HardwareAddr // Ethernet source, when unicast
	out   []observation.Observation
}

// Decode returns the observations in one Ethernet II frame captured at t on
// iface. Frames of a VLAN are skipped (VLANs are out of scope in v1);
// priority-tagged frames (802.1Q with VLAN ID 0) are decoded as untagged,
// as live capture sees them. Live capture never sees tags (the kernel
// strips them and the filter drops VLAN frames), pcap files may.
func Decode(p Protocols, t time.Time, iface string, data []byte) []observation.Observation {
	if len(data) < 14 {
		return nil
	}
	f := &frame{p: p, time: t, iface: iface}
	if src := net.HardwareAddr(data[6:12]); identify.UnicastMAC(src) {
		f.src = copyMAC(src)
	}
	etherType, payload := binary.BigEndian.Uint16(data[12:14]), data[14:]
	if etherType == EtherTypeDot1Q {
		if len(payload) < 4 || be16(payload)&0x0fff != 0 {
			return nil
		}
		etherType, payload = be16(payload[2:]), payload[4:]
	}
	switch etherType {
	case EtherTypeARP:
		if p.ARP {
			f.arp(payload)
		}
	case EtherTypeIPv4:
		f.ipv4(payload)
	case EtherTypeIPv6:
		if p.IPv6 {
			f.ipv6(payload)
		}
	case EtherTypeLLDP:
		if p.LLDP {
			f.lldp(payload)
		}
	}
	return f.out
}

// add appends o if it has usable evidence: a unicast MAC, or for the
// MAC-less DNS source an address.
func (f *frame) add(o observation.Observation) {
	if o.IP.IsValid() && !usableIP(o.IP) {
		o.IP = netip.Addr{}
	}
	switch {
	case o.Source == observation.PassiveDNS:
		if !o.IP.IsValid() {
			return
		}
	case o.MAC == nil || !identify.UnicastMAC(o.MAC):
		return
	}
	if o.Hostname == "" {
		o.NameType = ""
	}
	o.Time, o.Interface = f.time, f.iface
	f.out = append(f.out, o)
}

// source records the frame's source MAC with an IP header's source address
// (passive_ipv4, passive_ipv6), unless a protocol decoder already reported
// the same pair for this frame.
func (f *frame) source(src observation.Source, ip netip.Addr) {
	if f.src == nil || !usableIP(ip) {
		return
	}
	for _, o := range f.out {
		if o.IP == ip && o.MAC.String() == f.src.String() {
			return
		}
	}
	f.add(observation.Observation{Source: src, MAC: f.src, IP: ip})
}

// usableIP reports unicast host addresses: not unspecified, multicast,
// loopback or the IPv4 limited broadcast.
func usableIP(ip netip.Addr) bool {
	return ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast()
}

func copyMAC(b []byte) net.HardwareAddr { return append(net.HardwareAddr(nil), b...) }

func addr4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b[:4])) }

func addr16(b []byte) netip.Addr { return netip.AddrFrom16([16]byte(b[:16])) }

func be16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }

// text makes frame data safe to store and print: valid UTF-8, no control
// characters, surrounding space trimmed, at most n bytes.
func text(b []byte, n int) string {
	var sb strings.Builder
	for len(b) > 0 && sb.Len() < n {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		switch {
		case r == utf8.RuneError && size <= 1, r == 0:
			continue
		case unicode.IsControl(r):
			r = ' '
		}
		if sb.Len()+utf8.RuneLen(r) > n {
			break
		}
		sb.WriteRune(r)
	}
	return strings.TrimSpace(sb.String())
}

// hostname normalises a DNS, mDNS, DHCP or LLDP name: printable text
// without the trailing root dot. Names with spaces are kept (LLDP system
// names often have them).
func hostname(s string) string {
	return strings.TrimSuffix(text([]byte(s), maxName), ".")
}
