package decoders

import "lan-sentinel/internal/observation"

// ARP operation kinds recorded in the "arp" meta key.
const (
	ARPRequest    = "request"
	ARPReply      = "reply"
	ARPGratuitous = "gratuitous" // announcement: sender IP == target IP
	ARPProbe      = "probe"      // RFC 5227 probe: sender IP 0.0.0.0
)

// arp decodes an Ethernet/IPv4 ARP packet. The sender hardware and protocol
// addresses are the evidence ("IP is at MAC"); target fields are not, except
// that a probe records the address it asks about in the "target" meta key.
func (f *frame) arp(b []byte) {
	if len(b) < 28 || be16(b[0:]) != 1 || be16(b[2:]) != EtherTypeIPv4 || b[4] != 6 || b[5] != 4 {
		return
	}
	op := be16(b[6:])
	if op != 1 && op != 2 {
		return
	}
	sha, spa, tpa := copyMAC(b[8:14]), addr4(b[14:18]), addr4(b[24:28])
	o := observation.Observation{Source: observation.PassiveARP, MAC: sha}
	switch {
	case spa.IsUnspecified():
		o.Meta = map[string]string{"arp": ARPProbe, "target": tpa.String()}
	case spa == tpa:
		o.IP, o.Meta = spa, map[string]string{"arp": ARPGratuitous}
	case op == 1:
		o.IP, o.Meta = spa, map[string]string{"arp": ARPRequest}
	default:
		o.IP, o.Meta = spa, map[string]string{"arp": ARPReply}
	}
	f.add(o)
}
