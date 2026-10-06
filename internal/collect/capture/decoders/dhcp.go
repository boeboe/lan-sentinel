package decoders

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"

	"lan-sentinel/internal/observation"
)

// DHCP option codes.
const (
	dhcpOptPad          = 0
	dhcpOptSubnetMask   = 1
	dhcpOptRouter       = 3
	dhcpOptDNS          = 6
	dhcpOptHostname     = 12
	dhcpOptLeaseTime    = 51
	dhcpOptMessageType  = 53
	dhcpOptServerID     = 54
	dhcpOptParamRequest = 55
	dhcpOptVendorClass  = 60
	dhcpOptClientID     = 61
	dhcpOptRelayAgent   = 82
	dhcpOptEnd          = 255
	dhcpMagic           = 0x63825363
	dhcpFixedLen        = 240 // BOOTP header and magic cookie

	maxClientID     = 64  // bytes of option 61 kept
	maxParamRequest = 128 // codes of option 55 kept
	maxAddrList     = 8   // addresses of options 3 and 6 kept
)

// DHCP message types (option 53).
const (
	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpDecline  = 4
	dhcpAck      = 5
	dhcpNak      = 6
	dhcpRelease  = 7
	dhcpInform   = 8
)

var dhcpTypes = map[byte]string{
	dhcpDiscover: "discover", dhcpOffer: "offer", dhcpRequest: "request", dhcpDecline: "decline",
	dhcpAck: "ack", dhcpNak: "nak", dhcpRelease: "release", dhcpInform: "inform",
}

// dhcp decodes a DHCPv4 message between a client and a server or relay
// (FR-PA-3, FR-PA-7), sent from src. It reports the client: its hardware
// address with the address it holds by the message's own account, which
// has distinct provenance (docs/DATA_MODEL.md §2): passive_dhcp_lease for
// yiaddr in an ACK, which the server allocated or renewed; passive_dhcp for
// ciaddr in a REQUEST or an INFORM, which the client claims to use (an
// INFORM's address may well be static). Offers, declines, releases, naks and
// the ACK that answers an INFORM (yiaddr 0) bind no address. The hostname
// (option 12) and client identifier (61) are kept, and so are the parameter
// request list (55) and vendor class (60) for later fingerprinting. A
// server's reply (OFFER, ACK, NAK) also reports its sender, the server or
// the relay that forwarded it, as passive_dhcp_server, with the server
// identifier (54) kept apart from the sender and the configuration it
// advertises.
func (f *frame) dhcp(src netip.Addr, b []byte) {
	if len(b) < dhcpFixedLen || binary.BigEndian.Uint32(b[236:240]) != dhcpMagic || b[1] != 1 || b[2] != 6 {
		return
	}
	opts := dhcpOptions(b[dhcpFixedLen:])
	mt := opts[dhcpOptMessageType]
	if len(mt) != 1 || dhcpTypes[mt[0]] == "" {
		return // BOOTP or an unknown message type
	}
	typ := mt[0]
	reply := typ == dhcpOffer || typ == dhcpAck || typ == dhcpNak
	op := byte(1) // BOOTREQUEST
	if reply {
		op = 2 // BOOTREPLY
	}
	if b[0] != op {
		return // op and message type disagree
	}
	o := observation.Observation{Source: observation.PassiveDHCP, MAC: copyMAC(b[28:34]),
		Meta: map[string]string{observation.MetaDHCP: dhcpTypes[typ]}}
	ciaddr, yiaddr := addr4(b[12:16]), addr4(b[16:20])
	switch typ {
	case dhcpAck:
		if !yiaddr.IsUnspecified() {
			o.Source, o.IP = observation.PassiveDHCPLease, yiaddr
			if lease := dhcpLease(opts[dhcpOptLeaseTime]); lease != "" {
				o.Meta[observation.MetaLeaseSeconds] = lease
			}
		}
	case dhcpRequest, dhcpInform:
		o.IP = ciaddr
	}
	serverID := dhcpAddr(opts[dhcpOptServerID])
	if reply && serverID.IsValid() {
		o.Meta[observation.MetaServerID] = serverID.String()
	}
	if h := hostname(string(opts[dhcpOptHostname])); h != "" {
		o.Hostname, o.NameType = h, observation.NameDHCP
	}
	if id := opts[dhcpOptClientID]; len(id) > 0 {
		o.Meta["client_id"] = hexBytes(id[:min(len(id), maxClientID)])
	}
	if prl := opts[dhcpOptParamRequest]; len(prl) > 0 {
		prl = prl[:min(len(prl), maxParamRequest)]
		codes := make([]string, len(prl))
		for i, c := range prl {
			codes[i] = strconv.Itoa(int(c))
		}
		o.Meta["parameter_request_list"] = strings.Join(codes, ",")
	}
	if vc := text(opts[dhcpOptVendorClass], maxText); vc != "" {
		o.Meta["vendor_class"] = vc
	}
	if !o.IP.IsValid() || o.IP.IsUnspecified() {
		o.IP = netip.Addr{}
	}
	f.add(o)
	if reply && f.src != nil {
		f.dhcpServer(src, typ, serverID, addr4(b[24:28]), yiaddr.IsUnspecified(), opts)
	}
}

// dhcpServer reports the sender of a server reply: the frame's source MAC
// and IP, which belong to the relay when the reply was relayed (giaddr
// set). The server identifier is absent when the reply has none or an
// invalid one; such a server's identity is unknown. Offers and ACKs carry
// the configuration they advertise; a NAK carries none.
func (f *frame) dhcpServer(src netip.Addr, typ byte, serverID, giaddr netip.Addr, noAddress bool, opts map[byte][]byte) {
	meta := map[string]string{observation.MetaDHCP: dhcpTypes[typ]}
	if serverID.IsValid() {
		meta[observation.MetaServerID] = serverID.String()
	}
	if usableIP(giaddr) {
		meta[observation.MetaRelay] = giaddr.String()
	}
	if _, ok := opts[dhcpOptRelayAgent]; ok {
		meta[observation.MetaRelayAgent] = "true"
	}
	if typ == dhcpAck && noAddress {
		meta[observation.MetaConfigOnly] = "true"
	}
	if typ != dhcpNak {
		if v := dhcpAddrList(opts[dhcpOptRouter]); v != "" {
			meta[observation.MetaRouter] = v
		}
		if v := dhcpAddrList(opts[dhcpOptDNS]); v != "" {
			meta[observation.MetaDNS] = v
		}
		if m := opts[dhcpOptSubnetMask]; len(m) == 4 {
			meta[observation.MetaSubnetMask] = addr4(m).String()
		}
	}
	f.add(observation.Observation{Source: observation.PassiveDHCPServer, MAC: f.src, IP: src, Meta: meta})
}

// dhcpAddr returns the address of a 4-byte address option if it is a
// usable unicast address, else the zero Addr.
func dhcpAddr(b []byte) netip.Addr {
	if len(b) != 4 {
		return netip.Addr{}
	}
	if a := addr4(b); usableIP(a) {
		return a
	}
	return netip.Addr{}
}

// dhcpAddrList formats an address-list option (router, DNS servers) as
// comma-separated addresses; "" if it is malformed.
func dhcpAddrList(b []byte) string {
	if len(b) == 0 || len(b)%4 != 0 {
		return ""
	}
	n := min(len(b)/4, maxAddrList)
	addrs := make([]string, n)
	for i := range n {
		addrs[i] = addr4(b[4*i:]).String()
	}
	return strings.Join(addrs, ",")
}

// dhcpLease formats the lease time option in seconds, "infinite" for
// 0xffffffff; "" if it is malformed.
func dhcpLease(b []byte) string {
	if len(b) != 4 {
		return ""
	}
	if v := binary.BigEndian.Uint32(b); v != math.MaxUint32 {
		return strconv.FormatUint(uint64(v), 10)
	}
	return "infinite"
}

// dhcpOptions parses the options field into code → data. A repeated code
// is concatenated (RFC 3396). Parsing stops at the end option or at the
// first truncated option.
func dhcpOptions(b []byte) map[byte][]byte {
	opts := map[byte][]byte{}
	for len(b) > 0 {
		code := b[0]
		if code == dhcpOptEnd {
			break
		}
		if code == dhcpOptPad {
			b = b[1:]
			continue
		}
		if len(b) < 2 || len(b) < 2+int(b[1]) {
			break
		}
		n := int(b[1])
		opts[code] = append(opts[code], b[2:2+n]...)
		b = b[2+n:]
	}
	return opts
}

// hexBytes formats b as colon-separated hex, like a MAC.
func hexBytes(b []byte) string {
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02x", x)
	}
	return sb.String()
}
