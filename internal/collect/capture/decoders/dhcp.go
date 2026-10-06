package decoders

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"lan-sentinel/internal/observation"
)

// DHCP option codes.
const (
	dhcpOptPad          = 0
	dhcpOptHostname     = 12
	dhcpOptMessageType  = 53
	dhcpOptParamRequest = 55
	dhcpOptVendorClass  = 60
	dhcpOptClientID     = 61
	dhcpOptEnd          = 255
	dhcpMagic           = 0x63825363
	dhcpFixedLen        = 240 // BOOTP header and magic cookie

	maxClientID     = 64  // bytes of option 61 kept
	maxParamRequest = 128 // codes of option 55 kept
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
// (FR-PA-3). The evidence is the client hardware address with the address
// the client holds: yiaddr in an ACK, ciaddr in a renewing REQUEST or an
// INFORM. Offers, declines and releases bind no address. The hostname
// (option 12) and client identifier (61) are kept, and so are the parameter
// request list (55) and vendor class (60) for later fingerprinting.
func (f *frame) dhcp(b []byte) {
	if len(b) < dhcpFixedLen || binary.BigEndian.Uint32(b[236:240]) != dhcpMagic || b[1] != 1 || b[2] != 6 {
		return
	}
	opts := dhcpOptions(b[dhcpFixedLen:])
	mt := opts[dhcpOptMessageType]
	if len(mt) != 1 || dhcpTypes[mt[0]] == "" {
		return // BOOTP or an unknown message type
	}
	typ := mt[0]
	if (b[0] == 1) != (typ == dhcpDiscover || typ == dhcpRequest || typ == dhcpDecline || typ == dhcpRelease || typ == dhcpInform) {
		return // op and message type disagree
	}
	o := observation.Observation{Source: observation.PassiveDHCP, MAC: copyMAC(b[28:34]),
		Meta: map[string]string{"dhcp": dhcpTypes[typ]}}
	switch ciaddr, yiaddr := addr4(b[12:16]), addr4(b[16:20]); typ {
	case dhcpAck:
		o.IP = yiaddr
	case dhcpRequest, dhcpInform:
		o.IP = ciaddr
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
