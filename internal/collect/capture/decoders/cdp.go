package decoders

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"

	"lan-sentinel/internal/observation"
)

// CDP (Cisco Discovery Protocol) TLV types.
const (
	cdpDeviceID    = 0x0001
	cdpAddresses   = 0x0002
	cdpPortID      = 0x0003
	cdpCaps        = 0x0004
	cdpSoftware    = 0x0005
	cdpPlatform    = 0x0006
	cdpMgmtAddress = 0x0016

	cdpHeader = 4 // version, holdtime, checksum
	cdpTLV    = 4 // type, length (the length counts these 4 bytes)
)

// llcSNAPCDP is the LLC/SNAP header of a CDP frame: SNAP SAPs, UI, the
// Cisco OUI and protocol 0x2000.
var llcSNAPCDP = []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00}

var cdpCapabilityNames = []string{
	"router", "bridge", "source_route_bridge", "switch", "host", "igmp", "repeater", "phone", "remote", "cvta", "mac_relay",
}

// cdp decodes a CDP advertisement: an 802.3 LLC/SNAP frame that Cisco and
// Rockwell Stratix switches, routers and phones send to the directly
// attached neighbour. The evidence is the frame's source MAC; the device ID
// is its name, a link-layer discovery name like LLDP's system name
// (docs/DATA_MODEL.md §5.4). Platform, the first line of the software
// version, port, capabilities, holdtime and the management address go into
// meta: the management address may belong to another interface of the
// device, so it is not attributed. A holdtime of 0 is ignored.
func (f *frame) cdp(b []byte) {
	if len(b) < len(llcSNAPCDP)+cdpHeader || !bytes.Equal(b[:len(llcSNAPCDP)], llcSNAPCDP) {
		return
	}
	b = b[len(llcSNAPCDP):]
	if version, holdtime := b[0], b[1]; version < 1 || version > 2 || holdtime == 0 {
		return
	}
	meta := map[string]string{"ttl": strconv.Itoa(int(b[1]))}
	var name string
	for b = b[cdpHeader:]; len(b) >= cdpTLV; {
		typ, n := be16(b), int(be16(b[2:]))
		if n < cdpTLV || n > len(b) {
			return
		}
		v := b[cdpTLV:n]
		b = b[n:]
		switch typ {
		case cdpDeviceID:
			name = hostname(string(v))
		case cdpPortID:
			setText(meta, "port_id", v)
		case cdpCaps:
			if len(v) == 4 {
				if caps := cdpCapabilities(binary.BigEndian.Uint32(v)); caps != "" {
					meta["capabilities"] = caps
				}
			}
		case cdpSoftware:
			line, _, _ := bytes.Cut(v, []byte{'\n'})
			setText(meta, "software", line)
		case cdpPlatform:
			setText(meta, "platform", v)
		case cdpAddresses, cdpMgmtAddress:
			// The management address TLV wins over the interface addresses.
			if ip, ok := cdpAddress(v); ok && (typ == cdpMgmtAddress || meta["management_ip"] == "") {
				meta["management_ip"] = ip.String()
			}
		}
	}
	if name == "" {
		return
	}
	f.add(observation.Observation{Source: observation.PassiveCDP, MAC: f.src, Hostname: name, NameType: observation.NameLLDP, Meta: meta})
}

// cdpAddress returns the first IPv4 or IPv6 address of an address TLV: a
// count, then per address a protocol type, protocol length, protocol (NLPID
// 0xcc for IPv4, an 802.2 header ending in 0x86dd for IPv6), address length
// and address.
func cdpAddress(v []byte) (netip.Addr, bool) {
	if len(v) < 4 {
		return netip.Addr{}, false
	}
	count := binary.BigEndian.Uint32(v)
	v = v[4:]
	for i := uint32(0); i < count && len(v) >= 2; i++ {
		plen := int(v[1])
		if len(v) < 2+plen+2 {
			break
		}
		proto, alen := v[2:2+plen], int(be16(v[2+plen:]))
		v = v[4+plen:]
		if len(v) < alen {
			break
		}
		addr := v[:alen]
		v = v[alen:]
		switch {
		case plen == 1 && proto[0] == 0xcc && alen == 4:
			return addr4(addr), true
		case plen == 8 && be16(proto[6:]) == EtherTypeIPv6 && alen == 16:
			return addr16(addr), true
		}
	}
	return netip.Addr{}, false
}

func cdpCapabilities(bits uint32) string {
	var out []string
	for i, n := range cdpCapabilityNames {
		if bits&(1<<i) != 0 {
			out = append(out, n)
		}
	}
	return strings.Join(out, ",")
}
