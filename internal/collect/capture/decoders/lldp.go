package decoders

import (
	"net"
	"net/netip"
	"strings"

	"lan-sentinel/internal/identify"
	"lan-sentinel/internal/observation"
)

// LLDP TLV types (IEEE 802.1AB).
const (
	lldpEnd         = 0
	lldpChassisID   = 1
	lldpPortID      = 2
	lldpTTL         = 3
	lldpPortDesc    = 4
	lldpSystemName  = 5
	lldpSystemDesc  = 6
	lldpSysCaps     = 7
	lldpMgmtAddress = 8

	// ID subtypes: MAC address and network address (IANA family +
	// address) differ between chassis and port IDs.
	lldpChassisMAC     = 4
	lldpChassisNetwork = 5
	lldpPortMAC        = 3
	lldpPortNetwork    = 4
)

var lldpCapabilityNames = []string{
	"other", "repeater", "bridge", "wlan_ap", "router", "telephone", "docsis", "station", "c_vlan", "s_vlan", "tpmr",
}

// lldp decodes an LLDPDU. The evidence is the chassis MAC when the chassis
// ID is a MAC address, else the frame's source MAC; the system name is the
// host's LLDP name. Port, descriptions, capabilities and the management
// address go into meta: the management address may belong to another
// interface of the device, so it is not attributed. A shutdown LLDPDU (TTL
// 0) is ignored.
func (f *frame) lldp(b []byte) {
	var (
		mac             = f.src
		meta            = map[string]string{}
		haveTTL, haveID bool
		name            string
	)
	for len(b) >= 2 {
		typ, n := b[0]>>1, int(be16(b)&0x1ff)
		if len(b) < 2+n {
			return
		}
		v := b[2 : 2+n]
		b = b[2+n:]
		switch typ {
		case lldpEnd:
			b = nil
		case lldpChassisID:
			if n < 2 {
				return
			}
			haveID = true
			meta["chassis_id"] = lldpID(v[0], v[1:], lldpChassisMAC, lldpChassisNetwork)
			if v[0] == lldpChassisMAC && n == 7 && identify.UnicastMAC(v[1:]) {
				mac = copyMAC(v[1:])
			}
		case lldpPortID:
			if n >= 2 {
				meta["port_id"] = lldpID(v[0], v[1:], lldpPortMAC, lldpPortNetwork)
			}
		case lldpTTL:
			if n < 2 || be16(v) == 0 {
				return
			}
			haveTTL = true
		case lldpPortDesc:
			setText(meta, "port_description", v)
		case lldpSystemName:
			name = hostname(string(v))
		case lldpSystemDesc:
			setText(meta, "system_description", v)
		case lldpSysCaps:
			if n >= 4 {
				if caps := lldpCapabilities(be16(v[2:])); caps != "" {
					meta["capabilities"] = caps
				}
			}
		case lldpMgmtAddress:
			if ip, ok := lldpAddress(v); ok && meta["management_ip"] == "" {
				meta["management_ip"] = ip.String()
			}
		}
	}
	if !haveID || !haveTTL {
		return
	}
	o := observation.Observation{Source: observation.PassiveLLDP, MAC: mac, Meta: meta}
	if name != "" {
		o.Hostname, o.NameType = name, observation.NameLLDP
	}
	f.add(o)
}

// lldpID formats a chassis or port ID: a MAC for the MAC subtype, an
// address for the network-address subtype, else printable text.
func lldpID(subtype byte, v []byte, macSubtype, netSubtype byte) string {
	switch {
	case subtype == macSubtype && len(v) == 6:
		return net.HardwareAddr(v).String()
	case subtype == netSubtype:
		if ip, ok := ianaAddress(v); ok {
			return ip.String()
		}
	}
	return text(v, maxText)
}

// lldpAddress parses a management address TLV: address string length,
// IANA family, address, then interface data that is ignored.
func lldpAddress(v []byte) (netip.Addr, bool) {
	if len(v) < 2 || int(v[0]) < 1 || len(v) < 1+int(v[0]) {
		return netip.Addr{}, false
	}
	return ianaAddress(v[1 : 1+int(v[0])])
}

// ianaAddress parses an IANA address family number followed by the
// address (1 = IPv4, 2 = IPv6).
func ianaAddress(v []byte) (netip.Addr, bool) {
	switch {
	case len(v) == 5 && v[0] == 1:
		return addr4(v[1:]), true
	case len(v) == 17 && v[0] == 2:
		return addr16(v[1:]), true
	}
	return netip.Addr{}, false
}

func lldpCapabilities(enabled uint16) string {
	var names []string
	for i, n := range lldpCapabilityNames {
		if enabled&(1<<i) != 0 {
			names = append(names, n)
		}
	}
	return strings.Join(names, ",")
}

func setText(meta map[string]string, key string, v []byte) {
	if t := text(v, maxText); t != "" {
		meta[key] = t
	}
}
