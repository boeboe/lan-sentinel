package decoders

import (
	"net"
	"net/netip"
	"strings"

	"lan-sentinel/internal/observation"
)

// NDP message kinds recorded in the "ndp" meta key.
const (
	NDPRouterSolicitation    = "router_solicitation"
	NDPRouterAdvertisement   = "router_advertisement"
	NDPNeighborSolicitation  = "neighbor_solicitation"
	NDPNeighborAdvertisement = "neighbor_advertisement"
	NDPDuplicateDetection    = "dad" // neighbour solicitation from :: (RFC 4862)
)

// NDP option types carrying link-layer addresses.
const (
	ndpOptSourceLL = 1
	ndpOptTargetLL = 2
)

// ndp decodes router and neighbour solicitations and advertisements
// (RFC 4861). Messages that did not arrive with hop limit 255 cannot be
// link-local NDP and are ignored.
func (f *frame) ndp(src netip.Addr, hopLimit uint8, b []byte) {
	if hopLimit != 255 || len(b) < 8 || b[1] != 0 {
		return
	}
	o := observation.Observation{Source: observation.PassiveNDP, MAC: f.src, IP: src}
	var opts []byte
	switch b[0] {
	case 133: // router solicitation
		o.Meta, opts = map[string]string{"ndp": NDPRouterSolicitation}, b[8:]
	case 134: // router advertisement
		if len(b) < 16 {
			return
		}
		o.Meta, opts = map[string]string{"ndp": NDPRouterAdvertisement}, b[16:]
	case 135: // neighbour solicitation
		if len(b) < 24 {
			return
		}
		target := addr16(b[8:24])
		o.Meta, opts = map[string]string{"ndp": NDPNeighborSolicitation}, b[24:]
		if src.IsUnspecified() {
			// Duplicate address detection: the target is tentative, not
			// the sender's yet.
			o.IP, o.Meta = netip.Addr{}, map[string]string{"ndp": NDPDuplicateDetection, "target": target.String()}
		}
	case 136: // neighbour advertisement
		if len(b) < 24 {
			return
		}
		o.IP, opts = addr16(b[8:24]), b[24:]
		o.Meta = map[string]string{"ndp": NDPNeighborAdvertisement}
		if flags := naFlags(b[4]); flags != "" {
			o.Meta["flags"] = flags
		}
	default:
		return
	}
	want := byte(ndpOptSourceLL)
	if b[0] == 136 {
		want = ndpOptTargetLL
	}
	if mac := linkLayerOption(opts, want); mac != nil && o.IP.IsValid() {
		o.MAC = mac
	}
	f.add(o)
}

// naFlags names the router, solicited and override flags.
func naFlags(b byte) string {
	var fl []string
	for _, x := range []struct {
		bit  byte
		name string
	}{{0x80, "router"}, {0x40, "solicited"}, {0x20, "override"}} {
		if b&x.bit != 0 {
			fl = append(fl, x.name)
		}
	}
	return strings.Join(fl, ",")
}

// linkLayerOption returns the Ethernet address in the first option of type
// want, or nil. Options are type, length in units of 8 bytes, data.
func linkLayerOption(b []byte, want byte) net.HardwareAddr {
	for len(b) >= 2 {
		n := int(b[1]) * 8
		if n == 0 || n > len(b) {
			return nil
		}
		if b[0] == want && n >= 8 {
			return copyMAC(b[2:8])
		}
		b = b[n:]
	}
	return nil
}
