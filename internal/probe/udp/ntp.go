package udp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// NTP is the NTP client probe (UDP 123, RFC 5905): one mode 3 request with
// a random transmit timestamp, which a server echoes as the originate
// timestamp of its mode 4 reply. Details: version, stratum, leap
// indicator, reference ID, root delay and root dispersion; a kiss-o'-death
// reply (stratum 0) adds its kiss code.
type NTP struct{}

// Name implements Prober.
func (NTP) Name() string { return "ntp" }

// Port implements Prober.
func (NTP) Port() uint16 { return 123 }

const ntpLen = 48

// Request implements Prober.
func (NTP) Request() ([]byte, error) {
	req := make([]byte, ntpLen)
	req[0] = 4<<3 | 3 // LI 0, version 4, mode 3 (client)
	if _, err := rand.Read(req[40:48]); err != nil {
		return nil, fmt.Errorf("ntp request: %w", err)
	}
	return req, nil
}

// Parse implements Prober.
func (NTP) Parse(req, reply []byte) (Response, bool) {
	if len(req) < ntpLen || len(reply) < ntpLen {
		return Response{}, false
	}
	leap, version, mode := reply[0]>>6, reply[0]>>3&7, reply[0]&7
	if mode != 4 || version < 1 || version > 4 || string(reply[24:32]) != string(req[40:48]) {
		return Response{}, false
	}
	stratum := reply[1]
	d := map[string]string{
		"version":            strconv.Itoa(int(version)),
		"stratum":            strconv.Itoa(int(stratum)),
		"leap":               strconv.Itoa(int(leap)),
		"reference_id":       referenceID(stratum, reply[12:16]),
		"root_delay_ms":      shortMS(reply[4:8]),
		"root_dispersion_ms": shortMS(reply[8:12]),
	}
	if stratum == 0 {
		d["kiss_code"] = d["reference_id"]
	}
	return Response{Details: d}, true
}

// referenceID is ASCII for stratum 0 (kiss code) and 1 (reference clock,
// e.g. GPS), else the IPv4 address of the upstream server (for an IPv6
// upstream, the first four bytes of a hash of its address, shown the same
// way).
func referenceID(stratum byte, b []byte) string {
	if stratum <= 1 {
		s := strings.TrimRight(string(b), "\x00")
		for _, r := range s {
			if r < 0x20 || r > 0x7e {
				return fmt.Sprintf("0x%08x", binary.BigEndian.Uint32(b))
			}
		}
		return s
	}
	return netip.AddrFrom4([4]byte(b)).String()
}

// shortMS converts the NTP short format (16.16 seconds) to milliseconds.
func shortMS(b []byte) string {
	v := binary.BigEndian.Uint32(b)
	return strconv.FormatFloat(float64(v)*1000/65536, 'f', 3, 64)
}
