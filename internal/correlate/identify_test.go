package correlate

import (
	"database/sql"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/observation"
)

const printer = "b0:0c:d1:b3:95:f4"

// mdnsObs is an mDNS announcement by the printer with the given meta.
func mdnsObs(meta ...string) observation.Observation {
	m, _ := net.ParseMAC(printer)
	o := observation.Observation{Source: observation.PassiveMDNS, MAC: m, IP: netip.MustParseAddr("10.1.0.57"), Meta: map[string]string{}}
	for i := 0; i+1 < len(meta); i += 2 {
		o.Meta[meta[i]] = meta[i+1]
	}
	return o
}

func (h *harness) identEvents() []string {
	var out []string
	for _, e := range h.events() {
		if strings.Contains(e, "VENDOR_IDENTIFIED") {
			out = append(out, e)
		}
	}
	return out
}

func (h *harness) deviceType() string {
	got := h.query(`SELECT coalesce(device_type, '-') FROM hosts WHERE mac = '`+printer+`'`, func(r *sql.Rows) string {
		var s string
		_ = r.Scan(&s)
		return s
	})
	if len(got) == 0 {
		return ""
	}
	return got[0]
}

// A source's value changes only to a more convincing one: a device whose
// announcements differ does not flip, and every claim is still recorded.
func TestPassiveIdentificationIsSticky(t *testing.T) {
	h := newHarness(t)
	h.probeObs(0, mdnsObs("services", "_googlecast._tcp"))                 // Media player 0.6
	h.probeObs(time.Minute, mdnsObs("services", "_ipp._tcp"))              // Printer 0.7: adopted
	h.probeObs(2*time.Minute, mdnsObs("services", "_googlecast._tcp"))     // less convincing: kept as evidence
	h.probeObs(3*time.Minute, mdnsObs("txt", "model=AppleTV11,1"))         // Media player 0.7: as convincing, not adopted
	h.probeObs(4*time.Minute, mdnsObs("services", "_ipp._tcp,_http._tcp")) // the same value: a refresh
	expect(t, "events", h.identEvents(), []string{
		"0s VENDOR_IDENTIFIED host-01 >device_type=Media player",
		"1m0s VENDOR_IDENTIFIED host-01 device_type=Media player>device_type=Printer",
		"3m0s VENDOR_IDENTIFIED host-01 >model=AppleTV11,1",
		"3m0s VENDOR_IDENTIFIED host-01 >os=tvOS",
	})
	if got := h.deviceType(); got != "Printer" {
		t.Errorf("device_type = %s", got)
	}
	// One row per value, with the strongest evidence seen for it; the
	// adopted one is current.
	rows := h.query(`SELECT field || '=' || value || ' ' || source || ' ' || confidence || ' ' || current FROM identifications
		WHERE source = 'mdns' ORDER BY id`, func(r *sql.Rows) string {
		var s string
		_ = r.Scan(&s)
		return s
	})
	expect(t, "identifications", rows, []string{
		"device_type=Media player mdns 0.7 0", "device_type=Printer mdns 0.7 1", "model=AppleTV11,1 mdns 0.7 1", "os=tvOS mdns 0.7 1",
	})
}

// hosts.device_type is the most confident current claim of any source: a
// probe's word beats a passive guess, and a weaker one never displaces it.
func TestDeviceTypeAcrossSources(t *testing.T) {
	h := newHarness(t)
	h.probeObs(0, mdnsObs("services", "_ipp._tcp"))
	if got := h.deviceType(); got != "Printer" {
		t.Fatalf("device_type after mDNS = %s", got)
	}
	enip := enipObs("1756-L71/B LOGIX5571", "Programmable Logic Controller")
	enip.IP = netip.MustParseAddr("10.1.0.57")
	h.probeObs(time.Minute, enip)
	m, _ := net.ParseMAC(printer)
	h.probeObs(2*time.Minute, observation.Observation{Source: observation.PassiveLLDP, MAC: m, Meta: map[string]string{"capabilities": "bridge"}})
	if got := h.deviceType(); got != "Programmable Logic Controller" {
		t.Errorf("device_type = %s, want the probe's", got)
	}

	// After a restart the current claims are the same: nothing more
	// convincing has arrived, so nothing changes or is announced.
	h.restart()
	h.link("eth1", true, "10.1.0.0/24")
	before := len(h.identEvents())
	h.probeObs(3*time.Minute, mdnsObs("services", "_googlecast._tcp"))
	h.probeObs(4*time.Minute, observation.Observation{Source: observation.PassiveLLDP, MAC: m, Meta: map[string]string{"capabilities": "router"}})
	if after := h.identEvents(); len(after) != before {
		t.Errorf("events after the restart: %v", after[before:])
	}
	if got := h.deviceType(); got != "Programmable Logic Controller" {
		t.Errorf("device_type after the restart = %s", got)
	}
}

// Switching an identifier off on reload stops its claims.
func TestIdentifierSwitchedOff(t *testing.T) {
	h := newHarness(t)
	cfg := testConfig()
	cfg.Identity.Identifiers.MDNS = false
	h.c.SetConfig(cfg)
	h.probeObs(0, mdnsObs("services", "_ipp._tcp"))
	if ev := h.identEvents(); len(ev) != 0 {
		t.Errorf("events with mdns off: %v", ev)
	}
	cfg = testConfig()
	h.c.SetConfig(cfg)
	h.probeObs(time.Minute, mdnsObs("services", "_ipp._tcp"))
	if ev := h.identEvents(); fmt.Sprint(ev) != "[1m0s VENDOR_IDENTIFIED host-01 >device_type=Printer]" {
		t.Errorf("events with mdns back on: %v", ev)
	}
}
