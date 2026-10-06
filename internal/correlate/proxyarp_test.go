package correlate

import (
	"database/sql"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"lan-sentinel/internal/observation"
)

const macR = "00:00:5e:00:01:01" // a router

// arp feeds a passive ARP observation of the given kind ("reply",
// "request", "gratuitous") at t0+d on eth0.
func (h *harness) arp(d time.Duration, kind, mac, ip string) {
	h.t.Helper()
	m, _ := net.ParseMAC(mac)
	o := observation.Observation{Time: h.at(d), Source: observation.PassiveARP, Interface: "eth0", MAC: m,
		IP: netip.MustParseAddr(ip), Meta: map[string]string{"arp": kind}}
	h.sim.Set(o.Time)
	h.c.Handle(h.ctx, observation.Message{Observation: o})
}

func (h *harness) identifications() []string {
	return h.query(`SELECT host_id || ' ' || field || '=' || value || ' ' || source || ' ' || json_extract(evidence_json, '$.reason')
		FROM identifications WHERE field != 'manufacturer' ORDER BY id`, func(r *sql.Rows) string {
		var s string
		if err := r.Scan(&s); err != nil {
			h.t.Fatal(err)
		}
		return s
	})
}

// One contested reply is a duplicate IP; a second contested address makes
// the replier a proxy, whose answers then bind nothing.
func TestProxyARPByOverlaps(t *testing.T) {
	h := newHarness(t)
	h.arp(0, "request", macA, "10.0.0.5")                // host-01
	h.arp(0, "request", macB, "10.0.0.6")                // host-02
	h.arp(0, "request", macR, "10.0.0.1")                // host-03, its own address
	h.arp(time.Minute, "reply", macR, "10.0.0.5")        // duplicate IP with A
	h.arp(2*time.Minute, "reply", macR, "10.0.0.6")      // second overlap: proxy
	h.arp(3*time.Minute, "reply", macR, "10.0.0.6")      // ignored now
	h.arp(4*time.Minute, "reply", macR, "10.0.0.77")     // ignored: not its address
	h.arp(5*time.Minute, "reply", macR, "10.0.0.1")      // its own address: refreshed
	h.arp(6*time.Minute, "gratuitous", macC, "10.0.0.6") // still a duplicate IP

	expect(t, "events", hostEvents(h.events()), []string{
		"0s HOST_DISCOVERED host-01 >00:1b:1b:00:00:0a",
		"0s HOST_DISCOVERED host-02 >00:1b:1b:00:00:0b",
		"0s HOST_DISCOVERED host-03 >00:00:5e:00:01:01",
		"1m0s IP_ADDED host-03 >10.0.0.5",
		"1m0s DUPLICATE_IP_DETECTED host-03 >10.0.0.5",
		"2m0s VENDOR_IDENTIFIED host-03 >proxy_arp=true",
		"2m0s IP_REMOVED host-03 10.0.0.5>",
		"2m0s DUPLICATE_IP_RESOLVED host-01 >10.0.0.5",
		"6m0s HOST_DISCOVERED host-04 >00:1b:1b:00:00:0c",
		"6m0s DUPLICATE_IP_DETECTED host-04 >10.0.0.6",
	})
	expect(t, "bindings", h.bindings(), []string{
		"host-01 10.0.0.5 [0s,open) c=0",
		"host-02 10.0.0.6 [0s,open) c=1",
		"host-03 10.0.0.1 [0s,open) c=0",
		"host-03 10.0.0.5 [1m0s,2m0s) c=1", // closed while in conflict
		"host-04 10.0.0.6 [6m0s,open) c=1",
	})
	expect(t, "identifications", h.identifications(), []string{
		"host-03 proxy_arp=true passive_arp answered ARP for 2 addresses, 2 of them held by other live hosts",
	})
	if got := h.query(`SELECT last_seen FROM addresses WHERE host_id = 'host-03' AND ip = '10.0.0.1'`, scanText); got[0] != fmt.Sprint(ms(h.at(5*time.Minute))) {
		t.Errorf("own address last_seen = %s, want the 5m reply", got[0])
	}

	// The flag survives a restart.
	h.restart()
	h.arp(10*time.Minute, "reply", macR, "10.0.0.88")
	if n := len(h.bindings()); n != 5 {
		t.Errorf("after restart a proxy reply opened a binding: %v", h.bindings())
	}
}

func TestProxyARPByThreshold(t *testing.T) {
	h := newHarness(t)
	cfg := testConfig()
	cfg.Identity.ProxyARPThreshold = 3
	h.c.SetConfig(cfg)
	h.arp(0, "request", macR, "10.0.0.1")
	for i, ip := range []string{"10.0.0.20", "10.0.0.21", "10.0.0.22"} {
		h.arp(time.Duration(i+1)*time.Second, "reply", macR, ip)
	}
	if n := len(h.bindings()); n != 4 {
		t.Fatalf("below the threshold: %d bindings, want 4", n)
	}
	h.arp(10*time.Second, "reply", macR, "10.0.0.23") // 5th address > 3: proxy
	expect(t, "bindings", h.bindings(), []string{
		"host-01 10.0.0.1 [0s,open) c=0",
		"host-01 10.0.0.20 [1s,10s) c=0",
		"host-01 10.0.0.21 [2s,10s) c=0",
		"host-01 10.0.0.22 [3s,10s) c=0",
	})
	expect(t, "identifications", h.identifications(), []string{
		"host-01 proxy_arp=true passive_arp answered ARP for 4 addresses, 0 of them held by other live hosts",
	})
}

// Gratuitous ARP is never proxy behaviour, however many addresses clash.
func TestGratuitousARPIsNotProxy(t *testing.T) {
	h := newHarness(t)
	h.arp(0, "request", macA, "10.0.0.5")
	h.arp(0, "request", macB, "10.0.0.6")
	h.arp(time.Minute, "gratuitous", macC, "10.0.0.5")
	h.arp(2*time.Minute, "gratuitous", macC, "10.0.0.6")
	if got := h.identifications(); len(got) != 0 {
		t.Errorf("identifications = %v", got)
	}
	if n := len(h.query(`SELECT id FROM events WHERE type = 'DUPLICATE_IP_DETECTED'`, scanText)); n != 2 {
		t.Errorf("%d duplicate-IP events, want 2", n)
	}
}

func scanText(r *sql.Rows) string {
	var v string
	_ = r.Scan(&v)
	return v
}

// Claims count only within identity.address_expiry: a device that answers
// for a new address now and then (DHCP leases over months) is not a proxy.
func TestProxyARPClaimsAge(t *testing.T) {
	h := newHarness(t)
	cfg := testConfig()
	cfg.Identity.ProxyARPThreshold = 3
	h.c.SetConfig(cfg)
	for i, ip := range []string{"10.0.0.20", "10.0.0.21", "10.0.0.22", "10.0.0.23", "10.0.0.24"} {
		h.arp(time.Duration(i)*25*time.Hour, "reply", macR, ip)
	}
	if got := h.identifications(); len(got) != 0 {
		t.Errorf("flagged after addresses spread over days: %v", got)
	}
}

// A late reply is counted but never flags: the bindings the flag closes
// must have started before the observation that closes them.
func TestProxyARPLateReplyDoesNotFlag(t *testing.T) {
	h := newHarness(t)
	cfg := testConfig()
	cfg.Identity.ProxyARPThreshold = 2
	h.c.SetConfig(cfg)
	h.arp(10*time.Minute, "reply", macR, "10.0.0.20")
	h.arp(11*time.Minute, "reply", macR, "10.0.0.21")
	h.arp(5*time.Minute, "reply", macR, "10.0.0.22") // late: older than the last binding change
	if got := h.identifications(); len(got) != 0 {
		t.Fatalf("late reply flagged: %v", got)
	}
	h.arp(12*time.Minute, "reply", macR, "10.0.0.20") // timely; the counts already exceed 2
	expect(t, "identifications", h.identifications(), []string{
		"host-01 proxy_arp=true passive_arp answered ARP for 3 addresses, 0 of them held by other live hosts",
	})
	expect(t, "bindings", h.bindings(), []string{
		"host-01 10.0.0.20 [10m0s,12m0s) c=0",
		"host-01 10.0.0.21 [11m0s,12m0s) c=0",
	})
}
