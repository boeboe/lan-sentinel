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

// named feeds an observation carrying a hostname at t0+d.
func (h *harness) named(d time.Duration, src observation.Source, mac, ip string, typ observation.NameType, name string) {
	h.t.Helper()
	o := observation.Observation{Time: h.at(d), Source: src, Interface: "eth0", Hostname: name, NameType: typ}
	if mac != "" {
		o.MAC, _ = net.ParseMAC(mac)
	}
	if ip != "" {
		o.IP = netip.MustParseAddr(ip)
	}
	h.sim.Set(o.Time)
	h.c.Handle(h.ctx, observation.Message{Observation: o})
}

// names lists "host type:name [first,ended)" for every name row.
func (h *harness) names() []string {
	return h.query(`SELECT host_id, name_type, name, source, first_seen, coalesce(ended_at, -1) FROM names ORDER BY id`,
		func(r *sql.Rows) string {
			var host, typ, name, src string
			var first, ended int64
			if err := r.Scan(&host, &typ, &name, &src, &first, &ended); err != nil {
				h.t.Fatal(err)
			}
			end := "open"
			if ended >= 0 {
				end = time.UnixMilli(ended).UTC().Sub(t0).String()
			}
			return fmt.Sprintf("%s %s:%s %s [%s,%s)", host, typ, name, src, time.UnixMilli(first).UTC().Sub(t0), end)
		})
}

func (h *harness) preferred() []string {
	return h.query(`SELECT host_id || ' ' || coalesce(preferred_name, '-') FROM hosts ORDER BY host_id`, func(r *sql.Rows) string {
		var s string
		if err := r.Scan(&s); err != nil {
			h.t.Fatal(err)
		}
		return s
	})
}

func TestNames(t *testing.T) {
	h := newHarness(t)
	h.named(0, observation.PassiveDHCP, macA, "", observation.NameDHCP, "plc-a")
	h.named(time.Minute, observation.PassiveDHCP, macA, "", observation.NameDHCP, "plc-a") // confirmation
	h.named(2*time.Minute, observation.PassiveLLDP, macA, "", observation.NameLLDP, "PLC A")
	expect(t, "preferred after dhcp and lldp", h.preferred(), []string{"host-01 plc-a"})
	h.named(3*time.Minute, observation.PassiveMDNS, macA, "10.0.0.5", observation.NameMDNS, "plc-a.local")
	expect(t, "mdns preferred", h.preferred(), []string{"host-01 plc-a.local"})
	h.named(time.Hour, observation.PassiveDHCP, macA, "", observation.NameDHCP, "plc-a2")
	// Late: older than the change to plc-a2; only refreshes, never reopens.
	h.named(30*time.Minute, observation.PassiveDHCP, macA, "", observation.NameDHCP, "plc-a")
	// Invalid name types are ignored.
	h.named(2*time.Hour, observation.PassiveDHCP, macA, "", observation.NameType("wins"), "PLC")

	expect(t, "names", h.names(), []string{
		"host-01 dhcp:plc-a passive_dhcp [0s,1h0m0s)",
		"host-01 lldp:PLC A passive_lldp [2m0s,open)",
		"host-01 mdns:plc-a.local passive_mdns [3m0s,open)",
		"host-01 dhcp:plc-a2 passive_dhcp [1h0m0s,open)",
	})
	expect(t, "events", hostEvents(h.events()), []string{
		"0s HOST_DISCOVERED host-01 >00:1b:1b:00:00:0a",
		"0s HOSTNAME_ADDED host-01 >dhcp:plc-a",
		"2m0s HOSTNAME_ADDED host-01 >lldp:PLC A",
		"3m0s IP_ADDED host-01 >10.0.0.5",
		"3m0s HOSTNAME_ADDED host-01 >mdns:plc-a.local",
		"1h0m0s HOSTNAME_CHANGED host-01 dhcp:plc-a>dhcp:plc-a2",
	})

	// Names survive a restart, including the late-observation guard.
	h.restart()
	h.named(50*time.Minute, observation.PassiveDHCP, macA, "", observation.NameDHCP, "plc-a")
	h.named(2*time.Hour, observation.PassiveMDNS, macA, "10.0.0.5", observation.NameMDNS, "plc-a.local")
	if n := len(h.names()); n != 4 {
		t.Errorf("after restart: %d name rows, want 4", n)
	}
	expect(t, "preferred after restart", h.preferred(), []string{"host-01 plc-a.local"})
}

// Names are last-known attributes: time alone never closes them, whether
// the host stays visible (DHCP and mDNS are often seen only at boot on a
// switched port) or goes MISSING. Only a different name of the same type
// replaces one.
func TestNamesOutliveNameExpiry(t *testing.T) {
	h := newHarness(t)
	week := 168 * time.Hour
	h.named(0, observation.PassiveMDNS, macA, "10.0.0.5", observation.NameMDNS, "plc-a.local")
	h.named(0, observation.PassiveDHCP, macA, "10.0.0.5", observation.NameDHCP, "plc-a")
	h.named(0, observation.PassiveDHCP, macB, "10.0.0.6", observation.NameDHCP, "hmi")
	// A stays visible over ARP for three weeks without naming traffic; B
	// goes silent and becomes MISSING.
	for d := time.Hour; d <= 3*week; d += time.Hour {
		h.obs(d, observation.PassiveARP, "eth0", macA, "10.0.0.5")
	}
	expect(t, "names", h.names(), []string{
		"host-01 mdns:plc-a.local passive_mdns [0s,open)",
		"host-01 dhcp:plc-a passive_dhcp [0s,open)",
		"host-02 dhcp:hmi passive_dhcp [0s,open)",
	})
	expect(t, "preferred names", h.preferred(), []string{"host-01 plc-a.local", "host-02 hmi"})
	for _, e := range h.events() {
		if strings.Contains(e, "HOSTNAME_REMOVED") || strings.Contains(e, "HOSTNAME_CHANGED") {
			t.Errorf("name event without new naming evidence: %s", e)
		}
	}
	if got := h.query(`SELECT presence FROM hosts WHERE host_id = 'host-02'`, scanText); got[0] != "MISSING" {
		t.Fatalf("host-02 presence = %v, want MISSING", got)
	}
	// New naming evidence replaces the name, even weeks later.
	h.named(3*week+time.Hour, observation.PassiveDHCP, macA, "10.0.0.5", observation.NameDHCP, "plc-a-renamed")
	expect(t, "names after a rename", h.names(), []string{
		"host-01 mdns:plc-a.local passive_mdns [0s,open)",
		"host-01 dhcp:plc-a passive_dhcp [0s,505h0m0s)",
		"host-02 dhcp:hmi passive_dhcp [0s,open)",
		"host-01 dhcp:plc-a-renamed passive_dhcp [505h0m0s,open)",
	})
}

// A DNS PTR answer names the host that holds the address, without making
// it present or confirming the binding.
func TestDNSNamesAttachWithoutPresence(t *testing.T) {
	h := newHarness(t)
	h.obs(0, observation.PassiveARP, "eth0", macA, "10.0.0.5")
	h.named(time.Hour, observation.PassiveDNS, "", "10.0.0.5", observation.NameDNSPTR, "plc-a.plant.example")
	h.named(time.Hour, observation.PassiveDNS, "", "10.0.0.99", observation.NameDNSPTR, "nobody.plant.example")
	expect(t, "names", h.names(), []string{"host-01 dns_ptr:plc-a.plant.example passive_dns [1h0m0s,open)"})
	expect(t, "host not refreshed", h.query(`SELECT presence || ' ' || last_seen FROM hosts`, func(r *sql.Rows) string {
		var s string
		_ = r.Scan(&s)
		return s
	}), []string{fmt.Sprintf("STALE %d", t0.UnixMilli())})
	expect(t, "binding not refreshed", h.query(`SELECT last_seen FROM addresses`, func(r *sql.Rows) string {
		var v int64
		_ = r.Scan(&v)
		return fmt.Sprint(v)
	}), []string{fmt.Sprint(t0.UnixMilli())})
	if h.c.Unbound() != 1 {
		t.Errorf("unbound = %d, want 1 (the name for an unknown address)", h.c.Unbound())
	}
}
