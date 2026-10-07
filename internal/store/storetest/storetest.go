// Package storetest seeds databases for the read-side tests (store, api,
// cli) from the golden reconstruction scenario.
package storetest

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/correlate"
	"lan-sentinel/internal/events"
	"lan-sentinel/internal/identify"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/store"
)

// T0 is the golden scenario's start.
var T0 = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

// Expected is the part of the golden scenario (test/golden) the read-side
// tests use.
type Expected struct {
	Hosts   map[string]string `json:"hosts"`
	Queries []struct {
		Find     string    `json:"find"`
		At       time.Time `json:"at"`
		Conflict bool      `json:"conflict"`
		Holders  []struct {
			Host        string     `json:"host"`
			FirstSeen   time.Time  `json:"first_seen"`
			EndedAt     *time.Time `json:"ended_at"`
			Unconfirmed bool       `json:"unconfirmed"`
		} `json:"holders"`
		Previous *struct {
			Host string    `json:"host"`
			At   time.Time `json:"at"`
		} `json:"previous"`
		Next *struct {
			Host string    `json:"host"`
			At   time.Time `json:"at"`
		} `json:"next"`
	} `json:"queries"`
	Events  []struct{ Type, Host string } `json:"events"`
	History []struct {
		IP     string `json:"ip"`
		Events []int  `json:"events"`
	} `json:"history"`
}

// Seed replays the golden scenario in dir (with its tcp/502 result), plus
// an mDNS name for B and an LLDP neighbour on eth0, through the correlator
// into a new database. It returns the open store (closed at the end of the
// test), its path and the expectations.
func Seed(t testing.TB, dir string) (*store.Store, string, Expected) {
	t.Helper()
	var exp Expected
	b, err := os.ReadFile(dir + "expected.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &exp); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dir + "observations.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var obs []observation.Observation
	if err := observation.ReadJSONL(f, func(o observation.Observation) error {
		if o.Interface == "" {
			o.Interface = "eth1"
		}
		obs = append(obs, o)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mac := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
	obs = append(obs,
		observation.Observation{Time: T0.Add(4*time.Hour + time.Minute), Source: observation.PassiveMDNS, Interface: "eth1",
			MAC: mac(exp.Hosts["B"]), IP: netip.MustParseAddr("192.168.110.50"), Hostname: "plc-b.local", NameType: observation.NameMDNS},
		observation.Observation{Time: T0.Add(4*time.Hour + 2*time.Minute), Source: observation.PassiveLLDP, Interface: "eth0",
			MAC: mac("00:1e:c9:00:00:01"), Hostname: "plant-sw-01", NameType: observation.NameLLDP},
	)

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "hosts.db")
	sim := clock.NewSim(obs[0].Time)
	st, err := store.Open(ctx, store.Options{Path: path, Clock: sim})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := config.Defaults()
	cfg.Interfaces = []config.InterfaceConfig{{Name: "eth0"}, {Name: "eth1"}}
	vendors, err := identify.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	c, err := correlate.New(ctx, correlate.Options{Store: st, Events: events.NewEngine(st, log, func() platform.ClockState { return platform.ClockSynced }), Vendors: vendors,
		Clock: sim, Logger: log, Config: cfg, DataDriven: true})
	if err != nil {
		t.Fatal(err)
	}
	c.Handle(ctx, observation.Message{Link: &observation.LinkState{Time: obs[0].Time, Interface: "eth1", Present: true, Up: true,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.110.0/24")}}})
	for _, o := range obs {
		sim.Set(o.Time)
		c.Handle(ctx, observation.Message{Observation: o})
	}
	if err := st.Flush(ctx); err != nil || st.OpErrors() != 0 {
		t.Fatalf("seed: %v, %d op errors", err, st.OpErrors())
	}
	return st, path, exp
}

// AddDHCPServers records two DHCP servers on eth1 in a seeded database: the
// site's, allowed, and a rogue one without a server identifier, unexpected.
func AddDHCPServers(t testing.TB, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	err := st.Submit(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO dhcp_servers (context_id, server_id, relay, mac, ip, status, config_json, first_seen, last_seen)
			SELECT id, '192.168.110.1', '', '00:00:5e:00:01:01', '192.168.110.1', 'allowed',
				'{"router":"192.168.110.1","dns":"192.168.110.1","subnet_mask":"255.255.255.0"}', ?, ? FROM network_contexts WHERE interface = 'eth1'
			UNION ALL
			SELECT id, '', '', '02:00:00:00:00:66', '192.168.110.66', 'unexpected', '{}', ?, ? FROM network_contexts WHERE interface = 'eth1'`,
			T0.UnixMilli(), T0.Add(4*time.Hour).UnixMilli(), T0.Add(2*time.Hour).UnixMilli(), T0.Add(2*time.Hour).UnixMilli())
		return err
	})
	if err == nil {
		err = st.Flush(ctx)
	}
	if err != nil || st.OpErrors() != 0 {
		t.Fatalf("dhcp servers: %v, %d op errors", err, st.OpErrors())
	}
}

// AddIdentifications gives host A (00:1b:1b:aa:bb:01) passive claims: a
// current device type from mDNS, a weaker one it did not adopt, and the
// device type chosen from them.
func AddIdentifications(t testing.TB, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	err := st.Submit(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO identifications (host_id, field, value, confidence, source, evidence_json, first_seen, last_seen, current)
			SELECT host_id, 'device_type', 'Printer', 0.7, 'mdns', '{"service":"_ipp._tcp"}', ?, ?, 1 FROM hosts WHERE mac = '00:1b:1b:aa:bb:01'
			UNION ALL
			SELECT host_id, 'device_type', 'Media player', 0.6, 'mdns', '{"service":"_googlecast._tcp"}', ?, ?, 0 FROM hosts WHERE mac = '00:1b:1b:aa:bb:01'`,
			T0.UnixMilli(), T0.UnixMilli(), T0.UnixMilli(), T0.UnixMilli()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE hosts SET device_type = 'Printer' WHERE mac = '00:1b:1b:aa:bb:01'`)
		return err
	})
	if err == nil {
		err = st.Flush(ctx)
	}
	if err != nil || st.OpErrors() != 0 {
		t.Fatalf("identifications: %v, %d op errors", err, st.OpErrors())
	}
}
