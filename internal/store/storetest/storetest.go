// Package storetest seeds databases for the read-side tests (store, api,
// cli) from the golden reconstruction scenario.
package storetest

import (
	"context"
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
