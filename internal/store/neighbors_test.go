package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"lan-sentinel/internal/clock"
)

// An interface's LLDP and CDP neighbours: per protocol and MAC the latest
// advertisement, while its TTL (or holdtime) and the capture's refresh
// interval hold; other sources and other interfaces are not neighbours.
func TestNeighbors(t *testing.T) {
	now := t0.Add(day)
	s := open(t, Options{Clock: clock.NewSim(now)})
	seed(t, s, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO network_contexts (id, interface, first_seen, last_seen) VALUES (2, 'eth0', 0, 0)`); err != nil {
			return err
		}
		for _, o := range []struct {
			ago         time.Duration
			ctx         int
			source, mac string
			name, meta  string
		}{
			{5 * time.Minute, 1, "passive_lldp", "00:1e:c9:00:00:01", "plant-sw-01", `{"port_id":"ge-0/0/22","ttl":"120"}`},
			{30 * time.Second, 1, "passive_lldp", "00:1e:c9:00:00:01", "plant-sw-01",
				`{"port_id":"ge-0/0/23","port_description":"box","system_description":"Industrial Ethernet Switch","management_ip":"192.168.110.2","ttl":"120"}`},
			{time.Minute, 1, "passive_cdp", "00:1e:c9:00:00:02", "IE4000-PLANT1", `{"port_id":"GigabitEthernet1/0/12","platform":"cisco IE-4000-8GT4G-E","ttl":"180"}`},
			{6 * time.Minute, 1, "passive_lldp", "00:1e:c9:00:00:03", "old-sw", `{"port_id":"1","ttl":"120"}`},  // expired
			{6 * time.Minute, 1, "passive_lldp", "00:1e:c9:00:00:04", "slow-sw", `{"port_id":"2","ttl":"600"}`}, // a long TTL
			{10 * time.Second, 1, "passive_mdns", "00:1b:1b:00:00:01", "plc", `{}`},
			{10 * time.Second, 2, "passive_lldp", "00:1e:c9:00:00:05", "office-sw", `{"port_id":"7"}`}, // the default TTL
		} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO observations (ts, context_id, source, mac, hostname, meta_json, host_id)
				VALUES (?, ?, ?, ?, ?, ?, 'h1')`, msOf(now.Add(-o.ago)), o.ctx, o.source, o.mac, o.name, o.meta); err != nil {
				return err
			}
		}
		return nil
	})
	r, err := s.Reader(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ifs, err := r.Interfaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, i := range ifs {
		for _, n := range i.Neighbors {
			got[i.Name] = append(got[i.Name], fmt.Sprintf("%s %s %s port=%s desc=%s platform=%s mgmt=%s seen=%s",
				n.Protocol, n.MAC, n.Name, n.Port, n.Description, n.Platform, n.ManagementIP, now.Sub(n.LastSeen)))
		}
	}
	want := map[string][]string{
		"eth1": {
			"cdp 00:1e:c9:00:00:02 IE4000-PLANT1 port=GigabitEthernet1/0/12 desc= platform=cisco IE-4000-8GT4G-E mgmt= seen=1m0s",
			"lldp 00:1e:c9:00:00:01 plant-sw-01 port=ge-0/0/23 desc=Industrial Ethernet Switch platform= mgmt=192.168.110.2 seen=30s",
			"lldp 00:1e:c9:00:00:04 slow-sw port=2 desc= platform= mgmt= seen=6m0s",
		},
		"eth0": {"lldp 00:1e:c9:00:00:05 office-sw port=7 desc= platform= mgmt= seen=10s"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("neighbours:\n%v\nwant\n%v", got, want)
	}
}
