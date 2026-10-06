package golden

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/daemon"
	"lan-sentinel/internal/platform/fake"
	"lan-sentinel/test/fixtures"
)

// The committed pcap fixtures match their scenario descriptions.
func TestFixturesCurrent(t *testing.T) {
	files, err := fixtures.Files()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join("..", "fixtures", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("test/fixtures/%s is stale: run make fixtures", name)
		}
	}
}

// TestCaptureScenario replays the site-a capture through the whole daemon:
// the capture decoders, the correlator and the store. It reconstructs the
// injected IP change and the duplicate IP from frames alone.
func TestCaptureScenario(t *testing.T) {
	dir := t.TempDir()
	pcap, err := filepath.Abs("../fixtures/site-a-eth1.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "hosts.db")
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := "version: 1\ninterfaces:\n  - name: eth1\n    prefixes: [192.168.110.0/24]\n    replay: { file: " + pcap +
		" }\nreplay: { exit_when_done: true }\nstorage: { path: " + db + " }\napi: { socket: ./api.sock }\nlogging: { format: text, level: warn }\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	backends, _, _, _, _ := fake.Backends()
	var log bytes.Buffer
	errc := make(chan error, 1)
	go func() {
		errc <- daemon.Run(context.Background(), daemon.Options{Load: config.LoadOptions{Path: cfgPath}, Stderr: &log,
			Backends: &backends, Signals: make(chan os.Signal)})
	}()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("daemon: %v\n%s", err, log.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("replay did not finish")
	}

	conn, err := sql.Open("sqlite", "file:"+db+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	label := map[string]string{
		fixtures.PLCA.String(): "A", fixtures.PLCB.String(): "B", fixtures.PLCC.String(): "C",
		fixtures.HMI.String(): "HMI", fixtures.Server.String(): "SRV", fixtures.Switch.String(): "SW",
	}
	at := func(ms int64) string { return time.UnixMilli(ms).UTC().Sub(fixtures.SiteA).String() }
	rows := func(q string, scan func(r *sql.Rows) string) []string {
		t.Helper()
		rs, err := conn.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		defer rs.Close()
		var out []string
		for rs.Next() {
			out = append(out, scan(rs))
		}
		return out
	}
	hostOf := `(SELECT mac FROM hosts WHERE host_id = %s)`

	events := rows(`SELECT ts, type, `+fmt.Sprintf(hostOf, "e.host_id")+`, coalesce(`+fmt.Sprintf(hostOf, "e.related_host_id")+`, ''),
		coalesce(old_value, ''), coalesce(new_value, '') FROM events e WHERE host_id IS NOT NULL ORDER BY id`,
		func(r *sql.Rows) string {
			var ts int64
			var typ, mac, related, old, nw string
			if err := r.Scan(&ts, &typ, &mac, &related, &old, &nw); err != nil {
				t.Fatal(err)
			}
			if nw == mac {
				nw = "mac"
			}
			s := fmt.Sprintf("%s %s %s %s>%s", at(ts), typ, label[mac], old, nw)
			if related != "" {
				s += " (" + label[related] + ")"
			}
			return s
		})
	expect(t, "events", events, []string{
		"0s HOST_DISCOVERED A >mac",
		"1s HOSTNAME_ADDED A >mdns:plc-a.local",
		"2s HOST_DISCOVERED SW >mac",
		"2s HOSTNAME_ADDED SW >lldp:plant-sw-01",
		"10m0s HOST_DISCOVERED SRV >mac",
		"10m1s HOST_DISCOVERED HMI >mac",
		"10m1s HOSTNAME_ADDED HMI >dhcp:HMI-LINE3",
		"10m2s IP_ADDED HMI >192.168.110.20",
		"10m3s HOSTNAME_ADDED HMI >dns_ptr:hmi-line3.plant.example",
		"1h0m0s IP_CHANGED A 192.168.110.50>192.168.110.51",
		"2h0m0s HOST_DISCOVERED B >mac",
		"3h0m0s HOST_DISCOVERED C >mac",
		"3h0m0s DUPLICATE_IP_DETECTED C >192.168.110.51 (A)",
		"3h30m0s IP_CHANGED A 192.168.110.51>192.168.110.52",
		"3h30m0s DUPLICATE_IP_RESOLVED C >192.168.110.51 (A)",
	})

	find := func(ip string, d time.Duration) []string {
		t.Helper()
		ms := fixtures.SiteA.Add(d).UnixMilli()
		return rows(fmt.Sprintf(`SELECT h.mac FROM addresses a JOIN hosts h ON h.host_id = a.host_id
			WHERE a.ip = '%s' AND a.first_seen <= %d AND (a.ended_at IS NULL OR a.ended_at > %d) ORDER BY h.mac`, ip, ms, ms),
			func(r *sql.Rows) string {
				var mac string
				_ = r.Scan(&mac)
				return label[mac]
			})
	}
	for _, q := range []struct {
		ip   string
		at   time.Duration
		want string
	}{
		{"192.168.110.50", 30 * time.Minute, "A"},
		{"192.168.110.50", 90 * time.Minute, ""},
		{"192.168.110.50", 150 * time.Minute, "B"},
		{"192.168.110.51", 190 * time.Minute, "A C"},
		{"192.168.110.51", 220 * time.Minute, "C"},
		{"192.168.110.52", 4 * time.Hour, "A"},
	} {
		if got := strings.Join(find(q.ip, q.at), " "); got != q.want {
			t.Errorf("find %s --at T0+%s = %q, want %q", q.ip, q.at, got, q.want)
		}
	}

	names := rows(`SELECT mac, coalesce(preferred_name, '-') FROM hosts ORDER BY mac`, func(r *sql.Rows) string {
		var mac, name string
		_ = r.Scan(&mac, &name)
		return label[mac] + " " + name
	})
	expect(t, "preferred names", names, []string{
		"HMI HMI-LINE3", "SRV -", "A plc-a.local", "B -", "C -", "SW plant-sw-01",
	})
	// IPv6 is off by default, and the repeated echo within the refresh
	// interval was stored once.
	if n := rows(`SELECT count(*) FROM observations WHERE source IN ('passive_ndp', 'passive_ipv6')`, scanString); n[0] != "0" {
		t.Errorf("%s IPv6 observations with ipv6 disabled", n[0])
	}
	if n := rows(`SELECT count(*) FROM observations WHERE source = 'passive_ipv4' AND ip = '192.168.110.20'`, scanString); n[0] != "1" {
		t.Errorf("%s observations of the repeated echo, want 1", n[0])
	}
}

func scanString(r *sql.Rows) string {
	var s string
	_ = r.Scan(&s)
	return s
}

func expect(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s:\ngot:\n  %s\nwant:\n  %s", what, strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}
