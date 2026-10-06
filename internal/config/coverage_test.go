package config

import (
	"errors"
	"strings"
	"testing"
)

// Every scalar type can be set from the environment and from flags, and a
// bad value is reported against the key.
func TestEnvAndFlagTypes(t *testing.T) {
	l := mustLoad(t, minimal, LoadOptions{
		Environ: []string{
			"LAN_SENTINEL_PRESENCE_ACTIVE=2m",
			"LAN_SENTINEL_STORAGE_RETENTION_MAX_DB_SIZE=1GiB",
			"LAN_SENTINEL_METRICS_ENABLED=false",
			"LAN_SENTINEL_ACTIVE_MAX_CONCURRENT_PROBES=4",
			"LAN_SENTINEL_API_LISTEN=127.0.0.1:9734",
		},
		Flags: []Override{{Key: "logging.level", Value: "debug", Origin: "--log-level"}},
	})
	c := l.Config
	if c.Presence.Active.String() != "2m" || c.Storage.Retention.MaxDBSize != 1<<30 || c.Metrics.Enabled ||
		c.Active.MaxConcurrentProbes != 4 || c.API.Listen != "127.0.0.1:9734" || c.Logging.Level != "debug" {
		t.Errorf("values not applied: %+v %+v %+v", c.Presence, c.Storage, c.Active)
	}

	tests := []struct {
		env, flag, wantKey, wantMsg string
	}{
		{env: "LAN_SENTINEL_PRESENCE_ACTIVE=soon", wantKey: "presence.active", wantMsg: "invalid duration"},
		{env: "LAN_SENTINEL_STORAGE_RETENTION_MAX_DB_SIZE=lots", wantKey: "storage.retention.max_db_size", wantMsg: "invalid size"},
		{env: "LAN_SENTINEL_METRICS_ENABLED=maybe", wantKey: "metrics.enabled", wantMsg: "invalid boolean"},
		{env: "LAN_SENTINEL_ACTIVE_MAX_CONCURRENT_PROBES=many", wantKey: "active.max_concurrent_probes", wantMsg: "invalid integer"},
		{flag: "nope.key", wantKey: "nope.key", wantMsg: "not a settable key"},
		{flag: "presence.stale", wantKey: "presence.stale", wantMsg: "--test: invalid duration"},
	}
	for _, tt := range tests {
		o := LoadOptions{}
		if tt.env != "" {
			o.Environ = []string{tt.env}
		}
		if tt.flag != "" {
			o.Flags = []Override{{Key: tt.flag, Value: "x", Origin: "--test"}}
		}
		_, err := load([]byte(minimal), "test.yaml", o)
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("%v: err = %v", tt, err)
		}
		found := false
		for _, fe := range ve.Errors {
			found = found || (fe.Key == tt.wantKey && strings.Contains(fe.Msg, tt.wantMsg))
		}
		if !found {
			t.Errorf("%+v: errors %v", tt, ve.Errors)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(LoadOptions{Path: "/does/not/exist.yaml"}); err == nil {
		t.Error("missing file accepted")
	}
	for _, in := range []string{"version: [", "- a\n- b\n", "version: 1\npresence: { active: [1] }\n", "interfaces: notalist\n"} {
		if _, err := load([]byte(in), "test.yaml", LoadOptions{}); err == nil {
			t.Errorf("load(%q) accepted", in)
		}
	}
	if l, err := load(nil, "empty.yaml", LoadOptions{}); err == nil || l == nil {
		t.Errorf("empty file: want a validation error with the defaults loaded, got %v", err)
	}
}

// One case per validation rule not covered by TestValidation.
func TestValidationRules(t *testing.T) {
	iface := "version: 1\ninterfaces:\n  - name: eth0\n"
	replay := "version: 1\ninterfaces:\n  - name: eth1\n    prefixes: [10.0.0.0/24]\n"
	tests := []struct {
		name, yml, key, msg string
	}{
		{"resync too short", iface + "neighbor: { resync_interval: 10ms }\n", "neighbor.resync_interval", "at least 1s"},
		{"prefix host bits", "version: 1\ninterfaces:\n  - name: eth1\n    prefixes: [10.0.0.5/24]\n    replay: { file: x.jsonl }\n", "interfaces[0].prefixes[0]", "host bits"},
		{"replay without file", replay + "    replay: { speed: 1 }\n", "interfaces[0].replay.file", "is required"},
		{"replay negative speed", replay + "    replay: { file: x.jsonl, speed: -1 }\n", "interfaces[0].replay.speed", "positive factor"},
		{"replay with passive", replay + "    replay: { file: x.jsonl }\n    passive: { enabled: true }\n", "interfaces[0].passive.enabled", "mutually exclusive"},
		{"exclude host bits", iface + "    active: { enabled: true, networks: [10.0.0.0/24], exclude: [10.0.0.5/28] }\n", "interfaces[0].active.exclude[0]", "host bits"},
		{"negative startup delay", iface + "active: { startup_delay: -1s }\n", "active.startup_delay", "not be negative"},
		{"zero packet budget", iface + "active: { max_packets_per_second: 0 }\n", "active.max_packets_per_second", "greater than zero"},
		{"zero concurrency", iface + "active: { max_concurrent_probes: 0 }\n", "active.max_concurrent_probes", "at least 1"},
		{"negative target interval", iface + "active: { min_target_interval: -1s }\n", "active.min_target_interval", "not be negative"},
		{"scan prefix guard range", iface + "active: { max_auto_scan_prefix_v4: 4 }\n", "active.max_auto_scan_prefix_v4", "between 8 and 32"},
		{"zero protocol budget", iface + "active: { budgets: { icmp: { packets_per_second: 0 } } }\n", "active.budgets.icmp.packets_per_second", "greater than zero"},
		{"zero tcp connects", iface + "active: { budgets: { tcp: { connects_per_second: 0 } } }\n", "active.budgets.tcp.connects_per_second", "greater than zero"},
		{"zero tcp per host", iface + "active: { budgets: { tcp: { max_concurrent_per_host: 0 } } }\n", "active.budgets.tcp.max_concurrent_per_host", "at least 1"},
		{"tcp per interface above total", iface + "active: { max_concurrent_probes: 2, budgets: { tcp: { max_concurrent_per_interface: 3 } } }\n", "active.budgets.tcp.max_concurrent_per_interface", "must not exceed"},
		{"tcp bad port", iface + "active: { tcp: { targets: [{port: 70000, timeout: 1s}] } }\n", "active.tcp.targets[0].port", "between 1 and 65535"},
		{"tcp zero timeout", iface + "active: { tcp: { targets: [{port: 502}] } }\n", "active.tcp.targets[0].timeout", "greater than zero"},
		{"zero probe interval", iface + "active: { arp: { interval: 0s } }\n", "active.arp.interval", "at least 10s"},
		{"udp unknown probe", iface + "active: { udp: { probes: [snmp] } }\n", "active.udp.probes[0]", "must be one of"},
		{"dhcp server not unicast", iface + "    dhcp: { servers: [192.168.0.1, 255.255.255.255] }\n", "interfaces[0].dhcp.servers[1]", "not a unicast IPv4 address"},
		{"dhcp server ipv6", iface + "    dhcp: { servers: [fe80::1] }\n", "interfaces[0].dhcp.servers[0]", "not a unicast IPv4 address"},
		{"udp duplicate probe", iface + "active: { udp: { probes: [ntp, ntp] } }\n", "active.udp.probes[1]", "more than once"},
		{"udp enabled without probes", iface + "active: { udp: { enabled: true, probes: [] } }\n", "active.udp.probes", "at least one probe"},
		{"profile udp", iface + "profiles: { x: { udp: [modbus] } }\n", "profiles.x.udp[0]", "must be one of"},
		{"bad profile name", iface + "profiles: { Modbus: { arp: true } }\n", "profiles.Modbus", "lowercase"},
		{"bad profile port", iface + "profiles: { m: { tcp: [0] } }\n", "profiles.m.tcp[0]", "between 1 and 65535"},
		{"presence stale order", iface + "presence: { recent: 30m, stale: 10m }\n", "presence.stale", "longer than presence.recent"},
		{"duplicate name type", iface + "identity: { hostname_preference: [mdns, mdns] }\n", "identity.hostname_preference[1]", "more than once"},
		{"overlap above expiry", iface + "identity: { address_overlap: 48h }\n", "identity.address_overlap", "shorter than"},
		{"proxy threshold", iface + "identity: { proxy_arp_threshold: 1 }\n", "identity.proxy_arp_threshold", "at least 2"},
		{"empty storage path", iface + "storage: { path: \"\" }\n", "storage.path", "is required"},
		{"zero retention", iface + "storage: { retention: { events: 0s } }\n", "storage.retention.events", "greater than zero"},
		{"empty socket", iface + "api: { socket: \"\" }\n", "api.socket", "is required"},
		{"listen without port", iface + "api: { listen: \"127.0.0.1\" }\n", "api.listen", "host:port"},
		{"listen bad port", iface + "api: { listen: \"127.0.0.1:99999\" }\n", "api.listen", "invalid port"},
		{"bad log format", iface + "logging: { format: xml }\n", "logging.format", "must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, fe := range validationErrors(t, tt.yml) {
				if fe.Key == tt.key && strings.Contains(fe.Msg, tt.msg) {
					return
				}
			}
			t.Errorf("want %s: %q; got %v", tt.key, tt.msg, validationErrors(t, tt.yml))
		})
	}
}

func TestScalarYAMLAndText(t *testing.T) {
	for _, in := range []string{"presence: { active: [1] }", "storage: { retention: { max_db_size: { a: 1 } } }"} {
		if _, err := load([]byte(minimal+in+"\n"), "t.yaml", LoadOptions{}); err == nil {
			t.Errorf("non-scalar accepted: %s", in)
		}
	}
	if b, _ := Duration(0).MarshalText(); string(b) != "0s" {
		t.Errorf("Duration text = %s", b)
	}
	if b, _ := ByteSize(1500).MarshalText(); string(b) != "1500B" {
		t.Errorf("ByteSize text = %s", b)
	}
	var a AddrOrPrefix
	if err := a.UnmarshalText([]byte("10.0.0.0/33")); err == nil {
		t.Error("invalid CIDR accepted")
	}
}

func TestSummaryICMPAndEmptyProfile(t *testing.T) {
	l := mustLoad(t, minimal+"    active: { enabled: true, networks: [10.0.0.0/24] }\nactive: { icmp: { enabled: true }, udp: { enabled: true } }\nprofiles: {}\n", LoadOptions{})
	s := Summarize(l.Config)
	if len(s.Probes) != 3 || !strings.HasPrefix(s.Probes[1], "icmp every") || s.Probes[2] != "udp ntp, enip every 15m" || s.MaxPacketsPerSecond != 20 {
		t.Errorf("summary = %+v", s)
	}
	settings, err := l.Settings()
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range settings {
		if st.Key == "profiles" && st.Value != "{}" {
			t.Errorf("empty profiles = %q", st.Value)
		}
	}
}
