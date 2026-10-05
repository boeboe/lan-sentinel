package config

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// minimal is the smallest valid live configuration.
const minimal = "version: 1\ninterfaces:\n  - name: eth0\n"

func mustLoad(t *testing.T, yml string, o LoadOptions) *Loaded {
	t.Helper()
	l, err := load([]byte(yml), "test.yaml", o)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return l
}

func validationErrors(t *testing.T, yml string) []FieldError {
	t.Helper()
	_, err := load([]byte(yml), "test.yaml", LoadOptions{})
	if err == nil {
		return nil
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("load: unexpected error type %T: %v", err, err)
	}
	return ve.Errors
}

func TestDocExamplesLoad(t *testing.T) {
	for _, file := range []string{"testdata/architecture-example.yaml", "testdata/replay-example.yaml"} {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if errs := validationErrors(t, string(data)); len(errs) > 0 {
				t.Errorf("invalid: %v", errs)
			}
		})
	}
}

func TestDefaultsApplied(t *testing.T) {
	l := mustLoad(t, minimal, LoadOptions{})
	c := l.Config
	if c.Storage.Path != DefaultDBPath || c.API.Socket != DefaultSocketPath || c.Logging.Format != "journald" {
		t.Errorf("defaults not applied: %+v %+v %+v", c.Storage, c.API, c.Logging)
	}
	if c.Neighbor.ResyncInterval.D() != 10*time.Minute {
		t.Errorf("resync = %s", c.Neighbor.ResyncInterval)
	}
	if !c.Interfaces[0].PassiveEnabled() || c.Interfaces[0].Active.Enabled {
		t.Error("live interface should default to passive on, active off")
	}
	if c.Active.MaxPacketsPerSecond != 20 || c.Active.Budgets.TCP.MaxConcurrentPerHost != 1 {
		t.Errorf("safety defaults wrong: %+v", c.Active)
	}
}

func TestUnknownKeysReportedWithLines(t *testing.T) {
	yml := minimal + "active:\n  max_packets_per_secnd: 5\n  budgets:\n    tcp: { conects_per_second: 1 }\nbogus: true\n"
	errs := validationErrors(t, yml)
	want := []FieldError{
		{Key: "active.max_packets_per_secnd", Line: 5, Msg: "unknown key"},
		{Key: "active.budgets.tcp.conects_per_second", Line: 7, Msg: "unknown key"},
		{Key: "bogus", Line: 8, Msg: "unknown key"},
	}
	if len(errs) != len(want) {
		t.Fatalf("got %v, want %v", errs, want)
	}
	for i := range want {
		if errs[i] != want[i] {
			t.Errorf("error %d = %+v, want %+v", i, errs[i], want[i])
		}
	}
}

func TestPrecedenceAndSources(t *testing.T) {
	yml := minimal + "storage: { path: /tmp/file.db }\nlogging: { level: debug }\n"
	l := mustLoad(t, yml, LoadOptions{
		Environ: []string{
			"LAN_SENTINEL_LOGGING_LEVEL=warn",
			"LAN_SENTINEL_ACTIVE_MAX_PACKETS_PER_SECOND=18",
			"LAN_SENTINEL_IDENTITY_HOSTNAME_PREFERENCE=dhcp, mdns",
			"LAN_SENTINEL_ACTIVE_DISABLED=1", // reserved, not a key
			"LAN_SENTINEL_CONFIG=/x.yaml",    // reserved, not a key
			"PATH=/bin",
		},
		Flags: []Override{{Key: "storage.path", Value: "/tmp/flag.db", Origin: "--db"}},
	})
	c := l.Config
	tests := []struct {
		key, source string
		ok          bool
	}{
		{"storage.path", "flag --db", c.Storage.Path == "/tmp/flag.db"},
		{"logging.level", "env LAN_SENTINEL_LOGGING_LEVEL", c.Logging.Level == "warn"},
		{"active.max_packets_per_second", "env LAN_SENTINEL_ACTIVE_MAX_PACKETS_PER_SECOND", c.Active.MaxPacketsPerSecond == 18},
		{"identity.hostname_preference", "env LAN_SENTINEL_IDENTITY_HOSTNAME_PREFERENCE", strings.Join(c.Identity.HostnamePreference, ",") == "dhcp,mdns"},
		{"interfaces[0].name", "file test.yaml", c.Interfaces[0].Name == "eth0"},
		{"presence.stale", "default", c.Presence.Stale.D() == 24*time.Hour},
	}
	for _, tt := range tests {
		if !tt.ok {
			t.Errorf("%s: wrong value", tt.key)
		}
		if got := l.SourceOf(tt.key); got != tt.source {
			t.Errorf("%s: source %q, want %q", tt.key, got, tt.source)
		}
	}
}

func TestEnvErrors(t *testing.T) {
	_, err := load([]byte(minimal), "test.yaml", LoadOptions{Environ: []string{
		"LAN_SENTINEL_LOGING_LEVEL=info",
		"LAN_SENTINEL_ACTIVE_JITTER=lots",
	}})
	var ve *ValidationError
	if !errors.As(err, &ve) || len(ve.Errors) != 2 {
		t.Fatalf("want 2 validation errors, got %v", err)
	}
	if ve.Errors[0].Key != "LAN_SENTINEL_LOGING_LEVEL" || !strings.Contains(ve.Errors[1].Msg, "invalid number") {
		t.Errorf("unexpected errors: %v", ve.Errors)
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name    string
		yml     string
		wantKey string // "" means valid
		wantMsg string
	}{
		{"minimal valid", minimal, "", ""},
		{"no interfaces", "version: 1\n", "interfaces", "at least one"},
		{"wrong version", "version: 2\ninterfaces: [{name: eth0}]\n", "version", "must be 1"},
		{"duplicate interface", "version: 1\ninterfaces: [{name: eth0}, {name: eth0}]\n", "interfaces[1].name", "more than once"},
		{"long interface name", "version: 1\ninterfaces: [{name: averyveryverylongname}]\n", "interfaces[0].name", "15 characters"},
		{"active needs networks", minimal + "    active: { enabled: true }\n", "interfaces[0].active.networks", "at least one network"},
		{"wide scan refused", minimal + "    active: { enabled: true, networks: [10.0.0.0/16] }\n", "interfaces[0].active.networks[0]", "wider than /24"},
		{"wide scan allowed", minimal + "    active: { enabled: true, networks: [10.0.0.0/16] }\nactive: { allow_wide_scan: true }\n", "", ""},
		{"ipv6 scan refused", minimal + "    active: { enabled: true, networks: [\"fd00::/120\"] }\n", "interfaces[0].active.networks[0]", "only IPv4"},
		{"host bits", minimal + "    active: { enabled: true, networks: [192.168.1.5/24] }\n", "interfaces[0].active.networks[0]", "host bits"},
		{"exclude ip and cidr", minimal + "    active: { enabled: true, networks: [192.168.1.0/24], exclude: [192.168.1.1, 192.168.1.248/29] }\n", "", ""},
		{"prefixes on live interface", minimal + "    prefixes: [192.168.1.0/24]\n", "interfaces[0].prefixes", "only allowed on replay"},
		{"promisc without passive", minimal + "    passive: { enabled: false, promiscuous: true }\n", "interfaces[0].passive.promiscuous", "requires passive"},
		{"replay needs prefixes", "version: 1\ninterfaces:\n  - name: eth1\n    replay: { file: x.jsonl }\n", "interfaces[0].prefixes", "required"},
		{"replay bad extension", "version: 1\ninterfaces:\n  - name: eth1\n    prefixes: [10.0.0.0/24]\n    replay: { file: x.txt }\n", "interfaces[0].replay.file", "must end in"},
		{"replay exclusive with active", "version: 1\ninterfaces:\n  - name: eth1\n    prefixes: [10.0.0.0/24]\n    replay: { file: x.jsonl }\n    active: { enabled: true, networks: [10.0.0.0/24] }\n", "interfaces[0].active.enabled", "mutually exclusive"},
		{"budget above global", minimal + "active: { budgets: { arp: { packets_per_second: 30 } } }\n", "active.budgets.arp.packets_per_second", "exceeds the global"},
		{"tcp connects above global", minimal + "active: { budgets: { tcp: { connects_per_second: 7 } } }\n", "active.budgets.tcp.connects_per_second", "exceeds the global"},
		{"tcp per host above per interface", minimal + "active: { budgets: { tcp: { max_concurrent_per_host: 5 } } }\n", "active.budgets.tcp.max_concurrent_per_interface", "at least max_concurrent_per_host"},
		{"tcp enabled without targets", minimal + "active: { tcp: { enabled: true } }\n", "active.tcp.targets", "at least one target"},
		{"tcp duplicate port", minimal + "active: { tcp: { targets: [{port: 502, timeout: 1s}, {port: 502, timeout: 1s}] } }\n", "active.tcp.targets[1].port", "more than once"},
		{"jitter too high", minimal + "active: { jitter: 0.9 }\n", "active.jitter", "between 0 and 0.5"},
		{"presence order", minimal + "presence: { active: 1h, recent: 30m }\n", "presence.recent", "longer than presence.active"},
		{"bad name type", minimal + "identity: { hostname_preference: [mdns, wins] }\n", "identity.hostname_preference[1]", "must be one of"},
		{"profile without probes", minimal + "profiles: { empty: {} }\n", "profiles.empty", "enables no probe"},
		{"listen not loopback", minimal + "api: { listen: \"0.0.0.0:9734\" }\n", "api.listen", "loopback"},
		{"listen loopback", minimal + "api: { listen: \"127.0.0.1:9734\" }\n", "", ""},
		{"socket path too long", minimal + "api: { socket: /" + strings.Repeat("x", 110) + " }\n", "api.socket", "limited to 107"},
		{"bad log level", minimal + "logging: { level: verbose }\n", "logging.level", "must be one of"},
		{"db size too small", minimal + "storage: { retention: { max_db_size: 1MB } }\n", "storage.retention.max_db_size", "at least 10MB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validationErrors(t, tt.yml)
			if tt.wantKey == "" {
				if len(errs) > 0 {
					t.Fatalf("unexpected errors: %v", errs)
				}
				return
			}
			for _, fe := range errs {
				if fe.Key == tt.wantKey && strings.Contains(fe.Msg, tt.wantMsg) {
					return
				}
			}
			t.Errorf("want error on %s containing %q, got %v", tt.wantKey, tt.wantMsg, errs)
		})
	}
}

func TestErrorLinesFromFile(t *testing.T) {
	yml := minimal + "presence:\n  active: 1h\n  recent: 30m\n"
	errs := validationErrors(t, yml)
	if len(errs) != 1 || errs[0].Line != 6 {
		t.Fatalf("want one error on line 6, got %v", errs)
	}
}

func TestScalarTypes(t *testing.T) {
	tests := []struct {
		in   string
		want ByteSize
		bad  bool
	}{
		{"200MB", 200_000_000, false},
		{"1GiB", 1 << 30, false},
		{"512", 512, false},
		{"10 KB", 10_000, false},
		{"-1MB", 0, true},
		{"lots", 0, true},
	}
	for _, tt := range tests {
		var b ByteSize
		err := b.parse(tt.in)
		if (err != nil) != tt.bad || (!tt.bad && b != tt.want) {
			t.Errorf("parse(%q) = %d, %v", tt.in, b, err)
		}
	}
	if s := ByteSize(200_000_000).String(); s != "200MB" {
		t.Errorf("String = %q", s)
	}
	for in, want := range map[time.Duration]string{
		5 * time.Minute: "5m", 168 * time.Hour: "168h", 750 * time.Millisecond: "750ms", 90 * time.Second: "90s",
	} {
		if got := Duration(in).String(); got != want {
			t.Errorf("Duration(%v) = %q, want %q", in, got, want)
		}
	}
	var a AddrOrPrefix
	if err := a.UnmarshalText([]byte("192.168.1.1")); err != nil || !a.IsSingleIP() {
		t.Errorf("single IP: %v %v", a, err)
	}
	if b, _ := a.MarshalText(); string(b) != "192.168.1.1" {
		t.Errorf("MarshalText = %s", b)
	}
	if err := a.UnmarshalText([]byte("nope")); err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestSettingsAndSummary(t *testing.T) {
	data, err := os.ReadFile("testdata/architecture-example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	l := mustLoad(t, string(data), LoadOptions{Environ: []string{"LAN_SENTINEL_ACTIVE_JITTER=0.2"}})
	settings, err := l.Settings()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Setting{}
	for _, s := range settings {
		got[s.Key] = s
	}
	checks := []Setting{
		{"active.jitter", "0.2", "env LAN_SENTINEL_ACTIVE_JITTER"},
		{"interfaces[1].active.networks", "[192.168.110.0/24]", "file test.yaml"},
		{"interfaces[1].active.exclude", "[192.168.110.1]", "file test.yaml"},
		{"storage.retention.max_db_size", "200MB", "file test.yaml"},
		{"active.budgets.tcp.max_concurrent_per_host", "1", "file test.yaml"},
		{"profiles.modbus.tcp", "[502]", "file test.yaml"},
	}
	for _, want := range checks {
		if got[want.Key] != want {
			t.Errorf("%s = %+v, want %+v", want.Key, got[want.Key], want)
		}
	}

	s := Summarize(l.Config)
	// arp 10 + tcp 5×3 = 25, capped at the global 20.
	if s.MaxPacketsPerSecond != 20 {
		t.Errorf("MaxPacketsPerSecond = %v, want 20", s.MaxPacketsPerSecond)
	}
	if len(s.Interfaces) != 2 || !s.Interfaces[1].Active || s.Interfaces[0].Active {
		t.Errorf("interfaces = %+v", s.Interfaces)
	}
	if len(s.Probes) != 2 || s.Probes[1] != "tcp 502 (modbus) every 5m" {
		t.Errorf("probes = %v", s.Probes)
	}
}

func TestResolvePath(t *testing.T) {
	tests := []struct {
		explicit string
		env      []string
		want     string
	}{
		{"/a.yaml", []string{"LAN_SENTINEL_CONFIG=/b.yaml"}, "/a.yaml"},
		{"", []string{"LAN_SENTINEL_CONFIG=/b.yaml"}, "/b.yaml"},
		{"", nil, DefaultConfigPath},
	}
	for _, tt := range tests {
		if got := ResolvePath(tt.explicit, tt.env); got != tt.want {
			t.Errorf("ResolvePath(%q, %v) = %q, want %q", tt.explicit, tt.env, got, tt.want)
		}
	}
}

// The reference configs in deploy/ must stay valid.
func TestDeployConfigs(t *testing.T) {
	for _, file := range []string{"../../deploy/config.yaml", "../../deploy/config.dev.yaml"} {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if errs := validationErrors(t, string(data)); len(errs) > 0 {
				t.Errorf("invalid: %v", errs)
			}
		})
	}
}
