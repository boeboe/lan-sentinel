package config

import "time"

// Compiled default paths (docs/ARCHITECTURE.md §6). LAN Sentinel runs on
// Linux only; other OSes build for development but use the same defaults.
const (
	DefaultConfigPath = "/etc/lan-sentinel/config.yaml"
	DefaultDBPath     = "/data/lan-sentinel/hosts.db"
	DefaultSocketPath = "/run/lan-sentinel/api.sock"
	// maxSocketPath is the longest Unix socket path Linux accepts (sun_path).
	maxSocketPath = 107
)

// Defaults returns the compiled defaults.
func Defaults() *Config {
	return &Config{
		Version: 1,
		Passive: PassiveConfig{Protocols: PassiveProtocols{
			ARP: true, IPv4: true, IPv6: false, DHCP: true, MDNS: true, DNS: true, LLDP: true,
		}},
		Neighbor: NeighborConfig{ResyncInterval: Duration(10 * time.Minute)},
		Active: ActiveConfig{
			StartupDelay:        Duration(30 * time.Second),
			Jitter:              0.1,
			MaxPacketsPerSecond: 20,
			MaxConcurrentProbes: 10,
			MinTargetInterval:   Duration(time.Second),
			Budgets: Budgets{
				ARP:  RateBudget{PacketsPerSecond: 10},
				ICMP: RateBudget{PacketsPerSecond: 5},
				NDP:  RateBudget{PacketsPerSecond: 5},
				UDP:  RateBudget{PacketsPerSecond: 5},
				TCP:  TCPBudget{ConnectsPerSecond: 5, MaxConcurrentPerInterface: 4, MaxConcurrentPerHost: 1},
			},
			MaxAutoScanPrefixV4: 24,
			ARP:                 ProbeConfig{Enabled: true, Interval: Duration(5 * time.Minute)},
			ICMP:                ProbeConfig{Enabled: false, Interval: Duration(10 * time.Minute)},
			TCP:                 TCPProbeConfig{Enabled: false, Interval: Duration(5 * time.Minute)},
		},
		Presence: PresenceConfig{
			Active: Duration(5 * time.Minute),
			Recent: Duration(30 * time.Minute),
			Stale:  Duration(24 * time.Hour),
		},
		Identity: IdentityConfig{
			HostnamePreference: []string{"mdns", "dhcp", "dns_ptr", "lldp"},
			AddressOverlap:     Duration(5 * time.Minute),
			AddressExpiry:      Duration(24 * time.Hour),
			NameExpiry:         Duration(168 * time.Hour),
			ProxyARPThreshold:  16,
		},
		Storage: StorageConfig{
			Path: DefaultDBPath,
			Retention: RetentionConfig{
				Observations: Duration(168 * time.Hour),
				Rollups:      Duration(2160 * time.Hour),
				Events:       Duration(17520 * time.Hour),
				MaxDBSize:    200 * 1000 * 1000,
			},
		},
		API:     APIConfig{Socket: DefaultSocketPath},
		Metrics: MetricsConfig{Enabled: true},
		Logging: LoggingConfig{Level: "info", Format: "journald"},
	}
}
