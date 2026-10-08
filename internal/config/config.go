// Package config defines the LAN Sentinel configuration schema and loads it
// from compiled defaults, the YAML file, LAN_SENTINEL_* environment variables
// and command-line flags, in that order of increasing precedence, with strict
// validation. See docs/ARCHITECTURE.md §6.
package config

import (
	"net/netip"
	"slices"
)

// Config is the complete configuration.
type Config struct {
	Version    int                      `yaml:"version" json:"version"`
	Interfaces []InterfaceConfig        `yaml:"interfaces" json:"interfaces"`
	Passive    PassiveConfig            `yaml:"passive" json:"passive"`
	Neighbor   NeighborConfig           `yaml:"neighbor" json:"neighbor"`
	Active     ActiveConfig             `yaml:"active" json:"active"`
	Profiles   map[string]ProfileConfig `yaml:"profiles" json:"profiles"`
	Presence   PresenceConfig           `yaml:"presence" json:"presence"`
	Identity   IdentityConfig           `yaml:"identity" json:"identity"`
	Storage    StorageConfig            `yaml:"storage" json:"storage"`
	API        APIConfig                `yaml:"api" json:"api"`
	Metrics    MetricsConfig            `yaml:"metrics" json:"metrics"`
	Logging    LoggingConfig            `yaml:"logging" json:"logging"`
	Replay     ReplayConfig             `yaml:"replay" json:"replay"`
}

// InterfaceConfig configures one monitored interface (one network context).
type InterfaceConfig struct {
	Name    string           `yaml:"name" json:"name"`
	Passive InterfacePassive `yaml:"passive" json:"passive"`
	Active  InterfaceActive  `yaml:"active" json:"active"`
	DHCP    InterfaceDHCP    `yaml:"dhcp" json:"dhcp"`
	// Prefixes and Replay are only used for replay interfaces, whose subnets
	// cannot come from the interface manager.
	Prefixes []netip.Prefix   `yaml:"prefixes,omitempty" json:"prefixes,omitempty"`
	Replay   *InterfaceReplay `yaml:"replay,omitempty" json:"replay,omitempty"`
}

// IsReplay reports whether the interface is fed from a replay file.
func (i InterfaceConfig) IsReplay() bool { return i.Replay != nil }

// ReplayMode reports whether the daemon replays recorded files (every
// interface is a replay interface; validation forbids mixing).
func (c *Config) ReplayMode() bool {
	return len(c.Interfaces) > 0 && c.Interfaces[0].IsReplay()
}

// PassiveEnabled reports whether passive capture is enabled. It defaults to
// true for live interfaces and false for replay interfaces.
func (i InterfaceConfig) PassiveEnabled() bool {
	if i.Passive.Enabled == nil {
		return !i.IsReplay()
	}
	return *i.Passive.Enabled
}

// InterfacePassive configures passive capture on one interface.
type InterfacePassive struct {
	Enabled     *bool `yaml:"enabled" json:"enabled"`
	Promiscuous bool  `yaml:"promiscuous" json:"promiscuous"`
}

// InterfaceActive configures active discovery on one interface.
type InterfaceActive struct {
	Enabled  bool           `yaml:"enabled" json:"enabled"`
	Networks []netip.Prefix `yaml:"networks,omitempty" json:"networks,omitempty"`
	Exclude  []AddrOrPrefix `yaml:"exclude,omitempty" json:"exclude,omitempty"`
	// Identify is the opt-in identification probes on this interface
	// (ADR 0011). Object form only; a string list is invalid. Empty
	// (the default) sends nothing.
	Identify []InterfaceIdentify `yaml:"identify,omitempty" json:"identify,omitempty"`
}

// InterfaceIdentify is one named identification probe on an interface.
// Omitted options use active.identify.probes.
type InterfaceIdentify struct {
	Name      string `yaml:"name" json:"name"`
	UnitID    *int   `yaml:"unit_id,omitempty" json:"unit_id,omitempty"`
	Community string `yaml:"community,omitempty" json:"community,omitempty"`
}

// InterfaceDHCP configures DHCP server monitoring on one interface
// (docs/DATA_MODEL.md §5.6).
type InterfaceDHCP struct {
	// Servers lists the DHCP server identifiers (option 54) allowed on the
	// interface; a reply from any other, or without a valid identifier, is
	// unexpected. Unset: no allowlist, servers are reported without a
	// verdict. Empty: no DHCP server is expected.
	Servers *[]netip.Addr `yaml:"servers,omitempty" json:"servers,omitempty"`
}

// Checked reports whether the interface has an allowlist.
func (d InterfaceDHCP) Checked() bool { return d.Servers != nil }

// Allowed reports whether a server identifier is on the allowlist; an
// invalid (unknown) identifier never is.
func (d InterfaceDHCP) Allowed(serverID netip.Addr) bool {
	return d.Servers != nil && serverID.IsValid() && slices.Contains(*d.Servers, serverID)
}

// InterfaceReplay feeds an interface from a recorded file.
type InterfaceReplay struct {
	File  string  `yaml:"file" json:"file"`
	Speed float64 `yaml:"speed" json:"speed"`
}

// PassiveConfig holds global passive-capture settings.
type PassiveConfig struct {
	Protocols PassiveProtocols `yaml:"protocols" json:"protocols"`
	// RingSize is the AF_PACKET ring buffer per captured interface.
	RingSize ByteSize `yaml:"ring_size" json:"ring_size"`
}

// PassiveProtocols enables individual decoders.
type PassiveProtocols struct {
	ARP  bool `yaml:"arp" json:"arp"`
	IPv4 bool `yaml:"ipv4" json:"ipv4"`
	IPv6 bool `yaml:"ipv6" json:"ipv6"`
	DHCP bool `yaml:"dhcp" json:"dhcp"`
	MDNS bool `yaml:"mdns" json:"mdns"`
	DNS  bool `yaml:"dns" json:"dns"`
	LLDP bool `yaml:"lldp" json:"lldp"`
}

// NeighborConfig configures the kernel neighbour collector.
type NeighborConfig struct {
	ResyncInterval Duration `yaml:"resync_interval" json:"resync_interval"`
}

// ActiveConfig holds global active-discovery settings and safety budgets.
type ActiveConfig struct {
	StartupDelay        Duration `yaml:"startup_delay" json:"startup_delay"`
	Jitter              float64  `yaml:"jitter" json:"jitter"`
	MaxPacketsPerSecond float64  `yaml:"max_packets_per_second" json:"max_packets_per_second"`
	MaxConcurrentProbes int      `yaml:"max_concurrent_probes" json:"max_concurrent_probes"`
	MinTargetInterval   Duration `yaml:"min_target_interval" json:"min_target_interval"`
	Budgets             Budgets  `yaml:"budgets" json:"budgets"`
	MaxAutoScanPrefixV4 int      `yaml:"max_auto_scan_prefix_v4" json:"max_auto_scan_prefix_v4"`
	AllowWideScan       bool     `yaml:"allow_wide_scan" json:"allow_wide_scan"`
	// MaxSweepTargets caps the addresses one interface's ARP sweep covers
	// (after excludes). Above DefaultMaxSweepTargets it is an expert
	// override: it needs allow_wide_scan and rates and concurrency at or
	// below their defaults.
	MaxSweepTargets int            `yaml:"max_sweep_targets" json:"max_sweep_targets"`
	ARP             ProbeConfig    `yaml:"arp" json:"arp"`
	ICMP            ProbeConfig    `yaml:"icmp" json:"icmp"`
	TCP             TCPProbeConfig `yaml:"tcp" json:"tcp"`
	UDP             UDPProbeConfig `yaml:"udp" json:"udp"`
	Identify        IdentifyConfig `yaml:"identify" json:"identify"`
}

// UDPProbeNames are the protocol-specific UDP probes (FR-AC-6).
var UDPProbeNames = []string{"ntp", "enip"}

// IdentifyProbeNames are the identification probes an interface may name
// (ADR 0011). A name that is not on this list fails validation.
var IdentifyProbeNames = []string{"modbus", "http", "tls", "snmp", "ssh-banner", "telnet", "ftp"}

// IdentifyConfig is the global identification-probe schedule and defaults
// (FR-AC-11). Interval is how often the daemon looks for hosts it has
// never attempted, not a repeat period.
type IdentifyConfig struct {
	Interval   Duration              `yaml:"interval" json:"interval"`
	Timeout    Duration              `yaml:"timeout" json:"timeout"`
	HostMaxAge Duration              `yaml:"host_max_age" json:"host_max_age"`
	Probes     IdentifyProbeDefaults `yaml:"probes" json:"probes"`
}

// IdentifyProbeDefaults are the compiled defaults for probe options.
type IdentifyProbeDefaults struct {
	Modbus IdentifyModbusOptions `yaml:"modbus" json:"modbus"`
	SNMP   IdentifySNMPOptions   `yaml:"snmp" json:"snmp"`
}

// IdentifyModbusOptions are the defaults for the Modbus FC 43/14 probe.
type IdentifyModbusOptions struct {
	UnitID int `yaml:"unit_id" json:"unit_id"`
}

// IdentifySNMPOptions are the defaults for the SNMPv2c GetRequest.
type IdentifySNMPOptions struct {
	Community string `yaml:"community" json:"community"`
}

// UnitIDOf returns the Modbus unit id for an interface entry.
func (c IdentifyConfig) UnitIDOf(e InterfaceIdentify) int {
	if e.UnitID != nil {
		return *e.UnitID
	}
	if c.Probes.Modbus.UnitID != 0 {
		return c.Probes.Modbus.UnitID
	}
	return 1
}

// CommunityOf returns the SNMPv2c community for an interface entry.
// Empty when neither the entry nor the global default is set; validation
// requires a value when the interface names snmp.
func (c IdentifyConfig) CommunityOf(e InterfaceIdentify) string {
	if e.Community != "" {
		return e.Community
	}
	return c.Probes.SNMP.Community
}

// UDPProbeConfig configures periodic protocol-specific UDP probes.
type UDPProbeConfig struct {
	Enabled  bool     `yaml:"enabled" json:"enabled"`
	Interval Duration `yaml:"interval" json:"interval"`
	Probes   []string `yaml:"probes" json:"probes"`
}

// Budgets are the per-protocol rate limits beneath the global packet budget.
type Budgets struct {
	ARP  RateBudget `yaml:"arp" json:"arp"`
	ICMP RateBudget `yaml:"icmp" json:"icmp"`
	NDP  RateBudget `yaml:"ndp" json:"ndp"`
	UDP  RateBudget `yaml:"udp" json:"udp"`
	TCP  TCPBudget  `yaml:"tcp" json:"tcp"`
}

// RateBudget limits a packet-based probe engine.
type RateBudget struct {
	PacketsPerSecond float64 `yaml:"packets_per_second" json:"packets_per_second"`
}

// TCPBudget limits the TCP connect engine.
type TCPBudget struct {
	ConnectsPerSecond         float64 `yaml:"connects_per_second" json:"connects_per_second"`
	MaxConcurrentPerInterface int     `yaml:"max_concurrent_per_interface" json:"max_concurrent_per_interface"`
	MaxConcurrentPerHost      int     `yaml:"max_concurrent_per_host" json:"max_concurrent_per_host"`
}

// TCPConnectTokens is how many tokens of the global packet budget one TCP
// connect consumes (SYN, ACK, FIN/RST).
const TCPConnectTokens = 3

// ProbeConfig enables a periodic probe.
type ProbeConfig struct {
	Enabled  bool     `yaml:"enabled" json:"enabled"`
	Interval Duration `yaml:"interval" json:"interval"`
}

// TCPProbeConfig configures periodic TCP connect probes.
type TCPProbeConfig struct {
	Enabled  bool        `yaml:"enabled" json:"enabled"`
	Interval Duration    `yaml:"interval" json:"interval"`
	Targets  []TCPTarget `yaml:"targets" json:"targets"`
}

// TCPTarget is one probed TCP port.
type TCPTarget struct {
	Port    int      `yaml:"port" json:"port"`
	Name    string   `yaml:"name" json:"name"`
	Timeout Duration `yaml:"timeout" json:"timeout"`
}

// ProfileConfig is a named on-demand scan profile.
type ProfileConfig struct {
	ARP  bool     `yaml:"arp" json:"arp"`
	ICMP bool     `yaml:"icmp" json:"icmp"`
	TCP  []int    `yaml:"tcp" json:"tcp"`
	UDP  []string `yaml:"udp,omitempty" json:"udp,omitempty"`
}

// PresenceConfig holds presence thresholds (time since last observation).
type PresenceConfig struct {
	Active Duration `yaml:"active" json:"active"`
	Recent Duration `yaml:"recent" json:"recent"`
	Stale  Duration `yaml:"stale" json:"stale"`
}

// IdentityConfig holds correlation and naming settings.
type IdentityConfig struct {
	HostnamePreference []string `yaml:"hostname_preference" json:"hostname_preference"`
	AddressOverlap     Duration `yaml:"address_overlap" json:"address_overlap"`
	AddressExpiry      Duration `yaml:"address_expiry" json:"address_expiry"`
	// NameExpiry marks a name not confirmed for this long as stale when it
	// is read; it never closes the name (docs/DATA_MODEL.md §5.4).
	NameExpiry        Duration `yaml:"name_expiry" json:"name_expiry"`
	ProxyARPThreshold int      `yaml:"proxy_arp_threshold" json:"proxy_arp_threshold"`
	OUIOverride       string   `yaml:"oui_override" json:"oui_override"`
	// Identifiers enables the passive identification plugins
	// (docs/DATA_MODEL.md §5.7).
	Identifiers IdentifierToggles `yaml:"identifiers" json:"identifiers"`
}

// IdentifierToggles enables each passive identifier: device type, OS and
// model from mDNS services, DHCP vendor class and request list, hostname
// patterns and LLDP capabilities.
type IdentifierToggles struct {
	MDNS     bool `yaml:"mdns" json:"mdns"`
	DHCP     bool `yaml:"dhcp" json:"dhcp"`
	Hostname bool `yaml:"hostname" json:"hostname"`
	LLDP     bool `yaml:"lldp" json:"lldp"`
}

// StorageConfig configures the SQLite database.
type StorageConfig struct {
	Path      string          `yaml:"path" json:"path"`
	Retention RetentionConfig `yaml:"retention" json:"retention"`
}

// RetentionConfig holds retention limits.
type RetentionConfig struct {
	Observations Duration `yaml:"observations" json:"observations"`
	Rollups      Duration `yaml:"rollups" json:"rollups"`
	Events       Duration `yaml:"events" json:"events"`
	MaxDBSize    ByteSize `yaml:"max_db_size" json:"max_db_size"`
}

// APIConfig configures the local API listeners.
type APIConfig struct {
	Socket string `yaml:"socket" json:"socket"`
	Listen string `yaml:"listen" json:"listen"`
}

// MetricsConfig enables /metrics on the local TCP listener.
type MetricsConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// LoggingConfig configures logging.
type LoggingConfig struct {
	Level  string `yaml:"level" json:"level"`
	Format string `yaml:"format" json:"format"`
}

// ReplayConfig holds global replay settings.
type ReplayConfig struct {
	ExitWhenDone bool `yaml:"exit_when_done" json:"exit_when_done"`
}
