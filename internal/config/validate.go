package config

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"lan-sentinel/internal/netrange"
)

var (
	ifaceNameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$`)
	profileNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

	logLevels  = []string{"trace", "debug", "info", "warn", "error"}
	logFormats = []string{"journald", "text", "json"}
	nameTypes  = []string{"mdns", "dhcp", "dns_ptr", "lldp", "netbios"}
	replayExts = []string{".pcap", ".pcapng", ".pcap.gz", ".pcapng.gz", ".jsonl"}
	minDBSize  = ByteSize(10 * 1000 * 1000)
	// minProbeInterval keeps periodic probing from becoming a flood.
	minProbeInterval = 10 * time.Second
	minRingSize      = ByteSize(256 << 10)
	maxRingSize      = ByteSize(256 << 20)
	minIfPrefix      = 8
)

// Validate checks cfg and returns every problem found.
func Validate(cfg *Config) []FieldError {
	v := &validator{}

	if cfg.Version != 1 {
		v.add("version", "must be 1, got %d", cfg.Version)
	}
	v.interfaces(cfg)

	if r := cfg.Passive.RingSize; r < minRingSize || r > maxRingSize {
		v.add("passive.ring_size", "must be between %s and %s, got %s", minRingSize, maxRingSize, r)
	}
	if d := cfg.Neighbor.ResyncInterval.D(); d < time.Second {
		v.add("neighbor.resync_interval", "must be at least 1s, got %s", cfg.Neighbor.ResyncInterval)
	}
	v.active(cfg)
	v.profiles(cfg)
	v.presence(cfg)
	v.identity(cfg)
	v.storage(cfg)
	v.api(cfg)

	if !slices.Contains(logLevels, cfg.Logging.Level) {
		v.add("logging.level", "must be one of %v, got %q", logLevels, cfg.Logging.Level)
	}
	if !slices.Contains(logFormats, cfg.Logging.Format) {
		v.add("logging.format", "must be one of %v, got %q", logFormats, cfg.Logging.Format)
	}
	return v.errs
}

type validator struct{ errs []FieldError }

func (v *validator) add(key, format string, args ...any) {
	v.errs = append(v.errs, FieldError{Key: key, Msg: fmt.Sprintf(format, args...)})
}

func (v *validator) positive(key string, d Duration) {
	if d.D() <= 0 {
		v.add(key, "must be greater than zero, got %s", d)
	}
}

func (v *validator) interfaces(cfg *Config) {
	if len(cfg.Interfaces) == 0 {
		v.add("interfaces", "at least one interface is required")
	}
	replays := 0
	for _, ic := range cfg.Interfaces {
		if ic.IsReplay() {
			replays++
		}
	}
	if replays > 0 && replays < len(cfg.Interfaces) {
		v.add("interfaces", "replay and live interfaces cannot be mixed: replay runs the daemon on recorded time")
	}
	seen := map[string]bool{}
	for i, ic := range cfg.Interfaces {
		k := fmt.Sprintf("interfaces[%d]", i)
		switch {
		case !ifaceNameRe.MatchString(ic.Name):
			v.add(k+".name", "must be an interface name of at most 15 characters, got %q", ic.Name)
		case seen[ic.Name]:
			v.add(k+".name", "interface %q is listed more than once", ic.Name)
		}
		seen[ic.Name] = true

		for j, pf := range ic.Prefixes {
			if pf != pf.Masked() {
				v.add(fmt.Sprintf("%s.prefixes[%d]", k, j), "%s has host bits set; use %s", pf, pf.Masked())
			}
		}
		if ic.IsReplay() {
			v.replayInterface(k, ic)
		} else if len(ic.Prefixes) > 0 {
			v.add(k+".prefixes", "only allowed on replay interfaces; live interfaces learn their prefixes from the kernel")
		}
		if ic.Passive.Promiscuous && !ic.PassiveEnabled() {
			v.add(k+".passive.promiscuous", "requires passive.enabled")
		}
		v.activeInterface(k, ic, cfg.Active)
		if ic.DHCP.Servers != nil {
			for j, s := range *ic.DHCP.Servers {
				if !s.Is4() || !s.IsGlobalUnicast() { // private ranges count; broadcast, multicast and 0.0.0.0 do not
					v.add(fmt.Sprintf("%s.dhcp.servers[%d]", k, j), "%s is not a unicast IPv4 address (a DHCP server identifier, option 54)", s)
				}
			}
		}
	}
}

func (v *validator) replayInterface(k string, ic InterfaceConfig) {
	r := ic.Replay
	switch {
	case r.File == "":
		v.add(k+".replay.file", "is required")
	case !slices.ContainsFunc(replayExts, func(ext string) bool { return strings.HasSuffix(r.File, ext) }):
		v.add(k+".replay.file", "must end in one of %v, got %q", replayExts, r.File)
	}
	if r.Speed < 0 {
		v.add(k+".replay.speed", "must be 0 (simulated clock) or a positive factor, got %v", r.Speed)
	}
	if len(ic.Prefixes) == 0 {
		v.add(k+".prefixes", "required for replay interfaces (used for the on-link check)")
	}
	if ic.Passive.Enabled != nil && *ic.Passive.Enabled {
		v.add(k+".passive.enabled", "replay is mutually exclusive with live passive capture")
	}
	if ic.Active.Enabled {
		v.add(k+".active.enabled", "replay is mutually exclusive with active discovery")
	}
}

func (v *validator) activeInterface(k string, ic InterfaceConfig, ac ActiveConfig) {
	if ic.Active.Enabled && len(ic.Active.Networks) == 0 {
		v.add(k+".active.networks", "at least one network is required when active discovery is enabled")
	}
	var hosts []netrange.Range
	for j, n := range ic.Active.Networks {
		nk := fmt.Sprintf("%s.active.networks[%d]", k, j)
		switch {
		case !n.Addr().Is4():
			v.add(nk, "%s: only IPv4 networks can be scanned (v1 active discovery is IPv4-first)", n)
		case n != n.Masked():
			v.add(nk, "%s has host bits set; use %s", n, n.Masked())
		case n.Bits() < ac.MaxAutoScanPrefixV4 && !ac.AllowWideScan:
			v.add(nk, "%s is wider than /%d; narrow it or set active.allow_wide_scan: true", n, ac.MaxAutoScanPrefixV4)
		default:
			hosts = append(hosts, netrange.Hosts(n))
		}
	}
	if n := SweepTargets(ic); n > uint64(max(ac.MaxSweepTargets, 0)) && len(hosts) > 0 {
		v.add(k+".active.networks", "the networks hold %d addresses to sweep, more than active.max_sweep_targets (%d)", n, ac.MaxSweepTargets)
	}
	for j, e := range ic.Active.Exclude {
		if !e.IsSingleIP() && e.Prefix != e.Masked() {
			v.add(fmt.Sprintf("%s.active.exclude[%d]", k, j), "%s has host bits set; use %s", e.Prefix, e.Masked())
		}
	}
	v.identifyList(k+".active.identify", ic.Active.Identify, ac.Identify)
}

// maxSNMPCommunity bounds the SNMPv2c community so a typo cannot send
// a huge GetRequest (ADR 0011: one datagram).
const maxSNMPCommunity = 128

func (v *validator) identifyList(key string, list []InterfaceIdentify, defaults IdentifyConfig) {
	seen := map[string]bool{}
	for i, e := range list {
		k := fmt.Sprintf("%s[%d]", key, i)
		switch {
		case e.Name == "":
			v.add(k+".name", "is required")
		case !slices.Contains(IdentifyProbeNames, e.Name):
			v.add(k+".name", "must be one of %v, got %q", IdentifyProbeNames, e.Name)
		case seen[e.Name]:
			v.add(k+".name", "%q is listed more than once", e.Name)
		}
		seen[e.Name] = true
		if e.Name != "modbus" && e.UnitID != nil {
			v.add(k+".unit_id", "does not apply to %s", e.Name)
		}
		if e.Name != "snmp" && e.Community != "" {
			v.add(k+".community", "does not apply to %s", e.Name)
		}
		if e.Name != "tls" && e.SNI != "" {
			v.add(k+".sni", "does not apply to %s", e.Name)
		}
		if e.Name == "modbus" {
			id := defaults.UnitIDOf(e)
			if id < 1 || id > 255 {
				v.add(k+".unit_id", "must be between 1 and 255, got %d", id)
			}
		}
		if e.Name == "snmp" {
			c := defaults.CommunityOf(e)
			switch {
			case c == "":
				v.add(k+".community", "is required")
			case len(c) > maxSNMPCommunity:
				v.add(k+".community", "must be at most %d characters, got %d", maxSNMPCommunity, len(c))
			}
		}
		if e.Name == "tls" {
			if mode := defaults.SNIModeOf(e); mode != "" && mode != SNIModeAuto {
				v.add(k+".sni", "must be empty or %q, got %q", SNIModeAuto, mode)
			}
		}
	}
}

// Sweep limits: DefaultMaxSweepTargets is active.max_sweep_targets' default
// (a /16: nearly two hours at 10 pps); above it is an expert override.
// MaxSweepTargetsCeiling (a /8) only keeps the value sane.
const (
	DefaultMaxSweepTargets = 1 << 16
	MaxSweepTargetsCeiling = 1 << 24
)

// SweepTargets counts the addresses an interface's ARP sweep covers: the
// host addresses of its IPv4 networks less the excluded ones (the
// interface's own addresses, known only at run time, are not taken off).
func SweepTargets(ic InterfaceConfig) uint64 {
	var hosts, cut []netrange.Range
	for _, n := range ic.Active.Networks {
		if n.Addr().Is4() {
			hosts = append(hosts, netrange.Hosts(n))
		}
	}
	for _, e := range ic.Active.Exclude {
		if e.Addr().Is4() {
			cut = append(cut, netrange.Of(e.Prefix))
		}
	}
	return netrange.New(hosts...).Minus(cut...).Len()
}

// sweepOverride checks active.max_sweep_targets. Above the default it is an
// expert override, allowed only with allow_wide_scan and with the global and
// ARP rates and the concurrency cap at or below their defaults, so a wider
// sweep only ever takes longer, never sends faster.
func (v *validator) sweepOverride(a ActiveConfig) {
	const k = "active.max_sweep_targets"
	switch {
	case a.MaxSweepTargets < 1 || a.MaxSweepTargets > MaxSweepTargetsCeiling:
		v.add(k, "must be between 1 and %d, got %d", MaxSweepTargetsCeiling, a.MaxSweepTargets)
		return
	case a.MaxSweepTargets <= DefaultMaxSweepTargets:
		return
	case !a.AllowWideScan:
		v.add(k, "%d is above %d, an expert override that needs active.allow_wide_scan: true", a.MaxSweepTargets, DefaultMaxSweepTargets)
	}
	d := Defaults().Active
	for _, c := range []struct {
		key        string
		got, limit float64
	}{
		{"active.max_packets_per_second", a.MaxPacketsPerSecond, d.MaxPacketsPerSecond},
		{"active.budgets.arp.packets_per_second", a.Budgets.ARP.PacketsPerSecond, d.Budgets.ARP.PacketsPerSecond},
		{"active.max_concurrent_probes", float64(a.MaxConcurrentProbes), float64(d.MaxConcurrentProbes)},
	} {
		if c.got > c.limit {
			v.add(c.key, "%v exceeds its default %v, which the expert override active.max_sweep_targets above %d does not allow",
				c.got, c.limit, DefaultMaxSweepTargets)
		}
	}
}

// IsSingleIP reports whether the exclude entry is one address.
func (a AddrOrPrefix) IsSingleIP() bool { return a.IsValid() && a.Bits() == a.Addr().BitLen() }

func (v *validator) active(cfg *Config) {
	a := cfg.Active
	if a.StartupDelay.D() < 0 {
		v.add("active.startup_delay", "must not be negative")
	}
	if a.Jitter < 0 || a.Jitter > 0.5 {
		v.add("active.jitter", "must be between 0 and 0.5, got %v", a.Jitter)
	}
	if a.MaxPacketsPerSecond <= 0 {
		v.add("active.max_packets_per_second", "must be greater than zero, got %v", a.MaxPacketsPerSecond)
	}
	if a.MaxConcurrentProbes < 1 {
		v.add("active.max_concurrent_probes", "must be at least 1, got %d", a.MaxConcurrentProbes)
	}
	if a.MinTargetInterval.D() < 0 {
		v.add("active.min_target_interval", "must not be negative")
	}
	if a.MaxAutoScanPrefixV4 < minIfPrefix || a.MaxAutoScanPrefixV4 > 32 {
		v.add("active.max_auto_scan_prefix_v4", "must be between %d and 32, got %d", minIfPrefix, a.MaxAutoScanPrefixV4)
	}
	v.sweepOverride(a)

	for _, nb := range []struct {
		name string
		b    RateBudget
	}{{"arp", a.Budgets.ARP}, {"icmp", a.Budgets.ICMP}, {"ndp", a.Budgets.NDP}, {"udp", a.Budgets.UDP}} {
		k, b := "active.budgets."+nb.name+".packets_per_second", nb.b
		if b.PacketsPerSecond <= 0 {
			v.add(k, "must be greater than zero, got %v", b.PacketsPerSecond)
		} else if b.PacketsPerSecond > a.MaxPacketsPerSecond {
			v.add(k, "%v exceeds the global active.max_packets_per_second (%v)", b.PacketsPerSecond, a.MaxPacketsPerSecond)
		}
	}
	t := a.Budgets.TCP
	if t.ConnectsPerSecond <= 0 {
		v.add("active.budgets.tcp.connects_per_second", "must be greater than zero, got %v", t.ConnectsPerSecond)
	} else if t.ConnectsPerSecond*TCPConnectTokens > a.MaxPacketsPerSecond {
		v.add("active.budgets.tcp.connects_per_second", "%v connects/s × %d packets exceeds the global active.max_packets_per_second (%v)",
			t.ConnectsPerSecond, TCPConnectTokens, a.MaxPacketsPerSecond)
	}
	if t.MaxConcurrentPerHost < 1 {
		v.add("active.budgets.tcp.max_concurrent_per_host", "must be at least 1, got %d", t.MaxConcurrentPerHost)
	}
	if t.MaxConcurrentPerInterface < t.MaxConcurrentPerHost {
		v.add("active.budgets.tcp.max_concurrent_per_interface", "must be at least max_concurrent_per_host (%d), got %d", t.MaxConcurrentPerHost, t.MaxConcurrentPerInterface)
	} else if t.MaxConcurrentPerInterface > a.MaxConcurrentProbes {
		v.add("active.budgets.tcp.max_concurrent_per_interface", "must not exceed active.max_concurrent_probes (%d), got %d", a.MaxConcurrentProbes, t.MaxConcurrentPerInterface)
	}

	for _, iv := range []struct {
		key string
		d   Duration
	}{{"active.arp.interval", a.ARP.Interval}, {"active.icmp.interval", a.ICMP.Interval},
		{"active.tcp.interval", a.TCP.Interval}, {"active.udp.interval", a.UDP.Interval},
		{"active.identify.interval", a.Identify.Interval}} {
		if iv.d.D() < minProbeInterval {
			v.add(iv.key, "must be at least %s, got %s", Duration(minProbeInterval), iv.d)
		}
	}
	v.positive("active.identify.timeout", a.Identify.Timeout)
	v.positive("active.identify.host_max_age", a.Identify.HostMaxAge)
	if id := a.Identify.Probes.Modbus.UnitID; id < 1 || id > 255 {
		v.add("active.identify.probes.modbus.unit_id", "must be between 1 and 255, got %d", id)
	}
	if c := a.Identify.Probes.SNMP.Community; len(c) > maxSNMPCommunity {
		v.add("active.identify.probes.snmp.community", "must be at most %d characters, got %d", maxSNMPCommunity, len(c))
	}
	if s := a.Identify.Probes.TLS.SNI; s != "" && s != SNIModeAuto {
		v.add("active.identify.probes.tls.sni", "must be empty or %q, got %q", SNIModeAuto, s)
	}
	v.udpProbes("active.udp.probes", a.UDP.Probes)
	if a.UDP.Enabled && len(a.UDP.Probes) == 0 {
		v.add("active.udp.probes", "at least one probe is required when active.udp.enabled is true")
	}
	if a.TCP.Enabled && len(a.TCP.Targets) == 0 {
		v.add("active.tcp.targets", "at least one target is required when active.tcp.enabled is true")
	}
	ports := map[int]bool{}
	for i, tg := range a.TCP.Targets {
		k := fmt.Sprintf("active.tcp.targets[%d]", i)
		switch {
		case tg.Port < 1 || tg.Port > 65535:
			v.add(k+".port", "must be between 1 and 65535, got %d", tg.Port)
		case ports[tg.Port]:
			v.add(k+".port", "port %d is listed more than once", tg.Port)
		}
		ports[tg.Port] = true
		v.positive(k+".timeout", tg.Timeout)
	}
}

func (v *validator) udpProbes(key string, probes []string) {
	seen := map[string]bool{}
	for i, p := range probes {
		k := fmt.Sprintf("%s[%d]", key, i)
		switch {
		case !slices.Contains(UDPProbeNames, p):
			v.add(k, "must be one of %v, got %q", UDPProbeNames, p)
		case seen[p]:
			v.add(k, "%q is listed more than once", p)
		}
		seen[p] = true
	}
}

func (v *validator) profiles(cfg *Config) {
	for name, pr := range cfg.Profiles {
		k := "profiles." + name
		if !profileNameRe.MatchString(name) {
			v.add(k, "profile names use lowercase letters, digits, '-' and '_'")
		}
		if !pr.ARP && !pr.ICMP && len(pr.TCP) == 0 && len(pr.UDP) == 0 {
			v.add(k, "enables no probe")
		}
		v.udpProbes(k+".udp", pr.UDP)
		for i, port := range pr.TCP {
			if port < 1 || port > 65535 {
				v.add(fmt.Sprintf("%s.tcp[%d]", k, i), "must be between 1 and 65535, got %d", port)
			}
		}
	}
}

func (v *validator) presence(cfg *Config) {
	p := cfg.Presence
	v.positive("presence.active", p.Active)
	if p.Recent <= p.Active {
		v.add("presence.recent", "must be longer than presence.active (%s), got %s", p.Active, p.Recent)
	}
	if p.Stale <= p.Recent {
		v.add("presence.stale", "must be longer than presence.recent (%s), got %s", p.Recent, p.Stale)
	}
}

func (v *validator) identity(cfg *Config) {
	id := cfg.Identity
	seen := map[string]bool{}
	for i, t := range id.HostnamePreference {
		k := fmt.Sprintf("identity.hostname_preference[%d]", i)
		switch {
		case !slices.Contains(nameTypes, t):
			v.add(k, "must be one of %v, got %q", nameTypes, t)
		case seen[t]:
			v.add(k, "%q is listed more than once", t)
		}
		seen[t] = true
	}
	v.positive("identity.address_overlap", id.AddressOverlap)
	v.positive("identity.address_expiry", id.AddressExpiry)
	v.positive("identity.name_expiry", id.NameExpiry)
	if id.AddressOverlap >= id.AddressExpiry {
		v.add("identity.address_overlap", "must be shorter than identity.address_expiry (%s)", id.AddressExpiry)
	}
	if id.ProxyARPThreshold < 2 {
		v.add("identity.proxy_arp_threshold", "must be at least 2, got %d", id.ProxyARPThreshold)
	}
}

func (v *validator) storage(cfg *Config) {
	s := cfg.Storage
	if s.Path == "" {
		v.add("storage.path", "is required")
	}
	v.positive("storage.retention.observations", s.Retention.Observations)
	v.positive("storage.retention.rollups", s.Retention.Rollups)
	v.positive("storage.retention.events", s.Retention.Events)
	if s.Retention.MaxDBSize < minDBSize {
		v.add("storage.retention.max_db_size", "must be at least %s, got %s", minDBSize, s.Retention.MaxDBSize)
	}
}

func (v *validator) api(cfg *Config) {
	a := cfg.API
	switch {
	case a.Socket == "":
		v.add("api.socket", "is required")
	case len(a.Socket) > maxSocketPath:
		v.add("api.socket", "is %d bytes long; Unix socket paths are limited to %d", len(a.Socket), maxSocketPath)
	}
	if a.Listen == "" {
		return
	}
	host, port, err := net.SplitHostPort(a.Listen)
	if err != nil {
		v.add("api.listen", "must be host:port, got %q", a.Listen)
		return
	}
	if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
		v.add("api.listen", "must listen on a loopback address (127.0.0.1 or ::1), got %q", host)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		v.add("api.listen", "invalid port %q", port)
	}
}
