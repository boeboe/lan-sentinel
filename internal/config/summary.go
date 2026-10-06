package config

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Setting is one effective key with its value and origin.
type Setting struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// Settings flattens the effective configuration into sorted key/value pairs
// for `config show --sources`.
func (l *Loaded) Settings() ([]Setting, error) {
	out, err := flatten(l.Config)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Source = l.SourceOf(out[i].Key)
	}
	return out, nil
}

// Change is a key whose effective value differs between two
// configurations.
type Change struct {
	Key string `json:"key"`
	Old string `json:"old"`
	New string `json:"new"`
}

// Diff lists the keys whose values differ from old to next, sorted, keyed
// as `config show --sources` keys them. A key only one side has (a list of
// interfaces grew or shrank) is "" on the other.
func Diff(old, next *Config) ([]Change, error) {
	a, err := flatten(old)
	if err != nil {
		return nil, err
	}
	b, err := flatten(next)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(a))
	for _, s := range a {
		values[s.Key] = s.Value
	}
	out := []Change{}
	for _, s := range b {
		v, ok := values[s.Key]
		delete(values, s.Key)
		if !ok || v != s.Value {
			out = append(out, Change{Key: s.Key, Old: v, New: s.Value})
		}
	}
	for k, v := range values {
		out = append(out, Change{Key: k, Old: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// flatten turns c into sorted key/value pairs, without sources.
func flatten(c *Config) ([]Setting, error) {
	var n yaml.Node
	if err := n.Encode(c); err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	var out []Setting
	var walk func(n *yaml.Node, prefix string)
	walk = func(n *yaml.Node, prefix string) {
		switch n.Kind {
		case yaml.MappingNode:
			if len(n.Content) == 0 && prefix != "" {
				out = append(out, Setting{Key: prefix, Value: "{}"})
			}
			for i := 0; i+1 < len(n.Content); i += 2 {
				walk(n.Content[i+1], join(prefix, n.Content[i].Value))
			}
		case yaml.SequenceNode:
			if len(n.Content) > 0 && n.Content[0].Kind == yaml.MappingNode {
				for i, item := range n.Content {
					walk(item, fmt.Sprintf("%s[%d]", prefix, i))
				}
				return
			}
			vals := make([]string, len(n.Content))
			for i, c := range n.Content {
				vals[i] = c.Value
			}
			out = append(out, Setting{Key: prefix, Value: "[" + strings.Join(vals, ", ") + "]"})
		default:
			out = append(out, Setting{Key: prefix, Value: n.Value})
		}
	}
	walk(&n, "")
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// InterfaceSummary describes one interface for `config validate`.
type InterfaceSummary struct {
	Name        string   `json:"name"`
	Mode        string   `json:"mode"` // live or replay
	Passive     bool     `json:"passive"`
	Promiscuous bool     `json:"promiscuous"`
	Active      bool     `json:"active"`
	Networks    []string `json:"networks,omitempty"`
	Exclude     []string `json:"exclude,omitempty"`
	ReplayFile  string   `json:"replay_file,omitempty"`
	// SweepTargets is how many addresses an ARP sweep covers (after
	// excludes), and SweepSeconds how long one takes at the ARP rate.
	SweepTargets uint64  `json:"sweep_targets,omitempty"`
	SweepSeconds float64 `json:"sweep_seconds,omitempty"`
	// DHCPServers is the DHCP server allowlist; nil without one.
	DHCPServers *[]string `json:"dhcp_servers,omitempty"`
}

// Summary is what `config validate` prints for a valid configuration.
type Summary struct {
	Interfaces []InterfaceSummary `json:"interfaces"`
	// Probes lists enabled periodic probes, e.g. "arp every 5m".
	Probes  []string           `json:"probes"`
	Budgets map[string]float64 `json:"budgets"`
	// MaxPacketsPerSecond is the estimated worst-case probe rate: the sum of
	// the budgets of enabled probes, capped by the global budget. Zero when
	// no interface has active discovery enabled.
	MaxPacketsPerSecond float64 `json:"max_packets_per_second"`
}

// Summarize builds the `config validate` summary.
func Summarize(cfg *Config) Summary {
	s := Summary{Budgets: map[string]float64{
		"global_pps":   cfg.Active.MaxPacketsPerSecond,
		"arp_pps":      cfg.Active.Budgets.ARP.PacketsPerSecond,
		"icmp_pps":     cfg.Active.Budgets.ICMP.PacketsPerSecond,
		"ndp_pps":      cfg.Active.Budgets.NDP.PacketsPerSecond,
		"udp_pps":      cfg.Active.Budgets.UDP.PacketsPerSecond,
		"tcp_connects": cfg.Active.Budgets.TCP.ConnectsPerSecond,
	}}
	anyActive := false
	for _, ic := range cfg.Interfaces {
		is := InterfaceSummary{
			Name:        ic.Name,
			Mode:        "live",
			Passive:     ic.PassiveEnabled(),
			Promiscuous: ic.Passive.Promiscuous,
			Active:      ic.Active.Enabled,
		}
		if ic.IsReplay() {
			is.Mode, is.ReplayFile = "replay", ic.Replay.File
		}
		for _, n := range ic.Active.Networks {
			is.Networks = append(is.Networks, n.String())
		}
		for _, e := range ic.Active.Exclude {
			b, _ := e.MarshalText()
			is.Exclude = append(is.Exclude, string(b))
		}
		if ic.Active.Enabled {
			is.SweepTargets = SweepTargets(ic)
			if r := cfg.Active.Budgets.ARP.PacketsPerSecond; r > 0 {
				is.SweepSeconds = float64(is.SweepTargets) / r * 1.02 // paced 2% below the rate
			}
		}
		if ic.DHCP.Servers != nil {
			servers := make([]string, len(*ic.DHCP.Servers))
			for i, a := range *ic.DHCP.Servers {
				servers[i] = a.String()
			}
			is.DHCPServers = &servers
		}
		anyActive = anyActive || ic.Active.Enabled
		s.Interfaces = append(s.Interfaces, is)
	}

	a := cfg.Active
	var rate float64
	if a.ARP.Enabled {
		s.Probes = append(s.Probes, "arp every "+a.ARP.Interval.String())
		rate += a.Budgets.ARP.PacketsPerSecond
	}
	if a.ICMP.Enabled {
		s.Probes = append(s.Probes, "icmp every "+a.ICMP.Interval.String())
		rate += a.Budgets.ICMP.PacketsPerSecond
	}
	if a.TCP.Enabled {
		ports := make([]string, len(a.TCP.Targets))
		for i, t := range a.TCP.Targets {
			ports[i] = fmt.Sprintf("%d", t.Port)
			if t.Name != "" {
				ports[i] += " (" + t.Name + ")"
			}
		}
		s.Probes = append(s.Probes, "tcp "+strings.Join(ports, ", ")+" every "+a.TCP.Interval.String())
		rate += a.Budgets.TCP.ConnectsPerSecond * TCPConnectTokens
	}
	if a.UDP.Enabled && len(a.UDP.Probes) > 0 {
		s.Probes = append(s.Probes, "udp "+strings.Join(a.UDP.Probes, ", ")+" every "+a.UDP.Interval.String())
		rate += a.Budgets.UDP.PacketsPerSecond
	}
	if anyActive {
		s.MaxPacketsPerSecond = math.Min(rate, a.MaxPacketsPerSecond)
	}
	return s
}

// ActiveText says in one line what active discovery runs, for the log at
// start-up and on reload: "arp every 5m on eth0 (192.168.0.0/24 exclude
// 192.168.0.1)", "off", or "no probe enabled on eth0 (...)".
func (s Summary) ActiveText() string {
	var on []string
	for _, is := range s.Interfaces {
		if !is.Active {
			continue
		}
		nets := strings.Join(is.Networks, ", ")
		if len(is.Exclude) > 0 {
			nets += " exclude " + strings.Join(is.Exclude, ", ")
		}
		on = append(on, is.Name+" ("+nets+")")
	}
	switch {
	case len(on) == 0:
		return "off"
	case len(s.Probes) == 0:
		return "no probe enabled on " + strings.Join(on, ", ")
	}
	return strings.Join(s.Probes, ", ") + " on " + strings.Join(on, ", ")
}
