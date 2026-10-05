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
	var n yaml.Node
	if err := n.Encode(l.Config); err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	var out []Setting
	var walk func(n *yaml.Node, prefix string)
	walk = func(n *yaml.Node, prefix string) {
		switch n.Kind {
		case yaml.MappingNode:
			if len(n.Content) == 0 && prefix != "" {
				out = append(out, Setting{Key: prefix, Value: "{}", Source: l.SourceOf(prefix)})
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
			out = append(out, Setting{Key: prefix, Value: "[" + strings.Join(vals, ", ") + "]", Source: l.SourceOf(prefix)})
		default:
			out = append(out, Setting{Key: prefix, Value: n.Value, Source: l.SourceOf(prefix)})
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
	if anyActive {
		s.MaxPacketsPerSecond = math.Min(rate, a.MaxPacketsPerSecond)
	}
	return s
}
