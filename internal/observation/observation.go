// Package observation defines the one type every collector and probe emits
// (docs/DATA_MODEL.md §2), its JSONL encoding (replay files, golden
// scenarios) and the bounded bus that carries observations to the
// correlator.
package observation

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"time"
)

// Source says which mechanism produced an observation.
type Source string

// Sources (docs/DATA_MODEL.md §2).
const (
	PassiveARP     Source = "passive_arp"
	PassiveIPv4    Source = "passive_ipv4"
	PassiveIPv6    Source = "passive_ipv6"
	PassiveNDP     Source = "passive_ndp"
	PassiveDHCP    Source = "passive_dhcp"
	PassiveMDNS    Source = "passive_mdns"
	PassiveDNS     Source = "passive_dns"
	PassiveLLDP    Source = "passive_lldp"
	KernelNeighbor Source = "kernel_neighbor"
	ARPScan        Source = "arp_scan"
	ICMPScan       Source = "icmp_scan"
	NDPProbe       Source = "ndp_probe"
	TCPConnect     Source = "tcp_connect"
	UDPProbe       Source = "udp_probe"
)

// Sources lists every valid source.
var Sources = []Source{
	PassiveARP, PassiveIPv4, PassiveIPv6, PassiveNDP, PassiveDHCP, PassiveMDNS, PassiveDNS, PassiveLLDP,
	KernelNeighbor, ARPScan, ICMPScan, NDPProbe, TCPConnect, UDPProbe,
}

// Valid reports whether s is a known source.
func (s Source) Valid() bool { return slices.Contains(Sources, s) }

// NameType is the provenance of a hostname.
type NameType string

// Name types.
const (
	NameMDNS    NameType = "mdns"
	NameDHCP    NameType = "dhcp"
	NameDNSPTR  NameType = "dns_ptr"
	NameNetBIOS NameType = "netbios"
	NameLLDP    NameType = "lldp"
)

// ServiceState is a probe result.
type ServiceState string

// Probe results.
const (
	ServiceOpen        ServiceState = "OPEN"
	ServiceRefused     ServiceState = "REFUSED"
	ServiceTimeout     ServiceState = "TIMEOUT"
	ServiceUnreachable ServiceState = "UNREACHABLE"
	ServiceUnknown     ServiceState = "UNKNOWN"
)

// ServiceResult is the outcome of probing one protocol/port.
type ServiceResult struct {
	Proto string       `json:"proto"`
	Port  int          `json:"port"`
	State ServiceState `json:"state"`
}

// Key is "proto/port", e.g. "tcp/502".
func (s ServiceResult) Key() string { return fmt.Sprintf("%s/%d", s.Proto, s.Port) }

// Observation is raw evidence: source S saw MAC X / IP Y / name Z at time T
// on interface I.
type Observation struct {
	Time          time.Time
	Source        Source
	Interface     string           // network context key
	MAC           net.HardwareAddr // nil if the source has none (e.g. TCP probe)
	IP            netip.Addr       // invalid if the source has none (e.g. LLDP)
	Hostname      string
	NameType      NameType
	Service       *ServiceResult
	NeighborState string // kernel_neighbor: NUD state
	Meta          map[string]string
}

// jsonObservation is the JSONL wire form (docs/DATA_MODEL.md §2).
type jsonObservation struct {
	Time          time.Time         `json:"time"`
	Source        Source            `json:"source"`
	Interface     string            `json:"interface,omitempty"`
	MAC           string            `json:"mac,omitempty"`
	IP            string            `json:"ip,omitempty"`
	Hostname      string            `json:"hostname,omitempty"`
	NameType      NameType          `json:"name_type,omitempty"`
	Service       *ServiceResult    `json:"service,omitempty"`
	NeighborState string            `json:"neighbor_state,omitempty"`
	Meta          map[string]string `json:"meta,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (o Observation) MarshalJSON() ([]byte, error) {
	j := jsonObservation{
		Time: o.Time.UTC(), Source: o.Source, Interface: o.Interface, Hostname: o.Hostname,
		NameType: o.NameType, Service: o.Service, NeighborState: o.NeighborState, Meta: o.Meta,
	}
	if len(o.MAC) > 0 {
		j.MAC = o.MAC.String()
	}
	if o.IP.IsValid() {
		j.IP = o.IP.String()
	}
	return json.Marshal(j)
}

// UnmarshalJSON implements json.Unmarshaler. Unknown fields are rejected.
func (o *Observation) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var j jsonObservation
	if err := dec.Decode(&j); err != nil {
		return err
	}
	if j.Time.IsZero() {
		return errors.New("missing time")
	}
	if !j.Source.Valid() {
		return fmt.Errorf("unknown source %q", j.Source)
	}
	out := Observation{
		Time: j.Time, Source: j.Source, Interface: j.Interface, Hostname: j.Hostname, NameType: j.NameType,
		Service: j.Service, NeighborState: j.NeighborState, Meta: j.Meta,
	}
	if j.MAC != "" {
		mac, err := net.ParseMAC(j.MAC)
		if err != nil {
			return fmt.Errorf("mac: %w", err)
		}
		out.MAC = mac
	}
	if j.IP != "" {
		ip, err := netip.ParseAddr(j.IP)
		if err != nil {
			return fmt.Errorf("ip: %w", err)
		}
		out.IP = ip.Unmap()
	}
	if out.MAC == nil && !out.IP.IsValid() && out.Hostname == "" {
		return errors.New("observation has neither mac, ip nor hostname")
	}
	*o = out
	return nil
}

// maxLine bounds one JSONL line.
const maxLine = 1 << 20

// ReadJSONL calls fn for every observation in r, one JSON object per line.
// Blank lines are skipped; errors name the line.
func ReadJSONL(r io.Reader, fn func(Observation) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	for line := 1; sc.Scan(); line++ {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var o Observation
		if err := json.Unmarshal(b, &o); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if err := fn(o); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	return nil
}
