package config

import (
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Duration is a time.Duration written as a Go duration string ("5m", "750ms").
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return formatDuration(time.Duration(d)) }

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: expected a duration such as 5m or 750ms", n.Line)
	}
	return d.parse(n.Value)
}

// MarshalText implements encoding.TextMarshaler (used for JSON output).
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

func (d *Duration) parse(s string) error {
	v, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("invalid duration %q: use Go syntax such as 30s, 5m or 168h", s)
	}
	*d = Duration(v)
	return nil
}

func formatDuration(d time.Duration) string {
	switch {
	case d == 0:
		return "0s"
	case d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	case d%time.Second == 0:
		return strconv.FormatInt(int64(d/time.Second), 10) + "s"
	case d%time.Millisecond == 0:
		return strconv.FormatInt(int64(d/time.Millisecond), 10) + "ms"
	default:
		return d.String()
	}
}

// ByteSize is a size in bytes written as "200MB", "1GiB" or a plain integer.
type ByteSize int64

var byteUnits = []struct {
	suffix string
	mult   int64
}{
	// Longest suffixes first so "MiB" is not read as "B".
	{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30},
	{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
	{"B", 1},
}

func (b ByteSize) String() string {
	v := int64(b)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"GB", 1e9}, {"MB", 1e6}, {"KB", 1e3}} {
		if v != 0 && v%u.mult == 0 {
			return strconv.FormatInt(v/u.mult, 10) + u.suffix
		}
	}
	return strconv.FormatInt(v, 10) + "B"
}

// MarshalYAML implements yaml.Marshaler.
func (b ByteSize) MarshalYAML() (any, error) { return b.String(), nil }

// MarshalText implements encoding.TextMarshaler (used for JSON output).
func (b ByteSize) MarshalText() ([]byte, error) { return []byte(b.String()), nil }

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: expected a size such as 200MB", n.Line)
	}
	return b.parse(n.Value)
}

func (b *ByteSize) parse(s string) error {
	s = strings.TrimSpace(s)
	mult := int64(1)
	num := s
	for _, u := range byteUnits {
		if strings.HasSuffix(s, u.suffix) {
			mult, num = u.mult, strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			break
		}
	}
	v, err := strconv.ParseInt(num, 10, 64)
	if err != nil || v < 0 || v > math.MaxInt64/mult {
		return fmt.Errorf("invalid size %q: use a number with an optional unit B, KB, MB, GB, KiB, MiB or GiB", s)
	}
	*b = ByteSize(v * mult)
	return nil
}

// AddrOrPrefix is an exclude entry: a single IP or a CIDR. A single IP is
// stored as a full-length prefix.
type AddrOrPrefix struct{ netip.Prefix }

// MarshalText prints single addresses without the prefix length.
func (a AddrOrPrefix) MarshalText() ([]byte, error) {
	if a.IsSingleIP() {
		return []byte(a.Addr().String()), nil
	}
	return []byte(a.String()), nil
}

// UnmarshalText accepts "192.168.1.1" or "192.168.1.0/28".
func (a *AddrOrPrefix) UnmarshalText(b []byte) error {
	s := strings.TrimSpace(string(b))
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q", s)
		}
		a.Prefix = p
		return nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("invalid IP address %q", s)
	}
	a.Prefix = netip.PrefixFrom(ip, ip.BitLen())
	return nil
}
