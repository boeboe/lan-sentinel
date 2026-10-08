package config

import (
	"net/netip"
	"strings"
)

// SNIModeAuto is the only non-empty config value for TLS SNI: send
// preferred_name when it is a DNS name (ADR 0011).
const SNIModeAuto = "auto"

// SNIModeOf is empty (no SNI) or auto for an interface tls entry.
func (c IdentifyConfig) SNIModeOf(e InterfaceIdentify) string {
	if e.SNI != "" {
		return e.SNI
	}
	return c.Probes.TLS.SNI
}

// SNIName reports whether name is a DNS name we may put on a ClientHello:
// has a dot, RFC 1123 labels, not an IP. The returned string is lower case.
func SNIName(name string) (string, bool) {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" || !strings.Contains(name, ".") || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return "", false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", false
	}
	if len(name) > 253 {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 {
			return "", false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
				continue
			}
			return "", false
		}
	}
	return name, true
}

// ResolveSNI is the name to put on the ClientHello: operator first (already
// a DNS name), else preferred_name when mode is auto and it is a DNS name.
func ResolveSNI(mode, preferred, operator string) string {
	if operator != "" {
		n, _ := SNIName(operator)
		return n
	}
	if mode != SNIModeAuto {
		return ""
	}
	n, _ := SNIName(preferred)
	return n
}
