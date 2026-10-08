// Package idprobe is the opt-in identification engine (ADR 0011, FR-AC-11).
// The engine dials and enforces the Session caps. The scheduler owns
// eligibility, jobs and the interval. A Probe owns only the bounded
// exchange.
package idprobe

import (
	"context"
	"errors"
	"strconv"

	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/probe"
)

// Session is a restricted connection: the engine dials, the probe only
// reads and writes.
type Session interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}

// Limits bound one exchange. The engine enforces them; a probe must not
// expand past them because of what a device sends.
type Limits struct {
	MaxWrites int
	MaxRead   int
}

// Response is what a probe learnt. Details describe the service;
// Identity fields are claims (identifications, source = the probe name);
// Confidence is per field, defaulting to 0.9 when a field is omitted.
type Response struct {
	Details    map[string]string
	Identity   map[string]string
	Confidence map[string]float64
}

// Probe is one identification protocol.
type Probe interface {
	Name() string
	Protocol() probe.Protocol
	Port() uint16
	BudgetCost() int
	Limits() Limits
	Exchange(context.Context, Session) (Response, error)
}

// Probes are the built identification probes by name. Config validation
// lists the same names (config.IdentifyProbeNames).
var Probes = map[string]Probe{
	"modbus":     Modbus{},
	"http":       HTTP{},
	"tls":        TLS{},
	"snmp":       SNMP{},
	"ssh-banner": SSHBanner{},
	"telnet":     Telnet{},
	"ftp":        FTP{},
}

// BudgetCostOf is the logical packet charge of one exchange of name (ADR
// 0011): 3 for TCP setup and close plus one per application write the
// probe may make; UDP is one datagram. It is not a promise about segments
// or kernel ACKs. The engine books it before each send and `scan plan`
// estimates with it, so both read the same Probe. 0 for an unknown name.
func BudgetCostOf(name string) int {
	if p, ok := Probes[name]; ok {
		return p.BudgetCost()
	}
	return 0
}

// ErrLimit is a Session refusing a write or read past Limits.
var ErrLimit = errors.New("identify exchange exceeded its bound")

// errExchange is a protocol reject (malformed reply or bound).
var errExchange = errors.New("identification exchange rejected")

// Meta encodes a response as observation metadata.
func Meta(probeName, result, trigger, hostID, actor string, r Response) map[string]string {
	n := len(r.Details) + len(r.Identity)*2 + 5
	m := make(map[string]string, n)
	for k, v := range r.Details {
		m[k] = v
	}
	for k, v := range r.Identity {
		if k == "" || v == "" {
			continue
		}
		m[observation.MetaIdentityPrefix+k] = v
		if c, ok := r.Confidence[k]; ok {
			m[observation.MetaIdentityConfPrefix+k] = strconv.FormatFloat(c, 'f', 2, 64)
		}
	}
	m[observation.MetaProbe] = probeName
	m[observation.MetaResult] = result
	if trigger != "" {
		m[observation.MetaTrigger] = trigger
	}
	if hostID != "" {
		m[observation.MetaHostID] = hostID
	}
	if actor != "" {
		m[observation.MetaActor] = actor
	}
	return m
}
