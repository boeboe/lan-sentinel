// Package udp is the protocol-specific UDP probe engine (FR-AC-6). Each
// probe sends one well-formed request of its protocol to a known host and
// parses the reply; there is no generic UDP port scanning (CLAUDE.md rule
// 7). A reply becomes a udp_probe observation carrying the service state
// OPEN and the probe's details; no reply means nothing at all, never that
// the host is offline. A new probe is a new Prober in Probers.
package udp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe"
)

// Response is what a probe learnt from a reply. Details describe the
// service (services.detail_json); Identity fields are claims about the
// device (identifications rows, source = the probe name).
type Response struct {
	Details  map[string]string
	Identity map[string]string
}

// Prober is one protocol-specific UDP probe.
type Prober interface {
	Name() string
	Port() uint16
	// Request returns a new request, with a fresh token where the
	// protocol has one, so Parse can match the reply.
	Request() ([]byte, error)
	// Parse decodes reply and reports whether it answers req.
	Parse(req, reply []byte) (Response, bool)
}

// Probers are the available probes by name; config.UDPProbeNames lists the
// same names.
var Probers = map[string]Prober{"ntp": NTP{}, "enip": ENIP{}}

// Meta encodes a response as observation metadata: identity fields under
// observation.MetaIdentityPrefix, the probe's name under
// observation.MetaProbe, details as they are.
func Meta(probeName string, r Response) map[string]string {
	m := make(map[string]string, len(r.Details)+len(r.Identity)+1)
	for k, v := range r.Details {
		m[k] = v
	}
	for k, v := range r.Identity {
		m[observation.MetaIdentityPrefix+k] = v
	}
	m[observation.MetaProbe] = probeName
	return m
}

// Engine sends probes through connected UDP sockets bound to the
// interface.
type Engine struct {
	TX platform.Transmitter
}

// Protocol implements probe.Engine.
func (Engine) Protocol() probe.Protocol { return probe.UDP }

// Run implements probe.Engine: probe by probe across the hosts.
func (e Engine) Run(ctx context.Context, p probe.Pass) ([]probe.Result, error) {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []probe.Result
		runErr  error
	)
	add := func(r probe.Result) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}
loop:
	for _, name := range p.UDP {
		pr, ok := Probers[name]
		if !ok {
			runErr = fmt.Errorf("udp on %s: unknown probe %q", p.Link.Name, name)
			break
		}
		for _, target := range p.Targets {
			release, err := p.Budget.Acquire(ctx, probe.UDP, p.Link.Name, target)
			if errors.Is(err, probe.ErrRefused) {
				add(probe.Result{Target: target, Port: int(pr.Port()), Probe: name, State: probe.Blocked})
				continue
			}
			if err != nil {
				runErr = err
				break loop
			}
			wg.Add(1)
			go func(target netip.Addr) {
				defer wg.Done()
				defer release()
				resp, ok := e.probe(ctx, p, pr, target)
				if ctx.Err() != nil {
					return
				}
				r := probe.Result{Target: target, Port: int(pr.Port()), Probe: name, State: probe.NoReply}
				if ok {
					r.State = probe.Reply
					p.Emit(observation.Observation{
						Time: p.Now(), Source: observation.UDPProbe, Interface: p.Link.Name, IP: target,
						Service: &observation.ServiceResult{Proto: "udp", Port: int(pr.Port()), State: observation.ServiceOpen},
						Meta:    Meta(name, resp),
					})
				}
				add(r)
			}(target)
		}
	}
	wg.Wait()
	sort.SliceStable(results, func(i, j int) bool { return results[i].Probe < results[j].Probe })
	return results, runErr
}

// probe sends one request and waits for a matching reply until the reply
// timeout. Errors (an ICMP port unreachable, a send failure) are no reply.
func (e Engine) probe(ctx context.Context, p probe.Pass, pr Prober, target netip.Addr) (Response, bool) {
	req, err := pr.Request()
	if err != nil {
		return Response{}, false
	}
	conn, err := e.TX.DialUDP(ctx, p.Link.Name, netip.AddrPortFrom(target, pr.Port()))
	if err != nil {
		return Response{}, false
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(req); err != nil {
		return Response{}, false
	}
	deadline := time.Now().Add(p.Timeout())
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		n, err := conn.Read(buf)
		if err != nil {
			return Response{}, false
		}
		if r, ok := pr.Parse(req, buf[:n]); ok {
			return r, true
		}
	}
	return Response{}, false
}
