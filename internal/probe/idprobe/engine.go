package idprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/tcp"
)

// Engine runs identification jobs through the platform Transmitter.
type Engine struct {
	TX platform.Transmitter

	mu       sync.Mutex
	attempts map[[2]string]uint64
	duration map[string]float64
	claims   map[[2]string]uint64
}

// Protocol implements probe.Engine.
func (*Engine) Protocol() probe.Protocol { return probe.Identify }

// Run implements probe.Engine.
func (e *Engine) Run(ctx context.Context, p probe.Pass) ([]probe.Result, error) {
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
	timeout := p.Timeout()
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
loop:
	for _, job := range p.Identify {
		pr, ok := resolve(job)
		if !ok {
			add(probe.Result{Target: job.IP, Probe: job.Probe, State: probe.Blocked})
			continue
		}
		release, err := p.Budget.AcquirePackets(ctx, pr.Protocol(), p.Link.Name, job.IP, pr.BudgetCost())
		if errors.Is(err, probe.ErrRefused) {
			add(probe.Result{Target: job.IP, Port: int(pr.Port()), Probe: job.Probe, State: probe.Blocked})
			continue
		}
		if err != nil {
			runErr = err
			break loop
		}
		wg.Add(1)
		go func(job probe.IdentifyJob, pr Probe) {
			defer wg.Done()
			defer release()
			start := p.Now()
			result := e.exchange(ctx, p, job, pr, timeout)
			e.record(job.Probe, result, p.Now().Sub(start), result == observation.ResultOK)
			add(probe.Result{Target: job.IP, Port: int(pr.Port()), Probe: job.Probe, State: result})
		}(job, pr)
	}
	wg.Wait()
	return results, runErr
}

func resolve(job probe.IdentifyJob) (Probe, bool) {
	switch job.Probe {
	case "modbus":
		return Modbus{UnitID: job.UnitID}, true
	case "snmp":
		return SNMP{Community: job.Community}, true
	}
	pr, ok := Probes[job.Probe]
	return pr, ok
}

func (e *Engine) exchange(ctx context.Context, p probe.Pass, job probe.IdentifyJob, pr Probe, timeout time.Duration) string {
	addr := netip.AddrPortFrom(job.IP, pr.Port())
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(e.TX, dctx, p.Link.Name, addr, timeout, pr.Protocol())
	if err != nil {
		o := observation.Observation{
			Time: p.Now(), Source: observation.IdentifyProbe, Interface: p.Link.Name, IP: job.IP,
			Meta: Meta(pr.Name(), dialResult(err), job.Trigger, job.HostID, job.Actor, Response{}),
		}
		p.Emit(o)
		return dialResult(err)
	}
	defer func() { _ = conn.Close() }() // orderly close; never SetLinger(0)
	// Socket deadlines are wall-clock times, whatever clock the pass runs
	// on: a simulated pass clock here made every exchange time out at once
	// once the wall clock passed the simulated time.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	resp, xerr := pr.Exchange(dctx, newSession(conn, pr.Limits()))
	result := observation.ResultOK
	switch {
	case xerr == nil:
	case errors.Is(xerr, errExchange), errors.Is(xerr, errModbus), errors.Is(xerr, ErrLimit):
		result = observation.ResultMalformed
		resp = Response{}
	case isTimeout(xerr):
		result = observation.ResultTimeout
		resp = Response{}
	default:
		result = observation.ResultMalformed
		resp = Response{}
	}
	o := observation.Observation{
		Time: p.Now(), Source: observation.IdentifyProbe, Interface: p.Link.Name, IP: job.IP,
		Meta: Meta(pr.Name(), result, job.Trigger, job.HostID, job.Actor, resp),
	}
	if result == observation.ResultOK {
		proto := "tcp"
		if pr.Protocol() == probe.UDP {
			proto = "udp"
		}
		o.Service = &observation.ServiceResult{Proto: proto, Port: int(pr.Port()), State: observation.ServiceOpen}
		e.addClaims(pr.Name(), resp)
	}
	p.Emit(o)
	return result
}

func dial(tx platform.Transmitter, ctx context.Context, iface string, addr netip.AddrPort, timeout time.Duration, proto probe.Protocol) (net.Conn, error) {
	if proto == probe.UDP {
		return tx.DialUDP(ctx, iface, addr)
	}
	return tx.DialTCP(ctx, iface, addr, timeout)
}

func dialResult(err error) string {
	switch tcp.Classify(err) {
	case observation.ServiceRefused:
		return observation.ResultRefused
	default:
		return observation.ResultTimeout
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) ||
		(errors.As(err, &ne) && ne.Timeout())
}

func (e *Engine) record(name, result string, d time.Duration, _ bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.attempts == nil {
		e.attempts = map[[2]string]uint64{}
		e.duration = map[string]float64{}
	}
	e.attempts[[2]string{name, result}]++
	e.duration[name] = d.Seconds()
}

func (e *Engine) addClaims(name string, r Response) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.claims == nil {
		e.claims = map[[2]string]uint64{}
	}
	for f := range r.Identity {
		e.claims[[2]string{name, f}]++
	}
}

// Attempts is lan_sentinel_identify_attempts_total.
func (e *Engine) Attempts() map[[2]string]uint64 { return copy2(e, e.attempts) }

// Durations is lan_sentinel_identify_duration_seconds.
func (e *Engine) Durations() map[string]float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]float64, len(e.duration))
	for k, v := range e.duration {
		out[k] = v
	}
	return out
}

// Claims is lan_sentinel_identify_claims_total.
func (e *Engine) Claims() map[[2]string]uint64 { return copy2(e, e.claims) }

func copy2(e *Engine, m map[[2]string]uint64) map[[2]string]uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[[2]string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
