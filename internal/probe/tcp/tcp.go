// Package tcp is the bare TCP connect engine (FR-AC-4): a plain connect()
// to each configured port of each known host, closed at once with a reset
// without sending anything. Never SYN scanning (AGENTS.md rule 7). Every
// result becomes a tcp_connect observation: OPEN, REFUSED, TIMEOUT or
// UNREACHABLE.
//
// Packets per connect, all within the 3 tokens a connect is charged:
// OPEN sends SYN, ACK and RST (3); REFUSED sends one SYN (the target's RST
// ends it); TIMEOUT sends the SYN and at most 2 kernel retransmissions
// (platform.SYNRetries), never data.
//
// The reset close belongs to this bare probe only. A protocol-specific TCP
// probe that exchanges data over the established connection (none in v1)
// must close it orderly (FIN) after its exchange, and is charged for the
// packets it sends.
package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe"
)

// Engine dials through the platform transmitter.
type Engine struct {
	TX platform.Transmitter
}

// Protocol implements probe.Engine.
func (Engine) Protocol() probe.Protocol { return probe.TCP }

// Classify maps a connect error to a service state. UNKNOWN is a local
// failure (no permission, interface gone, out of descriptors), not an
// answer from the target.
func Classify(err error) observation.ServiceState {
	var ne net.Error
	switch {
	case err == nil:
		return observation.ServiceOpen
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET):
		return observation.ServiceRefused
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return observation.ServiceTimeout
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTDOWN):
		return observation.ServiceUnreachable
	}
	return observation.ServiceUnknown
}

// Run implements probe.Engine. Probes go port by port across the hosts, so
// consecutive connects reach different hosts. A connect that fails locally
// (UNKNOWN) emits no observation: it says nothing about the target, and it
// fails the pass.
func (e Engine) Run(ctx context.Context, p probe.Pass) ([]probe.Result, error) {
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		results  []probe.Result
		runErr   error
		localErr error
	)
	add := func(r probe.Result) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}
loop:
	for _, tg := range p.TCP {
		for _, target := range p.Targets {
			release, err := p.Budget.Acquire(ctx, probe.TCP, p.Link.Name, target)
			if errors.Is(err, probe.ErrRefused) {
				add(probe.Result{Target: target, Port: tg.Port, State: probe.Blocked})
				continue
			}
			if err != nil {
				runErr = err
				break loop
			}
			wg.Add(1)
			go func(target netip.Addr, tg config.TCPTarget) {
				defer wg.Done()
				defer release()
				addr := netip.AddrPortFrom(target, uint16(tg.Port)) //nolint:gosec // ports are validated 1–65535
				state, ok, err := e.connect(ctx, p.Link.Name, addr, timeout(tg))
				if !ok {
					return
				}
				add(probe.Result{Target: target, Port: tg.Port, State: string(state)})
				if state == observation.ServiceUnknown {
					mu.Lock()
					if localErr == nil {
						localErr = fmt.Errorf("tcp on %s: connect %s: %w", p.Link.Name, addr, err)
					}
					mu.Unlock()
					return
				}
				p.Emit(observation.Observation{
					Time: p.Now(), Source: observation.TCPConnect, Interface: p.Link.Name, IP: target,
					Service: &observation.ServiceResult{Proto: "tcp", Port: tg.Port, State: state},
				})
			}(target, tg)
		}
	}
	wg.Wait()
	if runErr == nil {
		runErr = localErr
	}
	return results, runErr
}

func timeout(tg config.TCPTarget) time.Duration {
	if d := tg.Timeout.D(); d > 0 {
		return d
	}
	return probe.DefaultTCPTimeout
}

// connect dials and closes at once. ok is false when the pass was cancelled
// mid-connect: that is no result at all.
func (e Engine) connect(ctx context.Context, iface string, addr netip.AddrPort, d time.Duration) (observation.ServiceState, bool, error) {
	conn, err := e.TX.DialTCP(ctx, iface, addr, d)
	if conn != nil {
		abort(conn)
	}
	if ctx.Err() != nil {
		return "", false, nil
	}
	return Classify(err), true, err
}

// abort closes a bare connect with SO_LINGER 0: the close is a RST, so the
// connect sends exactly SYN, ACK and RST, and neither side keeps the
// connection in TIME_WAIT or CLOSE_WAIT. Only for connects that carried no
// data.
func abort(c net.Conn) {
	if l, ok := c.(interface{ SetLinger(sec int) error }); ok {
		_ = l.SetLinger(0)
	}
	_ = c.Close()
}
