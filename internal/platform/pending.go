package platform

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// pending is a placeholder backend for a facility whose real implementation
// lands in a later phase. Every call fails with ErrNotImplemented naming the
// phase, so a configured collector shows as failed in `daemon status` rather
// than silently doing nothing.
type pending struct {
	backend string
	phase   int
}

func (p pending) err(what string) error {
	return fmt.Errorf("%s backend %s: %w (planned for phase %d)", what, p.backend, ErrNotImplemented, p.phase)
}

func (p pending) Backend() string { return p.backend }

type pendingTransmitter struct{ pending }

func (p pendingTransmitter) SendFrame(context.Context, string, []byte) error {
	return p.err("transmit")
}

func (p pendingTransmitter) DialTCP(context.Context, string, netip.AddrPort, time.Duration) (net.Conn, error) {
	return nil, p.err("transmit")
}

func (p pendingTransmitter) ICMPConn(context.Context, string, bool) (net.PacketConn, error) {
	return nil, p.err("transmit")
}
