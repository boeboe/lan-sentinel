// Package icmp is the ICMP echo engine (FR-AC-3): one echo request per
// known host; a reply becomes an icmp_scan observation. No reply means
// nothing: many OT devices and host firewalls drop ICMP.
package icmp

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe"
)

// Engine sends echo requests through a platform ICMP connection.
type Engine struct {
	TX platform.Transmitter
}

// Protocol implements probe.Engine.
func (Engine) Protocol() probe.Protocol { return probe.ICMP }

// payload is the fixed echo payload.
var payload = []byte("lan-sentinel")

// Request builds an echo request. On a ping socket the kernel replaces id
// with the socket's own identifier.
func Request(id, seq uint16) ([]byte, error) {
	m := layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: id, Seq: seq}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true}, &m, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("build echo request: %w", err)
	}
	return buf.Bytes(), nil
}

// ParseReply decodes an echo reply and returns its identifier and sequence.
func ParseReply(msg []byte) (id, seq uint16, ok bool) {
	var m layers.ICMPv4
	if err := m.DecodeFromBytes(msg, gopacket.NilDecodeFeedback); err != nil {
		return 0, 0, false
	}
	if m.TypeCode != layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0) {
		return 0, 0, false
	}
	return m.Id, m.Seq, true
}

// Run implements probe.Engine.
func (e Engine) Run(ctx context.Context, p probe.Pass) ([]probe.Result, error) {
	conn, err := e.TX.ICMPConn(ctx, p.Link.Name)
	if err != nil {
		return nil, fmt.Errorf("icmp on %s: %w", p.Link.Name, err)
	}
	defer func() { _ = conn.Close() }()

	id := uint16(rand.Uint32()) //nolint:gosec // an echo identifier, not a secret
	seqs := map[uint16]netip.Addr{}
	var mu sync.Mutex
	replies := probe.NewReplies(p, nil)
	rctx, stopRead := context.WithCancel(ctx)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(rctx, buf)
			if err != nil {
				return
			}
			rid, seq, ok := ParseReply(buf[:n])
			mu.Lock()
			target, known := seqs[seq]
			mu.Unlock()
			// A raw socket sees every echo reply on the box; a ping socket
			// only its own, with its own identifier.
			if !ok || !known || from != target || (!conn.Ping() && rid != id) || !replies.Reply(from) {
				continue
			}
			p.Emit(observation.Observation{Time: p.Now(), Source: observation.ICMPScan, Interface: p.Link.Name, IP: from})
		}
	}()

	results := make([]probe.Result, 0, len(p.Targets))
	var runErr error
	for i, target := range p.Targets {
		release, err := p.Budget.Acquire(ctx, probe.ICMP, p.Link.Name, target)
		if errors.Is(err, probe.ErrRefused) {
			results = append(results, probe.Result{Target: target, State: probe.Blocked})
			continue
		}
		if err != nil {
			runErr = err
			break
		}
		seq := uint16(i + 1) //nolint:gosec // wraps after 65,535 targets, as sequence numbers do
		mu.Lock()
		seqs[seq] = target
		mu.Unlock()
		msg, err := Request(id, seq)
		if err == nil {
			replies.Expect(target)
			err = conn.WriteTo(msg, target)
		}
		if err != nil {
			// A send error for one target (no route, no neighbour) is that
			// target's no-reply, not the end of the pass.
			release()
			results = append(results, probe.Result{Target: target, State: probe.NoReply})
			continue
		}
		results = append(results, probe.Result{Target: target, State: probe.NoReply})
		replies.Hold(ctx, target, release)
	}
	replies.Wait()
	stopRead()
	<-readDone
	return replies.Finish(results), runErr
}
