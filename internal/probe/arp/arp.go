// Package arp is the ARP sweep engine (FR-AC-2): one ARP request per
// target, broadcast on the interface; every reply from a target becomes an
// arp_scan observation. ARP is the primary IPv4 discovery mechanism.
package arp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe"
)

// Engine sends ARP requests through a platform frame connection.
type Engine struct {
	TX platform.Transmitter
}

// Protocol implements probe.Engine.
func (Engine) Protocol() probe.Protocol { return probe.ARP }

var broadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// Request builds the broadcast ARP request for target, sent from mac and
// src.
func Request(mac net.HardwareAddr, src, target netip.Addr) ([]byte, error) {
	s, t := src.As4(), target.As4()
	eth := layers.Ethernet{SrcMAC: mac, DstMAC: broadcast, EthernetType: layers.EthernetTypeARP}
	a := layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
		Operation: layers.ARPRequest, SourceHwAddress: mac, SourceProtAddress: s[:],
		DstHwAddress: make([]byte, 6), DstProtAddress: t[:],
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, &eth, &a); err != nil {
		return nil, fmt.Errorf("build ARP request: %w", err)
	}
	return buf.Bytes(), nil
}

// Reply is a decoded ARP reply: who claims which address.
type Reply struct {
	MAC net.HardwareAddr
	IP  netip.Addr
}

// ParseReply decodes an Ethernet ARP reply addressed to own.
func ParseReply(data []byte, own net.HardwareAddr) (Reply, bool) {
	var eth layers.Ethernet
	var a layers.ARP
	p := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &a)
	p.IgnoreUnsupported = true
	var decoded []gopacket.LayerType
	if err := p.DecodeLayers(data, &decoded); err != nil || len(decoded) < 2 {
		return Reply{}, false
	}
	if a.Operation != layers.ARPReply || a.AddrType != layers.LinkTypeEthernet || a.Protocol != layers.EthernetTypeIPv4 ||
		len(a.SourceHwAddress) != 6 || len(a.SourceProtAddress) != 4 || !bytes.Equal(a.DstHwAddress, own) {
		return Reply{}, false
	}
	ip, _ := netip.AddrFromSlice(a.SourceProtAddress)
	return Reply{MAC: append(net.HardwareAddr(nil), a.SourceHwAddress...), IP: ip}, true
}

// Run implements probe.Engine. The targets are the pass's Sweep (streamed,
// as wide as configured) or its Targets. Results: one per address that
// answered and per address the policy blocked, and one for all unanswered
// addresses (Count).
func (e Engine) Run(ctx context.Context, p probe.Pass) ([]probe.Result, error) {
	conn, err := e.TX.Frames(ctx, p.Link.Name, uint16(layers.EthernetTypeARP))
	if err != nil {
		return nil, fmt.Errorf("arp on %s: %w", p.Link.Name, err)
	}
	defer func() { _ = conn.Close() }()

	targets, isTarget := p.Sweep, p.InSweep
	if targets == nil {
		targets, isTarget = slices.Values(p.Targets), nil
	}
	replies := probe.NewReplies(p, isTarget)
	rctx, stopRead := context.WithCancel(ctx)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		read(rctx, conn, p, replies)
	}()

	var results []probe.Result
	sent := 0
	var runErr error
	for target := range targets {
		release, err := p.Budget.Acquire(ctx, probe.ARP, p.Link.Name, target)
		if errors.Is(err, probe.ErrRefused) {
			results = append(results, probe.Result{Target: target, State: probe.Blocked})
			continue
		}
		if err != nil {
			runErr = err
			break
		}
		frame, err := Request(p.Link.MAC, p.Link.SourceFor(target), target)
		if err == nil {
			replies.Expect(target)
			err = conn.WriteFrame(ctx, frame)
		}
		if err != nil {
			release()
			runErr = fmt.Errorf("arp on %s: %w", p.Link.Name, err)
			break
		}
		sent++
		replies.Hold(ctx, target, release)
	}
	replies.Wait()
	stopRead()
	<-readDone
	responders := replies.Responders()
	for _, ip := range responders {
		results = append(results, probe.Result{Target: ip, State: probe.Reply})
	}
	if n := sent - len(responders); n > 0 {
		results = append(results, probe.Result{Count: n, State: probe.NoReply})
	}
	return results, runErr
}

// read emits every distinct (IP, MAC) answer from a target: two MACs
// answering for one address are both evidence (a duplicate IP or a proxy).
func read(ctx context.Context, conn platform.FrameConn, p probe.Pass, replies *probe.Replies) {
	seen := map[string]bool{}
	for {
		f, err := conn.ReadFrame(ctx)
		if err != nil {
			return
		}
		r, ok := ParseReply(f.Data, p.Link.MAC)
		if !ok || !replies.Reply(r.IP) {
			continue
		}
		key := r.IP.String() + "/" + r.MAC.String()
		if !seen[key] {
			seen[key] = true
			p.Emit(observation.Observation{Time: p.Now(), Source: observation.ARPScan, Interface: p.Link.Name, MAC: r.MAC, IP: r.IP})
		}
	}
}
