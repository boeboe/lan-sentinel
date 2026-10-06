package capture

import (
	"fmt"

	"golang.org/x/net/bpf"

	"lan-sentinel/internal/collect/capture/decoders"
)

// Snap lengths returned by the filter: whole frames for the protocols the
// decoders read, headers only for IPv4/IPv6 source-address learning.
const (
	snapFull   = 0x40000
	snapHeader = 96 // Ethernet + the longest IPv4 header or the IPv6 header
)

// packetOutgoing is the kernel's PACKET_OUTGOING packet type: frames this
// host sends, which are not evidence about other hosts.
const packetOutgoing = 4

// vlanIDMask selects the VLAN ID in a tag control field.
const vlanIDMask = 0x0fff

// Filter returns the classic-BPF program for the enabled protocols
// (docs/ARCHITECTURE.md §3): ARP, LLDP, NDP, DHCP (67/68), mDNS (5353) and
// DNS responses (from 53) in full, other IPv4 and IPv6 frames truncated to
// their headers when source learning is on, everything else dropped; never
// the host's own outgoing frames, and never frames of a VLAN (out of scope
// in v1). The kernel strips 802.1Q tags before the filter runs, so the
// VLAN is checked through the tag extensions; priority-tagged frames
// (VLAN ID 0, common with PROFINET devices) belong to the untagged network
// and are kept.
func Filter(p decoders.Protocols) ([]bpf.RawInstruction, error) {
	return assemble(p, true)
}

// assemble builds the program. The x/net/bpf VM used in tests implements
// none of the packet-type and VLAN extensions, so tests leave that
// prelude out.
func assemble(p decoders.Protocols, kernel bool) ([]bpf.RawInstruction, error) {
	var a asm
	if kernel {
		a.ins(bpf.LoadExtension{Num: bpf.ExtType})
		a.jeq(packetOutgoing, "drop")
		a.ins(bpf.LoadExtension{Num: bpf.ExtVLANTagPresent})
		a.jeq(0, "untagged")
		a.ins(bpf.LoadExtension{Num: bpf.ExtVLANTag})
		a.jset(vlanIDMask, "drop")
		a.label("untagged")
	}
	a.ins(bpf.LoadAbsolute{Off: 12, Size: 2})
	if p.ARP {
		a.jeq(decoders.EtherTypeARP, "full")
	}
	if p.LLDP {
		a.jeq(decoders.EtherTypeLLDP, "full")
	}
	v4 := p.IPv4 || p.DHCP || p.MDNS || p.DNS
	if v4 {
		a.jeq(decoders.EtherTypeIPv4, "ipv4")
	}
	if p.IPv6 {
		a.jeq(decoders.EtherTypeIPv6, "ipv6")
	}
	a.ins(bpf.RetConstant{Val: 0})

	ipv4Header := "drop"
	if p.IPv4 {
		ipv4Header = "header"
	}
	if v4 {
		a.label("ipv4")
		if p.DHCP || p.MDNS || p.DNS {
			// Fragments after the first have no UDP header.
			a.ins(bpf.LoadAbsolute{Off: 20, Size: 2})
			a.jset(0x1fff, ipv4Header)
			a.ins(bpf.LoadAbsolute{Off: 23, Size: 1})
			a.jne(17, ipv4Header)
			a.ins(bpf.LoadMemShift{Off: 14})
			a.ins(bpf.LoadIndirect{Off: 14, Size: 2}) // source port
			a.udpPorts(p, true)
			if p.DHCP {
				a.ins(bpf.LoadIndirect{Off: 16, Size: 2}) // destination port
				a.jeq(decoders.PortDHCPServer, "full")
				a.jeq(decoders.PortDHCPClient, "full")
			}
		}
		a.jump(ipv4Header)
	}
	if p.IPv6 {
		a.label("ipv6")
		a.ins(bpf.LoadAbsolute{Off: 20, Size: 1}) // next header
		a.jeq(58, "icmpv6")
		if p.MDNS || p.DNS {
			a.jeq(17, "udp6")
		}
		a.jump("header")
		a.label("icmpv6")
		a.ins(bpf.LoadAbsolute{Off: 54, Size: 1}) // ICMPv6 type: NDP is 133-137
		a.jlt(133, "header")
		a.jgt(137, "header")
		a.jump("full")
		if p.MDNS || p.DNS {
			a.label("udp6")
			a.ins(bpf.LoadAbsolute{Off: 54, Size: 2})
			a.udpPorts(p, false)
			a.jump("header")
		}
	}
	a.label("header")
	a.ins(bpf.RetConstant{Val: snapHeader})
	a.label("full")
	a.ins(bpf.RetConstant{Val: snapFull})
	a.label("drop")
	a.ins(bpf.RetConstant{Val: 0})
	return a.assemble()
}

// udpPorts jumps to full for the mDNS and DNS source ports (and DHCP's on
// IPv4) in the accumulator.
func (a *asm) udpPorts(p decoders.Protocols, v4 bool) {
	if v4 && p.DHCP {
		a.jeq(decoders.PortDHCPServer, "full")
		a.jeq(decoders.PortDHCPClient, "full")
	}
	if p.MDNS {
		a.jeq(decoders.PortMDNS, "full")
	}
	if p.DNS {
		a.jeq(decoders.PortDNS, "full")
	}
}

// asm assembles classic BPF with symbolic jump targets.
type asm struct {
	prog   []bpf.Instruction
	jumps  []jump
	labels map[string]int
}

type jump struct {
	at    int
	label string
}

func (a *asm) ins(i bpf.Instruction) { a.prog = append(a.prog, i) }

func (a *asm) label(name string) {
	if a.labels == nil {
		a.labels = map[string]int{}
	}
	a.labels[name] = len(a.prog)
}

func (a *asm) cond(c bpf.JumpTest, v uint32, label string) {
	a.jumps = append(a.jumps, jump{len(a.prog), label})
	a.ins(bpf.JumpIf{Cond: c, Val: v})
}

func (a *asm) jeq(v uint32, label string)  { a.cond(bpf.JumpEqual, v, label) }
func (a *asm) jne(v uint32, label string)  { a.cond(bpf.JumpNotEqual, v, label) }
func (a *asm) jlt(v uint32, label string)  { a.cond(bpf.JumpLessThan, v, label) }
func (a *asm) jgt(v uint32, label string)  { a.cond(bpf.JumpGreaterThan, v, label) }
func (a *asm) jset(v uint32, label string) { a.cond(bpf.JumpBitsSet, v, label) }

func (a *asm) jump(label string) {
	a.jumps = append(a.jumps, jump{len(a.prog), label})
	a.ins(bpf.Jump{})
}

func (a *asm) assemble() ([]bpf.RawInstruction, error) {
	for _, j := range a.jumps {
		target, ok := a.labels[j.label]
		if !ok {
			return nil, fmt.Errorf("bpf: undefined label %q", j.label)
		}
		skip := target - j.at - 1
		switch i := a.prog[j.at].(type) {
		case bpf.JumpIf:
			if skip < 0 || skip > 255 {
				return nil, fmt.Errorf("bpf: jump to %q out of range", j.label)
			}
			i.SkipTrue = uint8(skip)
			a.prog[j.at] = i
		case bpf.Jump:
			i.Skip = uint32(skip)
			a.prog[j.at] = i
		}
	}
	return bpf.Assemble(a.prog)
}
