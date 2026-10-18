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
// (docs/ARCHITECTURE.md §3): ARP, LLDP, CDP (802.3 LLC/SNAP), NDP, DHCP
// (67/68), NetBIOS (from 137 and 138), mDNS (from 5353), DNS responses (from
// 53), SSDP (to or from 1900) and WS-Discovery (to or from 3702) in full,
// other IPv4 and IPv6 frames truncated to their headers when source learning
// is on, everything else dropped; never
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
	udp4 := p.DHCP || p.MDNS || p.DNS || p.NetBIOS || p.SSDP || p.WSD
	udp6 := p.MDNS || p.DNS || p.SSDP || p.WSD
	v4 := p.IPv4 || udp4
	if v4 {
		a.jeq(decoders.EtherTypeIPv4, "ipv4")
	}
	if p.IPv6 {
		a.jeq(decoders.EtherTypeIPv6, "ipv6")
	}
	if p.CDP {
		// A type/length field of at most 1500 is an 802.3 length; CDP
		// follows an LLC/SNAP header with the Cisco OUI and protocol 0x2000.
		a.jgt(decoders.MaxLength802, "drop")
		a.ins(bpf.LoadAbsolute{Off: 14, Size: 4})
		a.jne(0xaaaa0300, "drop") // SNAP SAPs, UI, first OUI byte
		a.ins(bpf.LoadAbsolute{Off: 18, Size: 4})
		a.jeq(0x000c2000, "full") // the rest of the Cisco OUI, protocol 0x2000
	}
	a.ins(bpf.RetConstant{Val: 0})

	ipv4Header := "drop"
	if p.IPv4 {
		ipv4Header = "header"
	}
	if v4 {
		a.label("ipv4")
		if udp4 {
			// Fragments after the first have no UDP header.
			a.ins(bpf.LoadAbsolute{Off: 20, Size: 2})
			a.jset(0x1fff, ipv4Header)
			a.ins(bpf.LoadAbsolute{Off: 23, Size: 1})
			a.jne(17, ipv4Header)
			a.ins(bpf.LoadMemShift{Off: 14})
			a.ins(bpf.LoadIndirect{Off: 14, Size: 2}) // source port
			a.udpPorts(p, true)
			if p.DHCP || p.SSDP || p.WSD {
				a.ins(bpf.LoadIndirect{Off: 16, Size: 2}) // destination port
				a.udpDestinationPorts(p, true)
			}
		}
		a.jump(ipv4Header)
	}
	if p.IPv6 {
		a.label("ipv6")
		a.ins(bpf.LoadAbsolute{Off: 20, Size: 1}) // next header
		a.jeq(58, "icmpv6")
		if udp6 {
			a.jeq(17, "udp6")
		}
		a.jump("header")
		a.label("icmpv6")
		a.ins(bpf.LoadAbsolute{Off: 54, Size: 1}) // ICMPv6 type: NDP is 133-137
		a.jlt(133, "header")
		a.jgt(137, "header")
		a.jump("full")
		if udp6 {
			a.label("udp6")
			a.ins(bpf.LoadAbsolute{Off: 54, Size: 2}) // source port
			a.udpPorts(p, false)
			if p.SSDP || p.WSD {
				a.ins(bpf.LoadAbsolute{Off: 56, Size: 2}) // destination port
				a.udpDestinationPorts(p, false)
			}
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

// udpPorts jumps to full for the source ports in the accumulator: mDNS,
// DNS, the answers of SSDP and WS-Discovery, and on IPv4 DHCP and NetBIOS.
func (a *asm) udpPorts(p decoders.Protocols, v4 bool) {
	if v4 && p.DHCP {
		a.jeq(decoders.PortDHCPServer, "full")
		a.jeq(decoders.PortDHCPClient, "full")
	}
	if v4 && p.NetBIOS {
		a.jeq(decoders.PortNBNS, "full")
		a.jeq(decoders.PortNBDatagram, "full")
	}
	if p.MDNS {
		a.jeq(decoders.PortMDNS, "full")
	}
	if p.DNS {
		a.jeq(decoders.PortDNS, "full")
	}
	if p.SSDP {
		a.jeq(decoders.PortSSDP, "full")
	}
	if p.WSD {
		a.jeq(decoders.PortWSD, "full")
	}
}

// udpDestinationPorts jumps to full for the destination ports in the
// accumulator: DHCP's on IPv4, and the SSDP and WS-Discovery multicast
// announcements, which may come from any port.
func (a *asm) udpDestinationPorts(p decoders.Protocols, v4 bool) {
	if v4 && p.DHCP {
		a.jeq(decoders.PortDHCPServer, "full")
		a.jeq(decoders.PortDHCPClient, "full")
	}
	if p.SSDP {
		a.jeq(decoders.PortSSDP, "full")
	}
	if p.WSD {
		a.jeq(decoders.PortWSD, "full")
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
