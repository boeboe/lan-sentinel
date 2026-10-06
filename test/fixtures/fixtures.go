// Package fixtures defines the synthetic pcap captures under test/fixtures
// (regenerated with `make fixtures`). They stand in for captures from real
// sites until those are available (docs/IMPLEMENTATION_PLAN.md, open
// checks), and they are built from scenario descriptions so a test can
// verify the committed files are current.
package fixtures

import (
	"bytes"
	"io"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"lan-sentinel/test/frames"
)

// Packet is one captured frame.
type Packet struct {
	Time  time.Time
	Frame []byte
}

// SiteA is the T0 of the site-a scenario.
var SiteA = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

// Hosts of the site-a scenario.
var (
	PLCA   = frames.MAC("00:1b:1b:aa:bb:01")
	PLCB   = frames.MAC("00:1b:1b:aa:bb:02")
	PLCC   = frames.MAC("00:1b:1b:aa:bb:03")
	HMI    = frames.MAC("00:0e:8c:11:22:33")
	Server = frames.MAC("00:15:5d:00:00:02")
	Switch = frames.MAC("00:1e:c9:00:00:01")
)

// SiteAPackets is a site on 192.168.110.0/24 seen from a switch port over
// four hours. It replays the reconstruction scenario (docs/DATA_MODEL.md
// §10) through the real decoders: an IP change by DHCP, a new host taking
// over the old address, and a duplicate IP raised by gratuitous ARP and
// resolved by the next DHCP lease; plus names from mDNS, DHCP, DNS PTR and
// LLDP, a repeated frame within the refresh interval and IPv6 traffic that
// the default configuration ignores.
func SiteAPackets() []Packet {
	at := func(d time.Duration, f []byte) Packet { return Packet{SiteA.Add(d), f} }
	ack := func(client []byte, ip string) []byte {
		return frames.DHCP{Type: layers.DHCPMsgTypeAck, Client: client, YourIP: ip, Server: Server, ServerIP: "192.168.110.2"}.Frame()
	}
	const s, m, h = time.Second, time.Minute, time.Hour
	return []Packet{
		at(0, frames.ARP(layers.ARPRequest, PLCA, "192.168.110.50", frames.Broadcast, "192.168.110.50")),
		at(1*s, frames.MDNS4(PLCA, "192.168.110.50", []layers.DNSResourceRecord{
			frames.PTR("_http._tcp.local", "PLC A._http._tcp.local"),
			frames.SRV("PLC A._http._tcp.local", "plc-a.local", 80),
			frames.A("plc-a.local", "192.168.110.50"),
		}, nil)),
		at(2*s, frames.LLDP{Source: frames.MAC("00:1e:c9:00:00:17"), ChassisMAC: Switch, PortID: "ge-0/0/23", TTL: 120,
			SystemName: "plant-sw-01", SystemDesc: "Industrial Ethernet Switch", Caps: 0x04, MgmtIP: "192.168.110.3"}.Frame()),
		at(10*m, frames.ARP(layers.ARPRequest, Server, "192.168.110.2", frames.MAC("00:00:00:00:00:00"), "192.168.110.20")),
		at(10*m+1*s, frames.DHCP{Type: layers.DHCPMsgTypeDiscover, Client: HMI, Hostname: "HMI-LINE3",
			ClientID: append([]byte{1}, HMI...), ParamRequest: []byte{1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252},
			VendorClass: "MSFT 5.0"}.Frame()),
		at(10*m+2*s, ack(HMI, "192.168.110.20")),
		at(10*m+3*s, frames.UDP4(Server, HMI, "192.168.110.2", "192.168.110.20", 53, 49152, frames.DNSResponse(
			[]layers.DNSResourceRecord{frames.PTR("20.110.168.192.in-addr.arpa", "hmi-line3.plant.example.")}, nil))),
		at(1*h, ack(PLCA, "192.168.110.51")),
		at(2*h, frames.ARP(layers.ARPReply, PLCB, "192.168.110.50", Server, "192.168.110.2")),
		at(2*h+50*m, frames.ARP(layers.ARPRequest, PLCA, "192.168.110.51", frames.MAC("00:00:00:00:00:00"), "192.168.110.2")),
		at(3*h, frames.ARP(layers.ARPRequest, PLCC, "192.168.110.51", frames.Broadcast, "192.168.110.51")),
		at(3*h+30*m, ack(PLCA, "192.168.110.52")),
		at(3*h+30*m+1*s, frames.NeighborAdvertisement(PLCA, "fe80::21b:1bff:feaa:bb01", "fe80::21b:1bff:feaa:bb01", 0x20)),
		at(4*h, frames.ICMPv4Echo(HMI, Server, "192.168.110.20", "192.168.110.2")),
		at(4*h+30*s, frames.ICMPv4Echo(HMI, Server, "192.168.110.20", "192.168.110.2")), // within the refresh interval
	}
}

// WritePcapng writes packets as a deterministic pcapng file: fixed section
// and interface options, so the output does not depend on the machine.
func WritePcapng(w io.Writer, pkts []Packet) error {
	intf := pcapgo.NgInterface{Name: "eth1", LinkType: layers.LinkTypeEthernet, SnapLength: 0, TimestampResolution: 9}
	nw, err := pcapgo.NewNgWriterInterface(w, intf, pcapgo.NgWriterOptions{
		SectionInfo: pcapgo.NgSectionInfo{Application: "lan-sentinel test/fixtures/gen"},
	})
	if err != nil {
		return err
	}
	for _, p := range pkts {
		ci := gopacket.CaptureInfo{Timestamp: p.Time, CaptureLength: len(p.Frame), Length: len(p.Frame)}
		if err := nw.WritePacket(ci, p.Frame); err != nil {
			return err
		}
	}
	return nw.Flush()
}

// Files maps each committed fixture to its contents.
func Files() (map[string][]byte, error) {
	var b bytes.Buffer
	if err := WritePcapng(&b, SiteAPackets()); err != nil {
		return nil, err
	}
	return map[string][]byte{"site-a-eth1.pcapng": b.Bytes()}, nil
}
