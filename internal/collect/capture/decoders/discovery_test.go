package decoders

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"

	"lan-sentinel/test/frames"
)

// The LAN discovery protocols: NetBIOS, CDP, SSDP and WS-Discovery
// (docs/DATA_MODEL.md §2).
func TestDecodeDiscovery(t *testing.T) {
	const (
		hmiIP   = "192.168.110.20"
		camIP   = "192.168.110.40"
		gateway = "192.168.110.1"
	)
	cam := frames.MAC("44:19:b6:00:00:40")
	ios := "Cisco IOS Software, IE4000 Software (IE4000-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE SOFTWARE (fc3)\n" +
		"Technical Support: http://www.cisco.com/techsupport\nCopyright (c) 1986-2021 by Cisco Systems, Inc."
	rawUDP := func(src, dstMAC []byte, ip, dst string, sport, dport uint16, msg string) []byte {
		return frames.UDP4(src, dstMAC, ip, dst, sport, dport, gopacket.Payload(msg))
	}
	onvifScopes := "onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/type/Network_Video_Transmitter " +
		"onvif://www.onvif.org/hardware/DS-2CD2143G0-I onvif://www.onvif.org/name/HIKVISION%20Camera " +
		"onvif://www.onvif.org/location/city/plant ldap:///ou=cameras"
	tests := []struct {
		name  string
		frame []byte
		p     Protocols
		want  []string
	}{
		// NetBIOS name service (UDP 137).
		{"netbios computer name", frames.NBNSRegistration(hmi, hmiIP, "HMI-LINE3", 0x00, false), All,
			[]string{"passive_netbios mac=00:0e:8c:11:22:33 ip=192.168.110.20 name=netbios:HMI-LINE3 netbios=registration"}},
		{"netbios server name", frames.NBNSRegistration(hmi, hmiIP, "HMI-LINE3", 0x20, false), All,
			[]string{"passive_netbios mac=00:0e:8c:11:22:33 ip=192.168.110.20 name=netbios:HMI-LINE3 netbios=registration"}},
		{"netbios workgroup", frames.NBNSRegistration(hmi, hmiIP, "PLANT", 0x00, true), All,
			[]string{"passive_netbios mac=00:0e:8c:11:22:33 ip=192.168.110.20 netbios=registration workgroup=PLANT"}},
		{"netbios domain controller", frames.NBNSRegistration(server, "192.168.110.2", "PLANT", 0x1c, true), All,
			[]string{"passive_netbios mac=02:00:00:00:00:53 ip=192.168.110.2 netbios=registration role=domain_controller workgroup=PLANT"}},
		{"netbios master browser", frames.NBNSRegistration(server, "192.168.110.2", "PLANT", 0x1d, false), All,
			[]string{"passive_netbios mac=02:00:00:00:00:53 ip=192.168.110.2 netbios=registration role=master_browser workgroup=PLANT"}},
		{"netbios messenger name (a user's) is not kept", frames.NBNSRegistration(hmi, hmiIP, "OPERATOR", 0x03, false), Protocols{NetBIOS: true}, nil},
		{"netbios disabled: the source only", frames.NBNSRegistration(hmi, hmiIP, "HMI-LINE3", 0x00, false), Protocols{IPv4: true},
			[]string{"passive_ipv4 mac=00:0e:8c:11:22:33 ip=192.168.110.20"}},
		{"netbios answer for its own address", frames.NBNSAnswer(hmi, plc, hmiIP, "192.168.110.50", "HMI-LINE3", 0x00, hmiIP), All,
			[]string{"passive_netbios mac=00:0e:8c:11:22:33 ip=192.168.110.20 name=netbios:HMI-LINE3 netbios=answer"}},
		{"netbios answer about another host (a WINS server's)", frames.NBNSAnswer(server, plc, "192.168.110.2", "192.168.110.50", "HMI-LINE3", 0x00, hmiIP),
			Protocols{NetBIOS: true}, nil},

		// NetBIOS datagrams (UDP 138): browser announcements.
		{"netbios host announcement", frames.Browser{Source: hmi, IP: hmiIP, Name: "HMI-LINE3", Workgroup: "PLANT", Opcode: 0x01,
			OSMajor: 6, OSMinor: 1, ServerType: 0x00001003, Comment: "Line 3 HMI"}.Frame(), All,
			[]string{"passive_netbios mac=00:0e:8c:11:22:33 ip=192.168.110.20 name=netbios:HMI-LINE3 comment=Line 3 HMI " +
				"netbios=host_announcement os_version=6.1 server_type=workstation,server,nt"}},
		{"netbios domain controller announcement", frames.Browser{Source: server, IP: "192.168.110.2", Name: "PLANT-DC1", Workgroup: "PLANT",
			Opcode: 0x0f, OSMajor: 10, OSMinor: 0, ServerType: 0x0004902b}.Frame(), All,
			[]string{"passive_netbios mac=02:00:00:00:00:53 ip=192.168.110.2 name=netbios:PLANT-DC1 netbios=host_announcement os_version=10.0 " +
				"server_type=workstation,server,domain_controller,time_source,nt,server_nt,master_browser"}},
		{"netbios workgroup announcement", frames.Browser{Source: server, IP: "192.168.110.2", Name: "PLANT-DC1", Workgroup: "PLANT",
			Opcode: 0x0c, ServerType: 0x80001000}.Frame(), All,
			[]string{"passive_netbios mac=02:00:00:00:00:53 ip=192.168.110.2 name=netbios:PLANT-DC1 netbios=workgroup_announcement workgroup=PLANT"}},
		{"netbios datagram relayed for another host", frames.Browser{Source: server, IP: "192.168.110.2", HeaderIP: hmiIP, Name: "HMI-LINE3",
			Workgroup: "PLANT", Opcode: 0x01}.Frame(), Protocols{NetBIOS: true}, nil},

		// CDP.
		{"cdp from a switch", frames.CDP{Source: swPort, Holdtime: 180, DeviceID: "IE4000-PLANT1.example.com", PortID: "GigabitEthernet1/0/12",
			Software: ios, Platform: "cisco IE-4000-8GT4G-E", Caps: 0x28, MgmtIP: "192.168.110.3"}.Frame(), All,
			[]string{"passive_cdp mac=00:1e:c9:00:00:17 name=lldp:IE4000-PLANT1.example.com capabilities=switch,igmp management_ip=192.168.110.3 " +
				"platform=cisco IE-4000-8GT4G-E port_id=GigabitEthernet1/0/12 software=Cisco IOS Software, IE4000 Software (IE4000-UNIVERSALK9-M), " +
				"Version 15.2(7)E4, RELEASE SOFTWARE (fc3) ttl=180"}},
		{"cdp from a phone", frames.CDP{Source: hmi, Holdtime: 180, DeviceID: "SEP000E8C112233", Caps: 0x90, Platform: "Cisco IP Phone 8841"}.Frame(), All,
			[]string{"passive_cdp mac=00:0e:8c:11:22:33 name=lldp:SEP000E8C112233 capabilities=host,phone platform=Cisco IP Phone 8841 ttl=180"}},
		{"cdp holdtime 0", frames.CDP{Source: swPort, DeviceID: "sw"}.Frame(), All, nil},
		{"cdp without a device id", frames.CDP{Source: swPort, Holdtime: 180, Platform: "cisco"}.Frame(), All, nil},
		{"cdp disabled", frames.CDP{Source: swPort, Holdtime: 180, DeviceID: "sw"}.Frame(), Protocols{LLDP: true, IPv4: true}, nil},

		// SSDP.
		{"ssdp root device", frames.SSDPNotify(router, gateway, "upnp:rootdevice", "uuid:2FAC1234-31F8-11B4-A222-08002B34C003::upnp:rootdevice",
			"Linux/4.14 UPnP/1.0 MiniUPnPd/2.1", "http://192.168.110.1:5000/rootDesc.xml"), All,
			[]string{"passive_ssdp mac=00:00:5e:00:01:01 ip=192.168.110.1 location=http://192.168.110.1:5000/rootDesc.xml nt=upnp:rootdevice " +
				"server=Linux/4.14 UPnP/1.0 MiniUPnPd/2.1 ssdp=notify uuid=2fac1234-31f8-11b4-a222-08002b34c003"}},
		{"ssdp device type", frames.SSDPNotify(router, gateway, "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
			"uuid:2fac1234-31f8-11b4-a222-08002b34c003::urn:schemas-upnp-org:device:InternetGatewayDevice:1", "Linux/4.14 UPnP/1.0 MiniUPnPd/2.1",
			"http://192.168.110.1:5000/rootDesc.xml"), Protocols{SSDP: true},
			[]string{"passive_ssdp mac=00:00:5e:00:01:01 ip=192.168.110.1 location=http://192.168.110.1:5000/rootDesc.xml " +
				"nt=urn:schemas-upnp-org:device:InternetGatewayDevice:1 server=Linux/4.14 UPnP/1.0 MiniUPnPd/2.1 ssdp=notify uuid=2fac1234-31f8-11b4-a222-08002b34c003"}},
		{"ssdp service type says nothing more", frames.SSDPNotify(router, gateway, "urn:schemas-upnp-org:service:WANIPConnection:1",
			"uuid:x::urn:schemas-upnp-org:service:WANIPConnection:1", "Linux", "http://192.168.110.1:5000/rootDesc.xml"), Protocols{SSDP: true}, nil},
		{"ssdp answer to a search", frames.SSDPResponse(cam, hmi, camIP, hmiIP, "upnp:rootdevice", "uuid:cam-1::upnp:rootdevice",
			"Linux/3.10 UPnP/1.0 HIKVISION", "http://192.168.110.40:49152/desc.xml"), Protocols{SSDP: true},
			[]string{"passive_ssdp mac=44:19:b6:00:00:40 ip=192.168.110.40 location=http://192.168.110.40:49152/desc.xml nt=upnp:rootdevice " +
				"server=Linux/3.10 UPnP/1.0 HIKVISION ssdp=response uuid=cam-1"}},
		{"ssdp byebye", rawUDP(router, frames.SSDPv4, gateway, "239.255.255.250", 1900, 1900,
			"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nNTS: ssdp:byebye\r\nUSN: uuid:x::upnp:rootdevice\r\n\r\n"),
			Protocols{SSDP: true}, nil},
		{"ssdp search", rawUDP(hmi, frames.SSDPv4, hmiIP, "239.255.255.250", 50000, 1900,
			"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"), Protocols{SSDP: true}, nil},

		// WS-Discovery.
		{"wsd onvif camera hello", frames.WSDHello(cam, camIP, "urn:uuid:4419b600-0040-4419-b600-4419b6000040", "dn:NetworkVideoTransmitter tds:Device",
			onvifScopes, "http://192.168.110.40/onvif/device_service http://[fe80::4619:b6ff:fe00:40]/onvif/device_service"), All,
			[]string{"passive_wsd mac=44:19:b6:00:00:40 ip=192.168.110.40 endpoint=urn:uuid:4419b600-0040-4419-b600-4419b6000040 " +
				"onvif_hardware=DS-2CD2143G0-I onvif_name=HIKVISION Camera onvif_types=video_encoder,Network_Video_Transmitter " +
				"types=NetworkVideoTransmitter,Device wsd=hello xaddr=http://192.168.110.40/onvif/device_service"}},
		{"wsd printer hello", frames.WSDHello(hmi, hmiIP, "urn:uuid:printer-1", "wsdp:Device wprt:PrintDeviceType", "", "http://192.168.110.20:5357/"),
			Protocols{WSD: true},
			[]string{"passive_wsd mac=00:0e:8c:11:22:33 ip=192.168.110.20 endpoint=urn:uuid:printer-1 types=Device,PrintDeviceType wsd=hello " +
				"xaddr=http://192.168.110.20:5357/"}},
		{"wsd probe matches: the first", frames.WSD(cam, camIP, "ProbeMatches", `<d:ProbeMatches>`+
			`<d:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:first</a:Address></a:EndpointReference><d:Types>dn:NetworkVideoTransmitter</d:Types></d:ProbeMatch>`+
			`<d:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:second</a:Address></a:EndpointReference><d:Types>wprt:PrintDeviceType</d:Types></d:ProbeMatch>`+
			`</d:ProbeMatches>`), Protocols{WSD: true},
			[]string{"passive_wsd mac=44:19:b6:00:00:40 ip=192.168.110.40 endpoint=urn:uuid:first types=NetworkVideoTransmitter wsd=probe_match"}},
		{"wsd bye", frames.WSD(cam, camIP, "Bye", `<d:Bye><a:EndpointReference><a:Address>urn:uuid:x</a:Address></a:EndpointReference></d:Bye>`),
			Protocols{WSD: true}, nil},
		{"wsd probe", frames.WSD(hmi, hmiIP, "Probe", `<d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>`), Protocols{WSD: true}, nil},
		{"wsd malformed", rawUDP(cam, frames.SSDPv4, camIP, "239.255.255.250", 3702, 3702, "<s:Envelope><s:Body><d:Hel"), Protocols{WSD: true}, nil},
		{"wsd too large", rawUDP(cam, frames.SSDPv4, camIP, "239.255.255.250", 3702, 3702,
			`<Envelope><Body><Hello><Types>`+strings.Repeat("x", maxWSD)+`</Types></Hello></Body></Envelope>`), Protocols{WSD: true}, nil},
		{"wsd disabled", frames.WSDHello(cam, camIP, "urn:uuid:x", "dn:NetworkVideoTransmitter", "", ""), Protocols{SSDP: true}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summaries(Decode(tt.p, t0, "eth1", tt.frame))
			if !slices.Equal(got, tt.want) {
				t.Errorf("got\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(tt.want, "\n  "))
			}
		})
	}
}

// Malformed NetBIOS, CDP and SSDP payloads are dropped, never trusted.
func TestDecodeDiscoveryMalformed(t *testing.T) {
	name := frames.NetBIOSName("HOST", 0)
	tests := []struct {
		name   string
		decode func(f *frame)
	}{
		{"nbns short", func(f *frame) { f.nbns(addr("192.168.110.20"), []byte{1, 2, 3}) }},
		{"nbns bad name letters", func(f *frame) {
			b := append([]byte{0, 0, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1, 32}, strings.Repeat("Z", 32)...)
			f.nbns(addr("192.168.110.20"), append(b, 0))
		}},
		{"nbns forward pointer", func(f *frame) {
			f.nbns(addr("192.168.110.20"), []byte{0, 0, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1, 0xc0, 0x20})
		}},
		{"nbns truncated record", func(f *frame) {
			b := append([]byte{0, 0, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1}, name...)
			f.nbns(addr("192.168.110.20"), append(b, 0, 0x20, 0, 1, 0xc0, 0x0c, 0, 0x20))
		}},
		{"nbns scope label past the end", func(f *frame) {
			b := append([]byte{0, 0, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1}, name[:33]...)
			f.nbns(addr("192.168.110.20"), append(b, 9, 'x'))
		}},
		{"datagram from a group name, not an smb", func(f *frame) {
			group := frames.NetBIOSName("PLANT", 0x1e)
			b := []byte{0x11, 2, 0, 1, 192, 168, 110, 20, 0, 138, 0, 0, 0, 0}
			b = append(append(b, group...), group...)
			f.nbDatagram(addr("192.168.110.20"), append(b, "nonsense"...))
		}},
		{"cdp tlv past the end", func(f *frame) {
			f.cdp([]byte{0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20, 0, 2, 180, 0, 0, 0, 1, 0, 40, 's', 'w'})
		}},
		{"cdp short tlv length", func(f *frame) {
			f.cdp([]byte{0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20, 0, 2, 180, 0, 0, 0, 1, 0, 2})
		}},
		{"cdp bad version", func(f *frame) {
			f.cdp([]byte{0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20, 0, 9, 180, 0, 0, 0, 1, 0, 6, 's', 'w'})
		}},
		{"ssdp not http", func(f *frame) { f.ssdp(addr("192.168.110.1"), []byte("\x00\x01garbage")) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFrame()
			tt.decode(f)
			if len(f.out) != 0 {
				t.Errorf("decoded %v", summaries(f.out))
			}
		})
	}
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }
