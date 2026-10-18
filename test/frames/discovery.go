package frames

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/gopacket/gopacket"
)

// More well-known destination MACs.
var (
	CDPDst = MAC("01:00:0c:cc:cc:cc")
	SSDPv4 = MAC("01:00:5e:7f:ff:fa") // 239.255.255.250: SSDP and WS-Discovery
)

// NetBIOSName encodes a NetBIOS name (RFC 1001 §14.1): the name padded with
// spaces to 15 characters, the suffix byte, first-level encoded, no scope.
func NetBIOSName(name string, suffix byte) []byte {
	raw := []byte(fmt.Sprintf("%-15.15s", name))
	raw = append(raw, suffix)
	out := []byte{32}
	for _, c := range raw {
		out = append(out, 'A'+c>>4, 'A'+c&0xf)
	}
	return append(out, 0)
}

func nbRecord(flags uint16, ip string) []byte {
	b := binary.BigEndian.AppendUint16(nil, flags)
	return append(b, netip.MustParseAddr(ip).AsSlice()...)
}

// NBNSRegistration builds the broadcast registration of a NetBIOS name for
// ip (a group name when group is set), from UDP 137 to 137 (RFC 1002
// §4.2.2): opcode 5, one question and the NB record as additional record.
func NBNSRegistration(mac net.HardwareAddr, ip, name string, suffix byte, group bool) []byte {
	msg := []byte{0x12, 0x34, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1} // id; register, RD, B; QD 1, AR 1
	msg = append(msg, NetBIOSName(name, suffix)...)
	msg = append(msg, 0, 0x20, 0, 1)                                        // NB, IN
	msg = append(msg, 0xc0, 0x0c, 0, 0x20, 0, 1, 0, 0x04, 0x93, 0xe0, 0, 6) // the question's name, NB, IN, TTL, length
	flags := uint16(0)
	if group {
		flags = 0x8000
	}
	msg = append(msg, nbRecord(flags, ip)...)
	return UDP4(mac, Broadcast, ip, "255.255.255.255", 137, 137, gopacket.Payload(msg))
}

// NBNSAnswer builds a positive answer to a NetBIOS name query giving name
// the address addr, from UDP 137 of ip to dst (RFC 1002 §4.2.13).
func NBNSAnswer(mac, dstMAC net.HardwareAddr, ip, dst, name string, suffix byte, addr string) []byte {
	msg := []byte{0x56, 0x78, 0x85, 0x00, 0, 0, 0, 1, 0, 0, 0, 0} // id; response, AA, RD; AN 1
	msg = append(msg, NetBIOSName(name, suffix)...)
	msg = append(msg, 0, 0x20, 0, 1, 0, 0x04, 0x93, 0xe0, 0, 6)
	msg = append(msg, nbRecord(0, addr)...)
	return UDP4(mac, dstMAC, ip, dst, 137, 137, gopacket.Payload(msg))
}

// Browser describes a browser announcement ([MS-BRWS] §2.2.1) in a NetBIOS
// datagram to the \MAILSLOT\BROWSE mailslot.
type Browser struct {
	Source     net.HardwareAddr
	IP         string
	Name       string // the sender's NetBIOS name: the datagram's source name
	Workgroup  string // the destination group, and the name a workgroup announcement announces
	Opcode     byte   // 0x01 host, 0x0f local master, 0x0c workgroup announcement
	OSMajor    byte
	OSMinor    byte
	ServerType uint32
	Comment    string
	HeaderIP   string // the datagram header's source address; empty: IP
}

// Frame builds the datagram: header, source and destination names, then an
// SMB Transaction (17 parameter words) whose bytes are the mailslot name and
// the announcement.
func (b Browser) Frame() []byte {
	announced := b.Name
	if b.Opcode == 0x0c {
		announced = b.Workgroup
	}
	data := []byte{b.Opcode, 1, 0x60, 0xea, 0, 0} // opcode, update count, periodicity (LE)
	data = append(data, fmt.Sprintf("%-16.16s", announced)...)
	for i := len(data) - 16; i < len(data); i++ {
		if data[i] == ' ' {
			data[i] = 0 // NUL padded
		}
	}
	data = append(data, b.OSMajor, b.OSMinor)
	data = binary.LittleEndian.AppendUint32(data, b.ServerType)
	data = append(data, 15, 1, 0x55, 0xaa) // browser version, signature
	data = append(append(data, b.Comment...), 0)

	const words = 17
	mailslot := append([]byte(`\MAILSLOT\BROWSE`), 0)
	smb := make([]byte, 32)
	copy(smb, "\xffSMB")
	smb[4] = 0x25 // SMB_COM_TRANSACTION
	w := make([]byte, 2*words)
	binary.LittleEndian.PutUint16(w[2:], uint16(len(data)))                     // total data count
	binary.LittleEndian.PutUint16(w[22:], uint16(len(data)))                    // data count
	binary.LittleEndian.PutUint16(w[24:], uint16(32+1+2*words+2+len(mailslot))) // data offset
	w[26] = 3                                                                   // setup count
	binary.LittleEndian.PutUint16(w[28:], 1)                                    // mailslot write
	binary.LittleEndian.PutUint16(w[30:], 1)                                    // priority
	binary.LittleEndian.PutUint16(w[32:], 2)                                    // class 2
	smb = append(append(smb, words), w...)
	smb = binary.LittleEndian.AppendUint16(smb, uint16(len(mailslot)+len(data)))
	smb = append(append(smb, mailslot...), data...)

	headerIP := b.IP
	if b.HeaderIP != "" {
		headerIP = b.HeaderIP
	}
	body := append(NetBIOSName(b.Name, 0x00), NetBIOSName(b.Workgroup, 0x1d)...)
	body = append(body, smb...)
	dgm := []byte{0x11, 0x02, 0x00, 0x01} // direct group, first fragment, id
	dgm = append(dgm, netip.MustParseAddr(headerIP).AsSlice()...)
	dgm = binary.BigEndian.AppendUint16(dgm, 138)
	dgm = binary.BigEndian.AppendUint16(dgm, uint16(len(body)))
	dgm = append(append(dgm, 0, 0), body...) // packet offset
	return UDP4(b.Source, Broadcast, b.IP, "255.255.255.255", 138, 138, gopacket.Payload(dgm))
}

// SSDPNotify builds the multicast NOTIFY ssdp:alive of a device for nt,
// from an ephemeral port as many devices send it (UDA 2.0 §1.2.2).
func SSDPNotify(mac net.HardwareAddr, ip, nt, usn, server, location string) []byte {
	msg := "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: " + location +
		"\r\nNT: " + nt + "\r\nNTS: ssdp:alive\r\nSERVER: " + server + "\r\nUSN: " + usn + "\r\n\r\n"
	return UDP4(mac, SSDPv4, ip, "239.255.255.250", 50123, 1900, gopacket.Payload(msg))
}

// SSDPResponse builds a device's unicast answer to an M-SEARCH for st, from
// UDP 1900 (UDA 2.0 §1.3.3).
func SSDPResponse(mac, dstMAC net.HardwareAddr, ip, dst, st, usn, server, location string) []byte {
	msg := "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: " + location +
		"\r\nSERVER: " + server + "\r\nST: " + st + "\r\nUSN: " + usn + "\r\n\r\n"
	return UDP4(mac, dstMAC, ip, dst, 1900, 50123, gopacket.Payload(msg))
}

// WSD builds a WS-Discovery SOAP envelope (the 2005/04 namespaces ONVIF and
// Windows use) with action and body, multicast to 3702.
func WSD(mac net.HardwareAddr, ip, action, body string) []byte {
	msg := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"` +
		` xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl"` +
		` xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof"` +
		` xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07">` +
		`<s:Header><a:MessageID>urn:uuid:0b6f2b26-6b5e-4c39-9c6d-1f2a3b4c5d6e</a:MessageID>` +
		`<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>` +
		`<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/` + action + `</a:Action></s:Header>` +
		`<s:Body>` + body + `</s:Body></s:Envelope>`
	return UDP4(mac, SSDPv4, ip, "239.255.255.250", 3702, 3702, gopacket.Payload(msg))
}

// WSDHello builds the Hello a device multicasts when it joins.
func WSDHello(mac net.HardwareAddr, ip, endpoint, types, scopes, xaddrs string) []byte {
	return WSD(mac, ip, "Hello", `<d:Hello><a:EndpointReference><a:Address>`+endpoint+`</a:Address></a:EndpointReference>`+
		`<d:Types>`+types+`</d:Types><d:Scopes>`+scopes+`</d:Scopes><d:XAddrs>`+xaddrs+`</d:XAddrs>`+
		`<d:MetadataVersion>1</d:MetadataVersion></d:Hello>`)
}

// CDP describes a CDP advertisement.
type CDP struct {
	Source   net.HardwareAddr
	Holdtime byte
	DeviceID string
	PortID   string
	Software string
	Platform string
	Caps     uint32
	MgmtIP   string
}

// Frame builds the 802.3 LLC/SNAP frame (Cisco OUI, protocol 0x2000) with a
// version 2 CDP header and the TLVs that are set.
func (c CDP) Frame() []byte {
	pdu := []byte{2, c.Holdtime, 0, 0} // version, holdtime, checksum (not checked)
	tlv := func(t uint16, v []byte) {
		pdu = binary.BigEndian.AppendUint16(pdu, t)
		pdu = binary.BigEndian.AppendUint16(pdu, uint16(4+len(v)))
		pdu = append(pdu, v...)
	}
	if c.DeviceID != "" {
		tlv(0x0001, []byte(c.DeviceID))
	}
	if c.PortID != "" {
		tlv(0x0003, []byte(c.PortID))
	}
	if c.Caps != 0 {
		tlv(0x0004, binary.BigEndian.AppendUint32(nil, c.Caps))
	}
	if c.Software != "" {
		tlv(0x0005, []byte(c.Software))
	}
	if c.Platform != "" {
		tlv(0x0006, []byte(c.Platform))
	}
	if c.MgmtIP != "" {
		v := []byte{0, 0, 0, 1, 1, 1, 0xcc, 0, 4} // one address: NLPID IP, length 4
		tlv(0x0016, append(v, netip.MustParseAddr(c.MgmtIP).AsSlice()...))
	}
	payload := append([]byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00}, pdu...)
	frame := append(append([]byte{}, CDPDst...), c.Source...)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	frame = append(frame, payload...)
	for len(frame) < 60 { // minimum frame size; the length field excludes the padding
		frame = append(frame, 0)
	}
	return frame
}
