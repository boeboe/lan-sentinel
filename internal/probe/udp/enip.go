package udp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// ENIP is the EtherNet/IP ListIdentity probe (UDP 44818, CIP Vol. 2): an
// encapsulation header with command 0x0063 and a random sender context,
// which the reply echoes. The CIP Identity item gives the device's own
// account of what it is: vendor ID, device type, product code, revision,
// status, serial number, product name and state. Identity: product and
// device type; the raw fields are details.
type ENIP struct{}

// Name implements Prober.
func (ENIP) Name() string { return "enip" }

// Port implements Prober.
func (ENIP) Port() uint16 { return 44818 }

const (
	enipHeaderLen    = 24
	enipListIdentity = 0x0063
	cipIdentityItem  = 0x000c
	// identityFixed is the CIP Identity item up to the product name:
	// protocol version (2), socket address (16), vendor ID, device type,
	// product code (2 each), revision (2), status (2), serial number (4).
	identityFixed = 2 + 16 + 2 + 2 + 2 + 2 + 2 + 4
)

// Request implements Prober.
func (ENIP) Request() ([]byte, error) {
	req := make([]byte, enipHeaderLen)
	binary.LittleEndian.PutUint16(req[0:2], enipListIdentity)
	if _, err := rand.Read(req[12:20]); err != nil {
		return nil, fmt.Errorf("enip request: %w", err)
	}
	return req, nil
}

// Parse implements Prober.
func (ENIP) Parse(req, reply []byte) (Response, bool) {
	if len(req) < enipHeaderLen || len(reply) < enipHeaderLen+2 {
		return Response{}, false
	}
	le := binary.LittleEndian
	length := int(le.Uint16(reply[2:4]))
	if le.Uint16(reply[0:2]) != enipListIdentity || le.Uint32(reply[8:12]) != 0 ||
		string(reply[12:20]) != string(req[12:20]) || len(reply) < enipHeaderLen+length {
		return Response{}, false
	}
	data := reply[enipHeaderLen : enipHeaderLen+length]
	if len(data) < 2 {
		return Response{}, false
	}
	count, data := int(le.Uint16(data)), data[2:]
	for range count {
		if len(data) < 4 {
			return Response{}, false
		}
		typ, n := le.Uint16(data), int(le.Uint16(data[2:]))
		if len(data) < 4+n {
			return Response{}, false
		}
		item := data[4 : 4+n]
		data = data[4+n:]
		if typ == cipIdentityItem {
			return parseIdentity(item)
		}
	}
	return Response{}, false
}

func parseIdentity(b []byte) (Response, bool) {
	if len(b) < identityFixed+1 {
		return Response{}, false
	}
	le := binary.LittleEndian
	nameLen := int(b[identityFixed])
	if len(b) < identityFixed+1+nameLen {
		return Response{}, false
	}
	vendor, devType, product := le.Uint16(b[18:]), le.Uint16(b[20:]), le.Uint16(b[22:])
	name := printable(b[identityFixed+1 : identityFixed+1+nameLen])
	d := map[string]string{
		"vendor_id":     strconv.Itoa(int(vendor)),
		"device_type":   strconv.Itoa(int(devType)),
		"product_code":  strconv.Itoa(int(product)),
		"revision":      fmt.Sprintf("%d.%d", b[24], b[25]),
		"status":        fmt.Sprintf("0x%04x", le.Uint16(b[26:])),
		"serial_number": fmt.Sprintf("0x%08x", le.Uint32(b[28:])),
		"product_name":  name,
	}
	if i := identityFixed + 1 + nameLen; len(b) > i {
		d["state"] = strconv.Itoa(int(b[i]))
	}
	id := map[string]string{"device_type": DeviceType(devType)}
	if name != "" {
		id["product"] = name
	}
	return Response{Details: d, Identity: id}, true
}

// printable keeps the printable ASCII of a device-supplied string.
func printable(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e {
			s.WriteByte(c)
		}
	}
	return strings.TrimSpace(s.String())
}

// cipDeviceTypes names common CIP device profiles.
var cipDeviceTypes = map[uint16]string{
	0x00: "Generic Device",
	0x02: "AC Drive",
	0x03: "Motor Overload",
	0x07: "General Purpose Discrete I/O",
	0x0c: "Communications Adapter",
	0x0e: "Programmable Logic Controller",
	0x13: "DC Drive",
	0x18: "Human-Machine Interface",
	0x2b: "Generic Device (keyable)",
}

// DeviceType names a CIP device type.
func DeviceType(t uint16) string {
	if s, ok := cipDeviceTypes[t]; ok {
		return s
	}
	return fmt.Sprintf("CIP device type 0x%02x", t)
}
