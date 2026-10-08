package idprobe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"

	"lan-sentinel/internal/probe"
)

// SNMP is one SNMPv2c GetRequest on udp/161 (ADR 0011). Varbinds are
// only sysDescr, sysObjectID, sysName and sysServices. No walk, no set,
// no second community.
type SNMP struct {
	Community string
}

const (
	snmpPort       = 161
	snmpBudgetCost = 1
	snmpMaxRead    = 2048
	snmpVersion    = 1 // SNMPv2c
	snmpGetReq     = 0xa0
	snmpGetResp    = 0xa2
)

var (
	errSNMP        = fmt.Errorf("%w: snmp", errExchange)
	oidSysDescr    = []uint32{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidSysObjectID = []uint32{1, 3, 6, 1, 2, 1, 1, 2, 0}
	oidSysName     = []uint32{1, 3, 6, 1, 2, 1, 1, 5, 0}
	oidSysServices = []uint32{1, 3, 6, 1, 2, 1, 1, 7, 0}
)

var snmpFields = []struct {
	oid  string
	name string
	conf float64
}{
	{"1.3.6.1.2.1.1.1.0", "sysDescr", 0.9},
	{"1.3.6.1.2.1.1.2.0", "sysObjectID", 0.95},
	{"1.3.6.1.2.1.1.5.0", "sysName", 0.8},
	{"1.3.6.1.2.1.1.7.0", "sysServices", 0.7},
}

// Name implements Probe.
func (SNMP) Name() string { return "snmp" }

// Protocol implements Probe.
func (SNMP) Protocol() probe.Protocol { return probe.UDP }

// Port implements Probe.
func (SNMP) Port() uint16 { return snmpPort }

// BudgetCost implements Probe.
func (SNMP) BudgetCost() int { return snmpBudgetCost }

// Limits implements Probe.
func (SNMP) Limits() Limits { return Limits{MaxWrites: 1, MaxRead: snmpMaxRead} }

// Exchange implements Probe.
func (s SNMP) Exchange(ctx context.Context, sess Session) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	community := s.Community
	if community == "" {
		return Response{}, fmt.Errorf("%w: snmp community is not configured", errExchange)
	}
	reqID := snmpRequestID()
	req := encodeSNMPGet(reqID, community, oidSysDescr, oidSysObjectID, oidSysName, oidSysServices)
	if _, err := sess.Write(req); err != nil {
		return Response{}, err
	}
	raw := make([]byte, snmpMaxRead)
	n, err := sess.Read(raw)
	if err != nil && n == 0 {
		return Response{}, err
	}
	return parseSNMP(raw[:n], reqID)
}

func snmpRequestID() int32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 1
	}
	n := int32(binary.BigEndian.Uint32(b[:]) & 0x7fffffff)
	if n == 0 {
		return 1
	}
	return n
}

func encodeSNMPGet(reqID int32, community string, oids ...[]uint32) []byte {
	var binds []byte
	for _, oid := range oids {
		binds = append(binds, berSeq(0x30, berOID(oid), []byte{0x05, 0x00})...)
	}
	pdu := berSeq(snmpGetReq, berInt(int64(reqID)), berInt(0), berInt(0), berSeq(0x30, binds))
	return berSeq(0x30, berInt(snmpVersion), berOctet(community), pdu)
}

func parseSNMP(raw []byte, reqID int32) (Response, error) {
	tag, val, _, ok := berTLV(raw)
	if !ok || tag != 0x30 {
		return Response{}, fmt.Errorf("%w: message", errSNMP)
	}
	_, val, ok = skipTLV(val) // version
	if !ok {
		return Response{}, fmt.Errorf("%w: version", errSNMP)
	}
	_, val, ok = skipTLV(val) // community
	if !ok {
		return Response{}, fmt.Errorf("%w: community", errSNMP)
	}
	tag, pdu, _, ok := berTLV(val)
	if !ok || (tag != snmpGetResp && tag != snmpGetReq) {
		return Response{}, fmt.Errorf("%w: pdu", errSNMP)
	}
	idb, pdu, ok := takeTLV(pdu, 0x02)
	if !ok {
		return Response{}, fmt.Errorf("%w: request-id", errSNMP)
	}
	got, ok := berParseInt(idb)
	if !ok || int32(got) != reqID { //nolint:gosec
		return Response{}, fmt.Errorf("%w: request-id", errSNMP)
	}
	_, pdu, ok = skipTLV(pdu) // error-status
	if !ok {
		return Response{}, fmt.Errorf("%w: error-status", errSNMP)
	}
	_, pdu, ok = skipTLV(pdu) // error-index
	if !ok {
		return Response{}, fmt.Errorf("%w: error-index", errSNMP)
	}
	tag, list, _, ok := berTLV(pdu)
	if !ok || tag != 0x30 {
		return Response{}, fmt.Errorf("%w: varbinds", errSNMP)
	}
	ident := map[string]string{}
	conf := map[string]float64{}
	for len(list) > 0 {
		tag, bind, rest, ok := berTLV(list)
		if !ok || tag != 0x30 {
			break
		}
		list = rest
		oidb, bind, ok := takeTLV(bind, 0x06)
		if !ok {
			continue
		}
		oid, ok := decodeOID(oidb)
		if !ok {
			continue
		}
		vtag, vval, _, ok := berTLV(bind)
		if !ok {
			continue
		}
		text := snmpValue(vtag, vval)
		if text == "" {
			continue
		}
		for _, f := range snmpFields {
			if f.oid == oid {
				ident[f.name] = text
				conf[f.name] = f.conf
			}
		}
	}
	if len(ident) == 0 {
		return Response{}, fmt.Errorf("%w: no varbinds", errSNMP)
	}
	return Response{Identity: ident, Confidence: conf}, nil
}

func snmpValue(tag byte, val []byte) string {
	switch tag {
	case 0x04: // OCTET STRING
		return sanitize(val)
	case 0x06: // OID
		if s, ok := decodeOID(val); ok {
			return s
		}
	case 0x02: // INTEGER
		if n, ok := berParseInt(val); ok {
			return strconv.FormatInt(n, 10)
		}
	}
	return ""
}

func berSeq(tag byte, parts ...[]byte) []byte {
	var inner []byte
	for _, p := range parts {
		inner = append(inner, p...)
	}
	return append(append([]byte{tag}, berLen(len(inner))...), inner...)
}

func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp [8]byte
	i := 8
	for n > 0 {
		i--
		tmp[i] = byte(n)
		n >>= 8
	}
	out := make([]byte, 1+8-i)
	out[0] = 0x80 | byte(8-i)
	copy(out[1:], tmp[i:])
	return out
}

func berInt(n int64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(n))
	start := 0
	if n >= 0 {
		for start < 7 && buf[start] == 0 && buf[start+1]&0x80 == 0 {
			start++
		}
	} else {
		for start < 7 && buf[start] == 0xff && buf[start+1]&0x80 != 0 {
			start++
		}
	}
	return append([]byte{0x02, byte(8 - start)}, buf[start:]...)
}

func berOctet(s string) []byte {
	return append(append([]byte{0x04}, berLen(len(s))...), s...)
}

func berOID(oid []uint32) []byte {
	if len(oid) < 2 {
		return []byte{0x06, 0}
	}
	payload := []byte{byte(oid[0]*40 + oid[1])}
	for _, c := range oid[2:] {
		payload = append(payload, berBase128(c)...)
	}
	return append(append([]byte{0x06}, berLen(len(payload))...), payload...)
}

func berBase128(n uint32) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp [5]byte
	tmp[4] = byte(n & 0x7f)
	n >>= 7
	i := 4
	for n > 0 {
		i--
		tmp[i] = 0x80 | byte(n&0x7f)
		n >>= 7
	}
	return tmp[i:]
}

func berTLV(b []byte) (tag byte, val, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, b, false
	}
	tag = b[0]
	n, hdr, ok := berParseLen(b[1:])
	if !ok || n < 0 || 1+hdr+n > len(b) {
		return 0, nil, b, false
	}
	return tag, b[1+hdr : 1+hdr+n], b[1+hdr+n:], true
}

func berParseLen(b []byte) (n, hdr int, ok bool) {
	if len(b) < 1 {
		return 0, 0, false
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, true
	}
	c := int(b[0] & 0x7f)
	if c == 0 || c > 4 || 1+c > len(b) {
		return 0, 0, false
	}
	n = 0
	for i := 0; i < c; i++ {
		n = n<<8 | int(b[1+i])
	}
	if n < 0 {
		return 0, 0, false
	}
	return n, 1 + c, true
}

func skipTLV(b []byte) ([]byte, []byte, bool) {
	_, _, rest, ok := berTLV(b)
	return nil, rest, ok
}

func takeTLV(b []byte, want byte) ([]byte, []byte, bool) {
	tag, val, rest, ok := berTLV(b)
	if !ok || tag != want {
		return nil, b, false
	}
	return val, rest, true
}

func berParseInt(b []byte) (int64, bool) {
	if len(b) == 0 || len(b) > 8 {
		return 0, false
	}
	var n int64
	for _, c := range b {
		n = n<<8 | int64(c)
	}
	if b[0]&0x80 != 0 && len(b) < 8 {
		n |= int64(-1) << (8 * len(b)) // sign extend
	}
	return n, true
}

func decodeOID(b []byte) (string, bool) {
	if len(b) < 1 {
		return "", false
	}
	parts := []string{strconv.Itoa(int(b[0] / 40)), strconv.Itoa(int(b[0] % 40))}
	var n uint32
	for i := 1; i < len(b); i++ {
		n = n<<7 | uint32(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			parts = append(parts, strconv.FormatUint(uint64(n), 10))
			n = 0
			continue
		}
		if i == len(b)-1 {
			return "", false
		}
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "." + p
	}
	return out, true
}
