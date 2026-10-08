package idprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"lan-sentinel/internal/probe"
)

// Modbus is Read Device Identification, FC 43/14 basic stream (ADR 0011).
// One initial request plus at most four continuation requests. These are
// continuation requests, not register reads.
type Modbus struct {
	UnitID uint8
}

const (
	modbusFC          = 0x2b
	modbusMEI         = 0x0e
	modbusReadBasic   = 0x01
	modbusMaxADU      = 260
	modbusMaxWrites   = 5 // initial + 4 continuations
	modbusBudgetCost  = 8 // 3 TCP + 5 writes
	modbusPort        = 502
	modbusObjVendor   = 0x00
	modbusObjProduct  = 0x01
	modbusObjRevision = 0x02
	modbusConfidence  = 0.95
)

var errModbus = errors.New("modbus device identification rejected")

// Name implements Probe.
func (Modbus) Name() string { return "modbus" }

// Protocol implements Probe.
func (Modbus) Protocol() probe.Protocol { return probe.TCP }

// Port implements Probe.
func (Modbus) Port() uint16 { return modbusPort }

// BudgetCost implements Probe.
func (Modbus) BudgetCost() int { return modbusBudgetCost }

// Limits implements Probe.
func (Modbus) Limits() Limits {
	return Limits{MaxWrites: modbusMaxWrites, MaxRead: modbusMaxADU * modbusMaxWrites}
}

// Exchange implements Probe.
func (m Modbus) Exchange(ctx context.Context, s Session) (Response, error) {
	unit := m.UnitID
	if unit == 0 {
		unit = 1
	}
	var (
		tid   uint16 = 1
		obj   byte
		ident = map[string]string{}
		conf  = map[string]float64{}
	)
	for n := 0; n < modbusMaxWrites; n++ {
		if err := ctx.Err(); err != nil {
			return Response{}, err
		}
		req := encodeDeviceID(tid, unit, obj)
		if _, err := s.Write(req); err != nil {
			return Response{}, err
		}
		adu, err := readADU(s)
		if err != nil {
			return Response{}, err
		}
		more, next, err := parseDeviceID(adu, tid, unit, ident)
		if err != nil {
			return Response{}, err
		}
		tid++
		if !more {
			break
		}
		obj = next
	}
	if len(ident) == 0 {
		return Response{}, fmt.Errorf("%w: no identification objects", errModbus)
	}
	for f := range ident {
		conf[f] = modbusConfidence
	}
	return Response{Identity: ident, Confidence: conf}, nil
}

func encodeDeviceID(tid uint16, unit, obj byte) []byte {
	req := make([]byte, 11)
	binary.BigEndian.PutUint16(req[0:2], tid)
	binary.BigEndian.PutUint16(req[4:6], 5) // unit + PDU
	req[6] = unit
	req[7] = modbusFC
	req[8] = modbusMEI
	req[9] = modbusReadBasic
	req[10] = obj
	return req
}

func readADU(s Session) ([]byte, error) {
	hdr := make([]byte, 7)
	if _, err := io.ReadFull(s, hdr); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[4:6]))
	if n < 1 || n > modbusMaxADU-6 {
		return nil, fmt.Errorf("%w: length %d", errModbus, n)
	}
	adu := make([]byte, 6+n)
	copy(adu, hdr)
	if _, err := io.ReadFull(s, adu[7:]); err != nil {
		return nil, err
	}
	if len(adu) > modbusMaxADU {
		return nil, fmt.Errorf("%w: ADU %d bytes", errModbus, len(adu))
	}
	return adu, nil
}

func parseDeviceID(adu []byte, tid uint16, unit byte, ident map[string]string) (more bool, next byte, err error) {
	if len(adu) < 8 {
		return false, 0, fmt.Errorf("%w: short ADU", errModbus)
	}
	if binary.BigEndian.Uint16(adu[0:2]) != tid {
		return false, 0, fmt.Errorf("%w: transaction id", errModbus)
	}
	if binary.BigEndian.Uint16(adu[2:4]) != 0 {
		return false, 0, fmt.Errorf("%w: protocol id", errModbus)
	}
	if adu[6] != unit {
		return false, 0, fmt.Errorf("%w: unit id", errModbus)
	}
	if adu[7] == modbusFC+0x80 {
		return false, 0, fmt.Errorf("%w: exception", errModbus)
	}
	if adu[7] != modbusFC {
		return false, 0, fmt.Errorf("%w: function", errModbus)
	}
	if len(adu) < 14 {
		return false, 0, fmt.Errorf("%w: short PDU", errModbus)
	}
	if adu[8] != modbusMEI {
		return false, 0, fmt.Errorf("%w: MEI", errModbus)
	}
	// adu[9] is the echoed Read Device ID code; adu[10] conformity.
	more = adu[11] != 0
	next = adu[12]
	count := int(adu[13])
	p := 14
	for i := 0; i < count; i++ {
		if p+2 > len(adu) {
			return false, 0, fmt.Errorf("%w: truncated objects", errModbus)
		}
		id, n := adu[p], int(adu[p+1])
		p += 2
		if p+n > len(adu) {
			return false, 0, fmt.Errorf("%w: truncated object value", errModbus)
		}
		val := sanitize(adu[p : p+n])
		p += n
		if field := objectField(id); field != "" && val != "" {
			ident[field] = val
		}
	}
	return more, next, nil
}

func objectField(id byte) string {
	switch id {
	case modbusObjVendor:
		return "vendor"
	case modbusObjProduct:
		return "product"
	case modbusObjRevision:
		return "revision"
	}
	return ""
}

func sanitize(b []byte) string {
	s := string(b)
	if !utf8.ValidString(s) {
		return ""
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r < 32 || r == 127 {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
