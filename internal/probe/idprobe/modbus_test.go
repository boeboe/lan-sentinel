package idprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

type memSession struct {
	in     []byte
	off    int
	writes [][]byte
	maxW   int
}

func (s *memSession) Write(p []byte) (int, error) {
	if s.maxW > 0 && len(s.writes) >= s.maxW {
		return 0, ErrLimit
	}
	s.writes = append(s.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (s *memSession) Read(p []byte) (int, error) {
	if s.off >= len(s.in) {
		return 0, io.EOF
	}
	n := copy(p, s.in[s.off:])
	s.off += n
	return n, nil
}

func object(id byte, val string) []byte {
	return append([]byte{id, byte(len(val))}, val...)
}

func deviceIDReply(tid uint16, unit byte, more bool, next byte, objects ...[]byte) []byte {
	pdu := []byte{modbusFC, modbusMEI, modbusReadBasic, 0x01, 0, next, byte(len(objects))}
	if more {
		pdu[4] = 0xff
	}
	for _, o := range objects {
		pdu = append(pdu, o...)
	}
	adu := make([]byte, 7+len(pdu))
	binary.BigEndian.PutUint16(adu[0:2], tid)
	binary.BigEndian.PutUint16(adu[4:6], uint16(1+len(pdu))) //nolint:gosec
	adu[6] = unit
	copy(adu[7:], pdu)
	return adu
}

func TestModbusBasicStream(t *testing.T) {
	reply := deviceIDReply(1, 1, false, 0,
		object(modbusObjVendor, "ACME"),
		object(modbusObjProduct, "PLC-1"),
		object(modbusObjRevision, "1.2"),
	)
	s := &memSession{in: reply}
	r, err := (Modbus{UnitID: 1}).Exchange(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if r.Identity["vendor"] != "ACME" || r.Identity["product"] != "PLC-1" || r.Identity["revision"] != "1.2" {
		t.Errorf("identity = %v", r.Identity)
	}
	if r.Confidence["vendor"] != 0.95 || len(s.writes) != 1 {
		t.Errorf("confidence = %v writes = %d", r.Confidence, len(s.writes))
	}
}

func TestModbusContinuation(t *testing.T) {
	first := deviceIDReply(1, 1, true, modbusObjProduct, object(modbusObjVendor, "ACME"))
	second := deviceIDReply(2, 1, false, 0, object(modbusObjProduct, "PLC-1"))
	s := &memSession{in: append(first, second...)}
	r, err := (Modbus{UnitID: 1}).Exchange(context.Background(), s)
	if err != nil || r.Identity["vendor"] != "ACME" || r.Identity["product"] != "PLC-1" {
		t.Fatalf("r = %+v err = %v", r, err)
	}
	if len(s.writes) != 2 {
		t.Errorf("writes = %d, want 2", len(s.writes))
	}
}

func TestParseDeviceIDRejects(t *testing.T) {
	ok := deviceIDReply(1, 1, false, 0, object(modbusObjVendor, "ACME"))
	tests := []struct {
		name string
		adu  []byte
		want string
	}{
		{"transaction id", func() []byte { b := bytes.Clone(ok); binary.BigEndian.PutUint16(b[0:2], 9); return b }(), "transaction id"},
		{"protocol id", func() []byte { b := bytes.Clone(ok); binary.BigEndian.PutUint16(b[2:4], 1); return b }(), "protocol id"},
		{"function", func() []byte { b := bytes.Clone(ok); b[7] = 0x03; return b }(), "function"},
		{"mei", func() []byte { b := bytes.Clone(ok); b[8] = 0x0d; return b }(), "MEI"},
		{"unit id", func() []byte { b := bytes.Clone(ok); b[6] = 2; return b }(), "unit id"},
		{"exception", func() []byte { b := bytes.Clone(ok); b[7] = modbusFC + 0x80; return b }(), "exception"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ident := map[string]string{}
			_, _, err := parseDeviceID(tt.adu, 1, 1, ident)
			if err == nil || !errors.Is(err, errModbus) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %s", err, tt.want)
			}
		})
	}
}

func TestReadADURejectsOversize(t *testing.T) {
	hdr := make([]byte, 7)
	binary.BigEndian.PutUint16(hdr[4:6], 255) // 6+255 > 260
	s := &memSession{in: hdr}
	_, err := readADU(s)
	if err == nil || !errors.Is(err, errModbus) {
		t.Errorf("err = %v", err)
	}
}

func TestModbusBudgetAndLimits(t *testing.T) {
	m := Modbus{}
	if m.BudgetCost() != 8 || m.Port() != 502 || m.Name() != "modbus" {
		t.Errorf("modbus = %+v cost %d", m, m.BudgetCost())
	}
	lim := m.Limits()
	if lim.MaxWrites != 5 {
		t.Errorf("MaxWrites = %d", lim.MaxWrites)
	}
}
