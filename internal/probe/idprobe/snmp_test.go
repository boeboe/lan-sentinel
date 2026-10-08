package idprobe

import (
	"context"
	"errors"
	"testing"
)

func snmpGetResponse(reqID int32, community string) []byte {
	descr := berSeq(0x30, berOID(oidSysDescr), berOctet("ACME PLC"))
	obj := berSeq(0x30, berOID(oidSysObjectID), berOID([]uint32{1, 3, 6, 1, 4, 1, 999}))
	name := berSeq(0x30, berOID(oidSysName), berOctet("line-1"))
	svc := berSeq(0x30, berOID(oidSysServices), berInt(72))
	binds := berSeq(0x30, descr, obj, name, svc)
	pdu := berSeq(snmpGetResp, berInt(int64(reqID)), berInt(0), berInt(0), binds)
	return berSeq(0x30, berInt(snmpVersion), berOctet(community), pdu)
}

func TestSNMPParse(t *testing.T) {
	r, err := parseSNMP(snmpGetResponse(1, "public"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if r.Identity["sysDescr"] != "ACME PLC" || r.Identity["sysName"] != "line-1" ||
		r.Identity["sysObjectID"] != "1.3.6.1.4.1.999" || r.Identity["sysServices"] != "72" {
		t.Errorf("identity = %v", r.Identity)
	}
	if r.Confidence["sysObjectID"] != 0.95 || r.Confidence["sysDescr"] != 0.9 {
		t.Errorf("confidence = %v", r.Confidence)
	}
}

func TestSNMPExchangeWritesOnce(t *testing.T) {
	s := &memSession{in: snmpGetResponse(1, "public")}
	_, _ = (SNMP{Community: "public"}).Exchange(context.Background(), s)
	if len(s.writes) != 1 || len(s.writes[0]) < 10 {
		t.Fatalf("writes = %d", len(s.writes))
	}
	tag, _, _, ok := berTLV(s.writes[0])
	if !ok || tag != 0x30 {
		t.Errorf("request tag = %d ok = %v", tag, ok)
	}
}

func TestSNMPRequiresCommunity(t *testing.T) {
	_, err := (SNMP{}).Exchange(context.Background(), &memSession{})
	if !errors.Is(err, errExchange) {
		t.Errorf("empty community = %v", err)
	}
}

func TestSNMPRejects(t *testing.T) {
	if _, err := parseSNMP(nil, 1); !errors.Is(err, errSNMP) {
		t.Errorf("empty = %v", err)
	}
	if _, err := parseSNMP(snmpGetResponse(99, "public"), 1); !errors.Is(err, errSNMP) {
		t.Errorf("reqid = %v", err)
	}
}
