package idprobe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"time"
)

func testTLSCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xabc),
		Subject:      pkix.Name{CommonName: "plc", Organization: []string{"ACME"}},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{"plc.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func tlsRecord(typ byte, payload []byte) []byte {
	rec := make([]byte, 5+len(payload))
	rec[0] = typ
	rec[1], rec[2] = 0x03, 0x03
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload))) //nolint:gosec
	copy(rec[5:], payload)
	return rec
}

func tlsHandshake(typ byte, body []byte) []byte {
	msg := make([]byte, 4+len(body))
	msg[0] = typ
	putUint24(msg[1:], len(body))
	copy(msg[4:], body)
	return msg
}

func tlsServerHello(verMaj, verMin byte) []byte {
	body := make([]byte, 2+32+1+2+1)
	body[0], body[1] = verMaj, verMin
	body[35] = 0
	body[36], body[37] = 0x00, 0x2f
	return tlsHandshake(tlsHSServer, body)
}

func tlsCertificateMsg(der []byte) []byte {
	inner := make([]byte, 3+3+len(der))
	putUint24(inner, 3+len(der))
	putUint24(inner[3:], len(der))
	copy(inner[6:], der)
	return tlsHandshake(tlsHSCert, inner)
}

func TestTLSCertificate(t *testing.T) {
	der := testTLSCertDER(t)
	raw := append(tlsRecord(tlsRecordHS, tlsServerHello(0x03, 0x03)),
		tlsRecord(tlsRecordHS, tlsCertificateMsg(der))...)
	s := &memSession{in: raw}
	r, err := (TLS{}).Exchange(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if r.Identity["subject_cn"] != "plc" || r.Identity["subject_o"] != "ACME" ||
		r.Identity["san"] != "plc.local" || r.Identity["tls_version"] != "1.2" ||
		r.Identity["fingerprint"] == "" || r.Confidence["subject_o"] != 0.7 {
		t.Errorf("identity = %v conf = %v", r.Identity, r.Confidence)
	}
	if len(s.writes) != 1 {
		t.Errorf("writes = %d", len(s.writes))
	}
}

func TestTLSRejects(t *testing.T) {
	if _, err := parseTLS(tlsRecord(tlsRecordAlert, []byte{2, 40})); !errors.Is(err, errTLS) {
		t.Errorf("alert = %v", err)
	}
	hello13 := tlsRecord(tlsRecordHS, tlsServerHello(0x03, 0x04))
	if _, err := parseTLS(hello13); !errors.Is(err, errTLS) {
		t.Errorf("tls1.3 = %v", err)
	}
	if _, err := parseTLS(nil); !errors.Is(err, errTLS) {
		t.Errorf("empty = %v", err)
	}
}
