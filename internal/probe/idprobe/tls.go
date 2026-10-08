package idprobe

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"lan-sentinel/internal/probe"
)

// TLS records the peer certificate from one ClientHello on tcp/443
// (ADR 0011). No SNI, no trust validation, no completed handshake:
// one write, then parse unencrypted TLS 1.2 Certificate messages.
type TLS struct{}

const (
	tlsPort        = 443
	tlsBudgetCost  = 4 // 3 TCP + 1 write
	tlsMaxRead     = 16 << 10
	tlsConfidence  = 0.7
	tlsHSClient    = 1
	tlsHSServer    = 2
	tlsHSCert      = 11
	tlsRecordHS    = 22
	tlsRecordAlert = 21
)

var errTLS = fmt.Errorf("%w: tls", errExchange)

// Name implements Probe.
func (TLS) Name() string { return "tls" }

// Protocol implements Probe.
func (TLS) Protocol() probe.Protocol { return probe.TCP }

// Port implements Probe.
func (TLS) Port() uint16 { return tlsPort }

// BudgetCost implements Probe.
func (TLS) BudgetCost() int { return tlsBudgetCost }

// Limits implements Probe.
func (TLS) Limits() Limits { return Limits{MaxWrites: 1, MaxRead: tlsMaxRead} }

// Exchange implements Probe.
func (TLS) Exchange(ctx context.Context, s Session) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	hello, err := encodeClientHello()
	if err != nil {
		return Response{}, err
	}
	if _, err := s.Write(hello); err != nil {
		return Response{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(s, tlsMaxRead))
	if err != nil && !isBenignRead(err) {
		return Response{}, err
	}
	return parseTLS(raw)
}

func encodeClientHello() ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	suites := []uint16{0x002f, 0x0035, 0x009c, 0xc013, 0xc014, 0xc02f, 0xc030}
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, random...)
	body = append(body, 0)                                            // session_id
	body = binary.BigEndian.AppendUint16(body, uint16(len(suites)*2)) //nolint:gosec
	for _, c := range suites {
		body = binary.BigEndian.AppendUint16(body, c)
	}
	body = append(body, 1, 0) // compression null
	hs := make([]byte, 4+len(body))
	hs[0] = tlsHSClient
	putUint24(hs[1:], len(body))
	copy(hs[4:], body)
	rec := make([]byte, 5+len(hs))
	rec[0] = tlsRecordHS
	rec[1], rec[2] = 0x03, 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs))) //nolint:gosec
	copy(rec[5:], hs)
	return rec, nil
}

func parseTLS(raw []byte) (Response, error) {
	var hs []byte
	off := 0
	tlsVer := ""
	for off+5 <= len(raw) {
		typ := raw[off]
		n := int(binary.BigEndian.Uint16(raw[off+3 : off+5]))
		off += 5
		if n < 0 || off+n > len(raw) {
			break
		}
		frag := raw[off : off+n]
		off += n
		switch typ {
		case tlsRecordAlert:
			return Response{}, fmt.Errorf("%w: alert", errTLS)
		case tlsRecordHS:
			hs = append(hs, frag...)
		}
	}
	ident := map[string]string{}
	for len(hs) >= 4 {
		mlen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if 4+mlen > len(hs) {
			break
		}
		msg, rest := hs[:4+mlen], hs[4+mlen:]
		hs = rest
		switch msg[0] {
		case tlsHSServer:
			if len(msg) >= 6 {
				tlsVer = tlsVersionName(msg[4], msg[5])
				if msg[4] == 0x03 && msg[5] == 0x04 {
					return Response{}, fmt.Errorf("%w: tls 1.3 encrypts the certificate", errTLS)
				}
			}
		case tlsHSCert:
			if err := certClaims(msg[4:], ident); err != nil {
				return Response{}, err
			}
		}
	}
	if ident["fingerprint"] == "" {
		return Response{}, fmt.Errorf("%w: no certificate", errTLS)
	}
	if tlsVer != "" {
		ident["tls_version"] = tlsVer
	}
	conf := map[string]float64{}
	for f := range ident {
		conf[f] = tlsConfidence
	}
	return Response{Identity: ident, Confidence: conf}, nil
}

func certClaims(p []byte, ident map[string]string) error {
	if len(p) < 3 {
		return fmt.Errorf("%w: short certificate list", errTLS)
	}
	total := int(p[0])<<16 | int(p[1])<<8 | int(p[2])
	p = p[3:]
	if total > len(p) {
		p = p[:min(total, len(p))]
	}
	if len(p) < 3 {
		return fmt.Errorf("%w: empty certificate list", errTLS)
	}
	n := int(p[0])<<16 | int(p[1])<<8 | int(p[2])
	p = p[3:]
	if n <= 0 || n > len(p) {
		return fmt.Errorf("%w: truncated certificate", errTLS)
	}
	cert, err := x509.ParseCertificate(p[:n])
	if err != nil {
		return fmt.Errorf("%w: %w", errTLS, err)
	}
	if cn := sanitize([]byte(cert.Subject.CommonName)); cn != "" {
		ident["subject_cn"] = cn
	}
	if o := firstOrg(cert.Subject.Organization); o != "" {
		ident["subject_o"] = o
	}
	if cn := sanitize([]byte(cert.Issuer.CommonName)); cn != "" {
		ident["issuer_cn"] = cn
	}
	if o := firstOrg(cert.Issuer.Organization); o != "" {
		ident["issuer_o"] = o
	}
	if sans := cert.DNSNames; len(sans) > 0 {
		clean := make([]string, 0, len(sans))
		for _, s := range sans {
			if v := sanitize([]byte(s)); v != "" {
				clean = append(clean, v)
			}
		}
		if len(clean) > 0 {
			ident["san"] = strings.Join(clean, ",")
		}
	}
	if cert.SerialNumber != nil {
		ident["serial"] = strings.TrimPrefix(cert.SerialNumber.Text(16), "-")
	}
	ident["not_before"] = cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z")
	ident["not_after"] = cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
	sum := sha256.Sum256(cert.Raw)
	ident["fingerprint"] = hex.EncodeToString(sum[:])
	return nil
}

func firstOrg(orgs []string) string {
	if len(orgs) == 0 {
		return ""
	}
	return sanitize([]byte(orgs[0]))
}

func tlsVersionName(maj, min byte) string {
	if maj != 0x03 {
		return fmt.Sprintf("%d.%d", maj, min)
	}
	switch min {
	case 1:
		return "1.0"
	case 2:
		return "1.1"
	case 3:
		return "1.2"
	case 4:
		return "1.3"
	}
	return fmt.Sprintf("1.%d", min-1)
}

func putUint24(b []byte, n int) {
	b[0] = byte(n >> 16)
	b[1] = byte(n >> 8)
	b[2] = byte(n)
}
