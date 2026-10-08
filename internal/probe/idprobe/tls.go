package idprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"lan-sentinel/internal/probe"
)

// TLS records the peer certificate from one crypto/tls handshake on
// tcp/443 (ADR 0011). TLS 1.2 and 1.3, no trust validation. ServerName
// is SNI when set (opt-in auto or identify run --sni); empty sends none.
// The engine closes the TCP socket; this probe must not Close the
// tls.Conn (close_notify would be a write past MaxWrites).
type TLS struct {
	ServerName string
}

const (
	tlsPort = 443
	// A handshake writes the ClientHello and one final flight; a
	// HelloRetryRequest (the server wants a key share for another group)
	// adds a compatibility ChangeCipherSpec and a second ClientHello, each
	// written alone by crypto/tls: 4 writes at most. With 3, such a
	// working server was recorded as malformed, its only attempt used up.
	tlsMaxWrites  = 4
	tlsBudgetCost = 3 + tlsMaxWrites // TCP setup and close plus the writes
	tlsMaxRead    = 16 << 10
	tlsConfidence = 0.7
	// tlsMaxClientHello bounds the ClientHello: one TCP segment with room.
	tlsMaxClientHello = 512
)

// tlsCurves are the key-exchange groups offered, X25519 first (its key
// share goes in the ClientHello), P-256 second (a HelloRetryRequest away).
// Naming them leaves out Go's default post-quantum hybrid share, which
// grows the ClientHello to about 1.5 KB, past one TCP segment; old
// embedded TLS stacks on OT devices handle a split ClientHello badly.
var tlsCurves = []tls.CurveID{tls.X25519, tls.CurveP256}

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
func (TLS) Limits() Limits { return Limits{MaxWrites: tlsMaxWrites, MaxRead: tlsMaxRead} }

// Exchange implements Probe.
func (p TLS) Exchange(ctx context.Context, s Session) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	conn, ok := s.(net.Conn)
	if !ok {
		return Response{}, fmt.Errorf("%w: session is not a net.Conn", errTLS)
	}
	c := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // ADR 0011: claims are the peer certificate
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   tlsCurves,
		ServerName:         p.ServerName,
	})
	if err := c.HandshakeContext(ctx); err != nil {
		if isTimeout(err) {
			return Response{}, err
		}
		return Response{}, fmt.Errorf("%w: %w", errTLS, err)
	}
	state := c.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return Response{}, fmt.Errorf("%w: no certificate", errTLS)
	}
	r, err := certFromX509(state.PeerCertificates[0], tlsVersionLabel(state.Version))
	if err != nil {
		return Response{}, err
	}
	if p.ServerName != "" {
		if r.Details == nil {
			r.Details = map[string]string{}
		}
		r.Details["sni"] = p.ServerName
	}
	return r, nil
}

func certFromX509(cert *x509.Certificate, version string) (Response, error) {
	if cert == nil {
		return Response{}, fmt.Errorf("%w: no certificate", errTLS)
	}
	ident := map[string]string{}
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
	if version != "" {
		ident["tls_version"] = version
	}
	conf := map[string]float64{}
	for f := range ident {
		conf[f] = tlsConfidence
	}
	return Response{Identity: ident, Confidence: conf}, nil
}

func firstOrg(orgs []string) string {
	if len(orgs) == 0 {
		return ""
	}
	return sanitize([]byte(orgs[0]))
}

func tlsVersionLabel(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
