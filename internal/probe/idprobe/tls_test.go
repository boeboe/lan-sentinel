package idprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func testTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xabc),
		Subject:      pkix.Name{CommonName: "plc", Organization: []string{"ACME"}},
		Issuer:       pkix.Name{CommonName: "plc-ca", Organization: []string{"ACME"}},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{"plc.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// sizedConn records the size of every write, so a test can see the
// ClientHello on the wire.
type sizedConn struct {
	net.Conn
	sizes []int
}

func (c *sizedConn) Write(p []byte) (int, error) {
	c.sizes = append(c.sizes, len(p))
	return c.Conn.Write(p)
}

// exchangeTLS runs the probe against a crypto/tls server configured by
// server and returns the claims and each write the probe made.
func exchangeTLS(t *testing.T, server func(*tls.Config)) (Response, []int, error) {
	return exchangeTLSProbe(t, TLS{}, server)
}

func exchangeTLSProbe(t *testing.T, pr TLS, server func(*tls.Config)) (Response, []int, error) {
	t.Helper()
	cert := testTLSCertificate(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		server(cfg)
		errc <- tls.Server(c, cfg).Handshake()
	}()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	sized := &sizedConn{Conn: conn}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, xerr := pr.Exchange(ctx, newSession(sized, pr.Limits()))
	_ = conn.Close()
	<-errc
	return r, sized.sizes, xerr
}

// Every handshake a device may lead the probe into stays within the write
// cap: a HelloRetryRequest (the server wants another key share) and a
// client certificate request add messages, never a write past the cap,
// which would record a working server as malformed and use up its only
// attempt. The ClientHello stays small enough for one segment (no
// post-quantum key share), which old embedded TLS stacks expect.
func TestTLSHandshakes(t *testing.T) {
	tests := []struct {
		name    string
		server  func(*tls.Config)
		version string
	}{
		{"TLS 1.2", func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }, "1.2"},
		{"TLS 1.3", func(c *tls.Config) { c.MaxVersion = tls.VersionTLS13 }, "1.3"},
		{"TLS 1.3 HelloRetryRequest", func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.CurveP256} }, "1.3"},
		{"TLS 1.2 client certificate requested", func(c *tls.Config) {
			c.MaxVersion, c.ClientAuth = tls.VersionTLS12, tls.RequestClientCert
		}, "1.2"},
		{"TLS 1.3 client certificate requested", func(c *tls.Config) { c.ClientAuth = tls.RequestClientCert }, "1.3"},
		{"TLS 1.3 retry and client certificate", func(c *tls.Config) {
			c.CurvePreferences, c.ClientAuth = []tls.CurveID{tls.CurveP256}, tls.RequestClientCert
		}, "1.3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, writes, err := exchangeTLS(t, tt.server)
			t.Logf("writes %v", writes)
			if err != nil {
				t.Fatalf("exchange: %v (writes %v)", err, writes)
			}
			if r.Identity["subject_cn"] != "plc" || r.Identity["subject_o"] != "ACME" || r.Identity["san"] != "plc.local" ||
				r.Identity["tls_version"] != tt.version || r.Identity["fingerprint"] == "" || r.Confidence["subject_o"] != tlsConfidence {
				t.Errorf("identity = %v conf = %v", r.Identity, r.Confidence)
			}
			if len(writes) < 1 || len(writes) > tlsMaxWrites {
				t.Errorf("writes %v, want 1..%d", writes, tlsMaxWrites)
			}
			if writes[0] > tlsMaxClientHello {
				t.Errorf("ClientHello of %d bytes, want at most %d", writes[0], tlsMaxClientHello)
			}
		})
	}
}

func TestTLSRejects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte{21, 3, 3, 0, 2, 2, 40}) // fatal handshake_failure
		_ = c.Close()
	}()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := (TLS{}).Exchange(context.Background(), newSession(conn, TLS{}.Limits())); !errors.Is(err, errTLS) {
		t.Errorf("alert = %v", err)
	}
	if _, err := (TLS{}).Exchange(context.Background(), &memSession{}); !errors.Is(err, errTLS) {
		t.Errorf("memSession = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (TLS{}).Exchange(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled = %v", err)
	}
	if _, err := certFromX509(nil, "1.2"); !errors.Is(err, errTLS) {
		t.Errorf("nil cert = %v", err)
	}
}

func TestTLSSNI(t *testing.T) {
	var seen string
	r, _, err := exchangeTLSProbe(t, TLS{ServerName: "plc.local"}, func(c *tls.Config) {
		c.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			seen = chi.ServerName
			return nil, nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != "plc.local" {
		t.Errorf("server saw SNI %q", seen)
	}
	if r.Details["sni"] != "plc.local" {
		t.Errorf("details = %v", r.Details)
	}
	r, _, err = exchangeTLS(t, func(*tls.Config) {})
	if err != nil {
		t.Fatal(err)
	}
	if r.Details["sni"] != "" {
		t.Errorf("no SNI details = %v", r.Details)
	}
}

func TestTLSVersionLabel(t *testing.T) {
	if got := tlsVersionLabel(tls.VersionTLS10); got != "1.0" {
		t.Errorf("1.0 = %s", got)
	}
	if got := tlsVersionLabel(tls.VersionTLS11); got != "1.1" {
		t.Errorf("1.1 = %s", got)
	}
	if got := tlsVersionLabel(0x0305); got != "0x0305" {
		t.Errorf("unknown = %s", got)
	}
}
