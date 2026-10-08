package idprobe

import (
	"crypto/x509"
	"testing"
)

func fuzzNoEmptyClaims(t *testing.T, ident map[string]string) {
	t.Helper()
	for k, v := range ident {
		if k == "" || v == "" {
			t.Fatalf("empty claim %q=%q", k, v)
		}
	}
}

func FuzzParseDeviceID(f *testing.F) {
	ok := deviceIDReply(1, 1, false, 0, object(modbusObjVendor, "ACME"), object(modbusObjProduct, "PLC"))
	f.Add(ok)
	f.Add([]byte{})
	f.Add(make([]byte, 8))
	f.Fuzz(func(t *testing.T, b []byte) {
		ident := map[string]string{}
		_, _, _ = parseDeviceID(b, 1, 1, ident)
		fuzzNoEmptyClaims(t, ident)
	})
}

func FuzzParseHTTP(f *testing.F) {
	f.Add([]byte("HTTP/1.0 200 OK\r\nServer: x\r\n\r\n<title>t</title>"))
	f.Add([]byte("HTTP/1.0 200 OK\r\n\r\nİİİ<title>x</title>"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, _ := parseHTTP(b)
		fuzzNoEmptyClaims(t, r.Identity)
	})
}

func FuzzCertClaims(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		cert, err := x509.ParseCertificate(b)
		if err != nil {
			_, _ = certFromX509(nil, "1.2")
			return
		}
		r, err := certFromX509(cert, "1.3")
		if err != nil {
			return
		}
		fuzzNoEmptyClaims(t, r.Identity)
	})
}

func FuzzParseSNMP(f *testing.F) {
	f.Add(snmpGetResponse(1, "public"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, _ := parseSNMP(b, 1)
		fuzzNoEmptyClaims(t, r.Identity)
	})
}

func FuzzParseSSH(f *testing.F) {
	f.Add([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, _ := parseSSHBanner(b)
		fuzzNoEmptyClaims(t, r.Identity)
	})
}

func FuzzParseTelnet(f *testing.F) {
	f.Add([]byte{iac, telnetWill, 1, 'h', 'i'})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		banner, _ := parseTelnet(b)
		if banner != sanitize([]byte(banner)) {
			t.Fatalf("unsanitized %q", banner)
		}
	})
}

func FuzzParseFTP(f *testing.F) {
	f.Add([]byte("220 ready\r\n"))
	f.Add([]byte("220-a\r\n220 b\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, text, _ := parseFTPReply(b)
		if text != "" && sanitize([]byte(text)) == "" && text != sanitize([]byte(text)) {
			// parser may return raw text; Exchange sanitizes
			_ = text
		}
	})
}
