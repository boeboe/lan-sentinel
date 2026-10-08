package idprobe

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestHTTPExchange(t *testing.T) {
	body := "HTTP/1.0 200 OK\r\nServer: nginx/1.24\r\nWWW-Authenticate: Basic realm=\"x\"\r\n\r\n<html><title>PLC Home</title></html>"
	s := &memSession{in: []byte(body)}
	r, err := (HTTP{}).Exchange(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if r.Identity["server"] != "nginx/1.24" || r.Identity["title"] != "PLC Home" {
		t.Errorf("identity = %v", r.Identity)
	}
	if r.Details["status"] != "200" || r.Details["www_authenticate"] != "Basic" {
		t.Errorf("details = %v", r.Details)
	}
	if r.Confidence["server"] != 0.6 || r.Confidence["title"] != 0.5 {
		t.Errorf("confidence = %v", r.Confidence)
	}
	if len(s.writes) != 1 || !strings.Contains(string(s.writes[0]), "GET / HTTP/1.0") {
		t.Errorf("writes = %q", s.writes)
	}
	if !strings.Contains(string(s.writes[0]), "User-Agent: lan-sentinel/") {
		t.Errorf("user-agent = %q", s.writes[0])
	}
}

func TestHTMLTitleUnicodeToLower(t *testing.T) {
	// U+0130 grows under strings.ToLower; the old code used those
	// indices on the original and panicked (FuzzParseHTTP).
	prefix := strings.Repeat("İ", 17)
	if got := htmlTitle(prefix + "<title>PLC</title>"); got != "PLC" {
		t.Errorf("title = %q", got)
	}
	_ = htmlTitle(prefix + "<TITLE")
	raw := []byte("HTTP/1.0 200 OK\r\n\r\n" + prefix + "<title>x</title>")
	if _, err := parseHTTP(raw); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPRejects(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte("not http"),
		[]byte("HTTP/1.0 oops\r\n\r\n"),
		[]byte("GET / HTTP/1.0\r\n\r\n"),
	} {
		if _, err := parseHTTP(raw); !errors.Is(err, errHTTP) && !errors.Is(err, errExchange) {
			t.Errorf("%q = %v", raw, err)
		}
	}
}
