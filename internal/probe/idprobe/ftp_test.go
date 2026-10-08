package idprobe

import (
	"context"
	"errors"
	"testing"
)

func TestFTPExchange(t *testing.T) {
	in := []byte("220-ACME FTP\r\n220 ready\r\n215 UNIX Type: L8\r\n221 Bye\r\n")
	s := &memSession{in: in}
	r, err := (FTP{}).Exchange(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if r.Identity["banner"] != "ACME FTP ready" || r.Identity["syst"] != "UNIX Type: L8" {
		t.Errorf("identity = %v", r.Identity)
	}
	if r.Confidence["banner"] != 0.6 {
		t.Errorf("confidence = %v", r.Confidence)
	}
	if len(s.writes) != 2 || string(s.writes[0]) != "SYST\r\n" || string(s.writes[1]) != "QUIT\r\n" {
		t.Errorf("writes = %q", s.writes)
	}
}

func TestFTPRejects(t *testing.T) {
	if _, err := (FTP{}).Exchange(context.Background(), &memSession{in: []byte("421 busy\r\n")}); !errors.Is(err, errFTP) {
		t.Errorf("421 = %v", err)
	}
	if _, _, err := parseFTPReply([]byte("xx\r\n")); !errors.Is(err, errFTP) {
		t.Errorf("short = %v", err)
	}
}
