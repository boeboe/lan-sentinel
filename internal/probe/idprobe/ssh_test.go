package idprobe

import (
	"context"
	"errors"
	"testing"
)

func TestSSHBanner(t *testing.T) {
	s := &memSession{in: []byte("SSH-2.0-OpenSSH_8.9 Ubuntu\r\n")}
	r, err := (SSHBanner{}).Exchange(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if r.Identity["software"] != "OpenSSH_8.9" || r.Confidence["software"] != 0.8 {
		t.Errorf("identity = %v", r.Identity)
	}
	if len(s.writes) != 0 {
		t.Errorf("writes = %d", len(s.writes))
	}
}

func TestSSHRejects(t *testing.T) {
	for _, raw := range [][]byte{[]byte("HTTP/1.0"), []byte("SSH-2.0"), []byte("")} {
		if _, err := parseSSHBanner(raw); !errors.Is(err, errSSH) {
			t.Errorf("%q = %v", raw, err)
		}
	}
}
