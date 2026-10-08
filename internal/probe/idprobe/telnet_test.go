package idprobe

import (
	"context"
	"errors"
	"testing"
)

func TestTelnetBannerAndIAC(t *testing.T) {
	in := []byte{iac, telnetWill, 1, 'W', 'e', 'l', 'c', 'o', 'm', 'e'}
	s := &memSession{in: in}
	r, err := (Telnet{}).Exchange(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if r.Identity["banner"] != "Welcome" || r.Confidence["banner"] != 0.6 {
		t.Errorf("identity = %v", r.Identity)
	}
	if len(s.writes) != 1 || string(s.writes[0]) != string([]byte{iac, telnetDont, 1}) {
		t.Errorf("replies = %v", s.writes)
	}
}

func TestTelnetParseCapsIAC(t *testing.T) {
	var in []byte
	for i := 0; i < 10; i++ {
		in = append(in, iac, telnetDo, byte(i))
	}
	in = append(in, 'x')
	_, replies := parseTelnet(in)
	if len(replies) != 10 {
		t.Errorf("replies = %d", len(replies))
	}
}

func TestTelnetNoBanner(t *testing.T) {
	if _, err := (Telnet{}).Exchange(context.Background(), &memSession{in: []byte{iac, telnetWill, 1}}); !errors.Is(err, errTelnet) {
		t.Errorf("empty banner = %v", err)
	}
}
