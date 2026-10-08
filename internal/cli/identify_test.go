package cli

import (
	"strings"
	"testing"

	"lan-sentinel/internal/api"
)

func TestIdentifyRun(t *testing.T) {
	f := serveDescribe(t)
	a1 := f.ids["eth1 "+f.a]
	tests := []struct {
		name    string
		args    []string
		err     error
		code    int
		out     string
		errText string
	}{
		{"run", []string{"identify", "run", "--id", a1, "--probe", "modbus"}, nil, 0, "identify modbus on 00:1b:1b:aa:bb:01: ok", ""},
		{"json", []string{"-o", "json", "identify", "run", "--id", a1, "--probe", "modbus"}, nil, 0, `"probe": "modbus"`, ""},
		{"unknown probe", []string{"identify", "run", "--id", a1, "--probe", "ssh-kex"}, nil, ExitUsage, "", "must be one of"},
		{"refused", []string{"identify", "run", "--id", a1, "--probe", "modbus"}, api.ErrIdentifyRefused, ExitError, "", "identification probe refused"},
		{"offline", []string{"--offline", "identify", "run", "--id", a1, "--probe", "modbus"}, nil, ExitUsage, "", "needs the running daemon"},
		{"no probe", []string{"identify", "run", "--id", a1}, nil, ExitUsage, "", `"probe" not set`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f.ctl.err = tt.err
			code, out, stderr := f.run(t, tt.args...)
			if code != tt.code || !strings.Contains(out, tt.out) || !strings.Contains(stderr, tt.errText) {
				t.Errorf("exit %d (want %d)\nstdout: %s\nstderr: %s", code, tt.code, out, stderr)
			}
		})
	}
}
