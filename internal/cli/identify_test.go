package cli

import (
	"errors"
	"strings"
	"testing"

	"lan-sentinel/internal/api"
)

func TestIdentifyRun(t *testing.T) {
	f := serveDescribe(t)
	a1 := f.ids["eth1 "+f.a]
	const eth0 = "0199a0e0-0000-7000-8000-0000000000e0" // host A's MAC on eth0, where no probe is enabled
	tests := []struct {
		name    string
		args    []string
		err     error            // every probe
		refuse  map[string]bool  // these probes are refused
		fail    map[string]error // these probes fail otherwise
		code    int
		out     string
		notOut  string
		errText string
	}{
		{"run", []string{"identify", "run", "--id", a1, "--probe", "modbus"}, nil, nil, nil, 0, "identify modbus on 00:1b:1b:aa:bb:01: ok", "", ""},
		{"json", []string{"-o", "json", "identify", "run", "--id", a1, "--probe", "modbus"}, nil, nil, nil, 0, `"probe": "modbus"`, "", ""},
		{"unknown probe", []string{"identify", "run", "--id", a1, "--probe", "ssh-kex"}, nil, nil, nil, ExitUsage, "", "", "got \"ssh-kex\""},
		{"refused", []string{"identify", "run", "--id", a1, "--probe", "modbus"}, api.ErrIdentifyRefused, nil, nil, ExitError, "not sent", "", "no identification probe was sent"},
		{"offline", []string{"--offline", "identify", "run", "--id", a1, "--probe", "modbus"}, nil, nil, nil, ExitUsage, "", "", "needs the running daemon"},
		{"no probe", []string{"identify", "run", "--id", a1}, nil, nil, nil, ExitUsage, "", "", `"probe" not set`},
		{"sni on http", []string{"identify", "run", "--id", a1, "--probe", "http", "--sni", "plc.local"}, nil, nil, nil, ExitUsage, "", "", "only to --probe tls"},
		{"sni not dns", []string{"identify", "run", "--id", a1, "--probe", "tls", "--sni", "HMI1"}, nil, nil, nil, ExitUsage, "", "", "DNS name"},
		{"sni ok", []string{"identify", "run", "--id", a1, "--probe", "tls", "--sni", "plc.local"}, nil, nil, nil, 0, "identify tls", "", ""},
		{"list", []string{"identify", "run", "--id", a1, "--probe", "http,tls"}, nil, nil, nil, 0, "identify http on 00:1b:1b:aa:bb:01: ok", "", ""},
		{"unknown in list", []string{"identify", "run", "--id", a1, "--probe", "http,ssh-kex"}, nil, nil, nil, ExitUsage, "", "", "got \"ssh-kex\""},
		{"all mixed", []string{"identify", "run", "--id", a1, "--probe", "all,http"}, nil, nil, nil, ExitUsage, "", "", "cannot be mixed"},
		{"sni with list including tls", []string{"identify", "run", "--id", a1, "--probe", "http,tls", "--sni", "plc.local"}, nil, nil, nil, 0, "identify tls", "", ""},
		// all is the probes enabled on the host's interface (http, tls, ftp
		// on eth1), so the others are neither sent nor listed.
		{"all", []string{"identify", "run", "--id", a1, "--probe", "all"}, nil, nil, nil, 0, "identify ftp on 00:1b:1b:aa:bb:01: ok", "snmp", ""},
		{"all with sni", []string{"identify", "run", "--id", a1, "--probe", "all", "--sni", "plc.local"}, nil, nil, nil, 0, "identify tls", "", ""},
		{"all, none enabled", []string{"identify", "run", "--id", eth0, "--probe", "all"}, nil, nil, nil, ExitError, "", "", "no identification probe is enabled on eth0"},
		{"all refused", []string{"identify", "run", "--id", a1, "--probe", "all"}, api.ErrIdentifyRefused, nil, nil, ExitError, "not sent", "", "no identification probe was sent"},
		// One refusal does not stop the others, nor fail the command.
		{"some refused", []string{"identify", "run", "--id", a1, "--probe", "snmp,http"}, nil, map[string]bool{"snmp": true}, nil, 0,
			"identify snmp on 00:1b:1b:aa:bb:01: not sent", "", ""},
		{"some refused, json", []string{"-o", "json", "identify", "run", "--id", a1, "--probe", "snmp,http"}, nil, map[string]bool{"snmp": true}, nil, 0,
			`"error": "identification probe refused: snmp is not enabled on eth1"`, "", ""},
		// A failure stops the run; the attempts already made are still printed.
		{"failure, json", []string{"-o", "json", "identify", "run", "--id", a1, "--probe", "http,tls,ftp"}, nil, nil, map[string]error{"tls": errors.New("disk on fire")}, ExitError,
			`"probe": "http"`, "ftp", "disk on fire"},
		{"failure, table", []string{"identify", "run", "--id", a1, "--probe", "http,tls"}, nil, nil, map[string]error{"tls": errors.New("disk on fire")}, ExitError,
			"identify http on 00:1b:1b:aa:bb:01: ok", "", "disk on fire"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f.ctl.err, f.ctl.refuse, f.ctl.fail = tt.err, tt.refuse, tt.fail
			code, out, stderr := f.run(t, tt.args...)
			if code != tt.code || !strings.Contains(out, tt.out) || !strings.Contains(stderr, tt.errText) ||
				tt.notOut != "" && strings.Contains(out, tt.notOut) {
				t.Errorf("exit %d (want %d)\nstdout: %s\nstderr: %s", code, tt.code, out, stderr)
			}
		})
	}
}
