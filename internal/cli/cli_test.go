package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const validConfig = `version: 1
interfaces:
  - name: eth1
    active: { enabled: true, networks: [192.168.110.0/24], exclude: [192.168.110.1] }
active:
  tcp: { enabled: true, targets: [{ port: 502, name: modbus, timeout: 750ms }] }
logging: { format: text }
`

func run(t *testing.T, environ []string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Execute(context.Background(), Env{Args: args, Stdout: &out, Stderr: &errb, Environ: environ})
	return code, out.String(), errb.String()
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCommands(t *testing.T) {
	valid := writeFile(t, validConfig)
	invalid := writeFile(t, "version: 1\ninterfaces: []\nactive: { jitter: 2 }\n")
	missing := filepath.Join(t.TempDir(), "nope.yaml")

	tests := []struct {
		name       string
		args       []string
		environ    []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"version", []string{"version"}, nil, ExitOK, "lan-sentinel dev", ""},
		{"version json", []string{"version", "-o", "json"}, nil, ExitOK, `"platform": "` + runtime.GOOS + "/" + runtime.GOARCH, ""},
		{"unknown flag", []string{"--bogus"}, nil, ExitUsage, "", "unknown flag: --bogus"},
		{"unknown command", []string{"frobnicate"}, nil, ExitUsage, "", "unknown command"},
		{"bad output format", []string{"version", "-o", "xml"}, nil, ExitUsage, "", "invalid --output"},
		{"unsupported output format", []string{"version", "-o", "csv"}, nil, ExitUsage, "", "not supported by this command"},
		{"extra args", []string{"version", "extra"}, nil, ExitUsage, "", "unknown command"},
		{"validate ok", []string{"config", "validate", "--config", valid}, nil, ExitOK, "Estimated maximum probe rate: 20 pps", ""},
		{"validate quiet", []string{"config", "validate", "--config", valid, "--quiet"}, nil, ExitOK, "", ""},
		{"validate invalid", []string{"config", "validate", "--config", invalid}, nil, ExitError, "", "active.jitter: must be between 0 and 0.5"},
		{"validate lists every error", []string{"config", "validate", "--config", invalid}, nil, ExitError, "", "interfaces: at least one interface"},
		{"validate missing file", []string{"config", "validate", "--config", missing}, nil, ExitError, "", "no such file"},
		{"validate via env path", []string{"config", "validate"}, []string{"LAN_SENTINEL_CONFIG=" + valid}, ExitOK, "is valid", ""},
		{"validate bad env", []string{"config", "validate", "--config", valid}, []string{"LAN_SENTINEL_NOPE=1"}, ExitError, "", "LAN_SENTINEL_NOPE: unknown environment variable"},
		{"show yaml", []string{"config", "show", "--config", valid}, nil, ExitOK, "max_packets_per_second: 20", ""},
		{"show sources csv", []string{"config", "show", "--sources", "-o", "csv", "--config", valid, "--db", "/tmp/x.db"}, nil, ExitOK, "storage.path,/tmp/x.db,flag --db", ""},
		{"show sources env", []string{"config", "show", "--sources", "--config", valid}, []string{"LAN_SENTINEL_ACTIVE_JITTER=0.2"}, ExitOK, "env LAN_SENTINEL_ACTIVE_JITTER", ""},
		{"show invalid still prints", []string{"config", "show", "--config", invalid}, nil, ExitError, "version: 1", "invalid configuration"},
		{"daemon run invalid", []string{"daemon", "run", "--config", invalid}, nil, ExitError, "", "invalid configuration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tt.environ, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			if !strings.Contains(stdout, tt.wantStdout) {
				t.Errorf("stdout missing %q:\n%s", tt.wantStdout, stdout)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr missing %q:\n%s", tt.wantStderr, stderr)
			}
			if tt.name == "validate quiet" && stdout != "" {
				t.Errorf("--quiet printed %q", stdout)
			}
		})
	}
}

func TestValidateJSON(t *testing.T) {
	code, stdout, _ := run(t, nil, "config", "validate", "-o", "json", "--config", writeFile(t, validConfig))
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var got struct {
		Valid               bool    `json:"valid"`
		MaxPacketsPerSecond float64 `json:"max_packets_per_second"`
		Interfaces          []struct {
			Name     string   `json:"name"`
			Networks []string `json:"networks"`
		} `json:"interfaces"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout)
	}
	if !got.Valid || got.MaxPacketsPerSecond != 20 || got.Interfaces[0].Networks[0] != "192.168.110.0/24" {
		t.Errorf("summary = %+v", got)
	}
}
