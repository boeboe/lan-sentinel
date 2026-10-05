package cli

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestOutputFormats(t *testing.T) {
	valid := writeFile(t, validConfig)
	tests := []struct {
		name     string
		args     []string
		wantCode int
		check    func(t *testing.T, stdout string)
	}{
		{"sources as json lines", []string{"config", "show", "--sources", "-o", "jsonl", "--config", valid}, ExitOK, func(t *testing.T, out string) {
			lines := strings.Split(strings.TrimSpace(out), "\n")
			var s struct{ Key, Value, Source string }
			if err := json.Unmarshal([]byte(lines[0]), &s); err != nil || s.Key == "" || len(lines) < 50 {
				t.Errorf("jsonl: %d lines, first %q: %v", len(lines), lines[0], err)
			}
		}},
		{"sources as json", []string{"config", "show", "--sources", "-o", "json", "--config", valid}, ExitOK, func(t *testing.T, out string) {
			var s []map[string]string
			if err := json.Unmarshal([]byte(out), &s); err != nil || len(s) < 50 {
				t.Errorf("json: %d entries: %v", len(s), err)
			}
		}},
		{"config as json", []string{"config", "show", "-o", "json", "--config", valid}, ExitOK, func(t *testing.T, out string) {
			var c map[string]any
			if err := json.Unmarshal([]byte(out), &c); err != nil || c["version"] != float64(1) {
				t.Errorf("config json: %v %v", c["version"], err)
			}
		}},
		{"config as csv refused", []string{"config", "show", "-o", "csv", "--config", valid}, ExitUsage, nil},
		{"validate as csv refused", []string{"config", "validate", "-o", "csv", "--config", valid}, ExitUsage, nil},
		{"version quiet", []string{"version", "--quiet"}, ExitOK, func(t *testing.T, out string) {
			if strings.TrimSpace(out) != "dev" {
				t.Errorf("quiet version = %q", out)
			}
		}},
		{"show missing file", []string{"config", "show", "--config", "/nope.yaml"}, ExitError, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, nil, tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\n%s", code, tt.wantCode, stderr)
			}
			if tt.check != nil {
				tt.check(t, stdout)
			}
		})
	}
}

func TestErrorTypes(t *testing.T) {
	e := fail(ExitError, errors.New("boom"))
	var ee *exitError
	if !errors.As(e, &ee) || ee.Error() != "boom" || !errors.Is(e, ee.err) {
		t.Errorf("exitError = %v", e)
	}
	if silent(2).Error() != "exit 2" {
		t.Error("silent error text")
	}
	env := OSEnv()
	if env.Stdout == nil || env.Stderr == nil || len(env.Environ) == 0 {
		t.Errorf("OSEnv = %+v", env)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriterErrors(t *testing.T) {
	if err := writeJSON(failingWriter{}, map[string]int{"a": 1}); err == nil {
		t.Error("writeJSON ignored the write error")
	}
	if err := writeJSONL(failingWriter{}, []int{1}); err == nil {
		t.Error("writeJSONL ignored the write error")
	}
	if err := writeCSV(failingWriter{}, []string{"a"}, [][]string{{"b"}}); err == nil {
		t.Error("writeCSV ignored the write error")
	}
	if err := writeTable(failingWriter{}, []string{"a"}, [][]string{{"b"}}); err == nil {
		t.Error("writeTable ignored the write error")
	}
}
