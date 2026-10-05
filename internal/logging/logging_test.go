package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		in   string
		want slog.Level
		bad  bool
	}{
		{"trace", LevelTrace, false},
		{"DEBUG", slog.LevelDebug, false},
		{"info", slog.LevelInfo, false},
		{"warn", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"verbose", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseLevel(tt.in)
		if (err != nil) != tt.bad || got != tt.want {
			t.Errorf("ParseLevel(%q) = %v, %v", tt.in, got, err)
		}
	}
}

func TestFormats(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	lv.Set(LevelTrace)

	h, err := New(Options{Format: "json", Level: lv, Writer: &buf})
	if err != nil {
		t.Fatal(err)
	}
	slog.New(h).Log(context.Background(), LevelNotice, "host discovered", "event", "host_discovered")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("json output %q: %v", buf.String(), err)
	}
	if rec["level"] != "NOTICE" || rec["event"] != "host_discovered" {
		t.Errorf("json record = %v", rec)
	}

	buf.Reset()
	h, err = New(Options{Format: "text", Level: lv, Writer: &buf})
	if err != nil {
		t.Fatal(err)
	}
	slog.New(h).Log(context.Background(), LevelTrace, "tick")
	if !strings.Contains(buf.String(), "level=TRACE") {
		t.Errorf("text output = %q", buf.String())
	}

	if _, err := New(Options{Format: "xml", Level: lv, Writer: &buf}); err == nil {
		t.Error("unknown format accepted")
	}
}
