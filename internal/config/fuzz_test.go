package config

import (
	"os"
	"testing"
	"time"
)

// FuzzLoad feeds arbitrary bytes to the config loader. It must never panic,
// and a configuration it accepts must flatten for `config show --sources`.
func FuzzLoad(f *testing.F) {
	for _, file := range []string{
		"testdata/architecture-example.yaml",
		"testdata/replay-example.yaml",
		"../../deploy/config.yaml",
		"../../deploy/config.dev.yaml",
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(minimal))
	f.Add([]byte("version: 1\ninterfaces: [{name: eth0, active: {enabled: true, networks: [10.0.0.0/8]}}]\n"))
	f.Add([]byte("- not\n- a mapping\n"))
	f.Add([]byte("active: { budgets: { tcp: { connects_per_second: .inf } } }\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := load(data, "fuzz.yaml", LoadOptions{})
		if err != nil {
			return
		}
		if _, err := l.Settings(); err != nil {
			t.Fatalf("accepted config does not flatten: %v", err)
		}
		_ = Summarize(l.Config)
	})
}

// FuzzScalars checks that every scalar type round-trips: a value that parses
// prints in a form that parses back to the same value.
func FuzzScalars(f *testing.F) {
	for _, s := range []string{"200MB", "1GiB", "0", "10 KB", "5m", "750ms", "168h", "1h30m",
		"192.168.1.1", "192.168.1.0/24", "fd00::1", "fd00::/64", "-1", "", "9223372036854775807GB"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var b ByteSize
		if b.parse(s) == nil {
			var back ByteSize
			if err := back.parse(b.String()); err != nil || back != b {
				t.Fatalf("ByteSize %q -> %q -> %d, %v", s, b.String(), back, err)
			}
		}
		var d Duration
		if d.parse(s) == nil {
			var back Duration
			if err := back.parse(d.String()); err != nil || back != d {
				t.Fatalf("Duration %q -> %q -> %v, %v", s, d.String(), time.Duration(back), err)
			}
		}
		var a AddrOrPrefix
		if a.UnmarshalText([]byte(s)) == nil {
			text, err := a.MarshalText()
			if err != nil {
				t.Fatal(err)
			}
			var back AddrOrPrefix
			if err := back.UnmarshalText(text); err != nil || back != a {
				t.Fatalf("AddrOrPrefix %q -> %q -> %v, %v", s, text, back, err)
			}
		}
	})
}
