package config

import "testing"

func TestSNIName(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"plc.local", "plc.local", true},
		{"NAS.Example", "nas.example", true},
		{"a.b", "a.b", true},
		{"host-1.plant.local", "host-1.plant.local", true},
		{"", "", false},
		{"HMI1", "", false},
		{"Android_XXXXXXXX", "", false},
		{"192.168.0.99", "", false},
		{".local", "", false},
		{"plc.local.", "", false},
		{"plc..local", "", false},
		{"-x.local", "", false},
		{"x-.local", "", false},
	}
	for _, tt := range tests {
		got, ok := SNIName(tt.in)
		if ok != tt.ok || got != tt.want {
			t.Errorf("SNIName(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestResolveSNI(t *testing.T) {
	if got := ResolveSNI("", "plc.local", ""); got != "" {
		t.Errorf("empty mode = %q", got)
	}
	if got := ResolveSNI(SNIModeAuto, "plc.local", ""); got != "plc.local" {
		t.Errorf("auto + dns = %q", got)
	}
	if got := ResolveSNI(SNIModeAuto, "HMI1", ""); got != "" {
		t.Errorf("auto + token = %q", got)
	}
	if got := ResolveSNI("", "plc.local", "nas.local"); got != "nas.local" {
		t.Errorf("operator = %q", got)
	}
	if got := ResolveSNI(SNIModeAuto, "plc.local", "NAS.local"); got != "nas.local" {
		t.Errorf("operator wins = %q", got)
	}
}
