package service

import (
	"context"
	"log/slog"
	"testing"

	"github.com/coreos/go-systemd/v22/journal"
)

func TestJournalHandlerFields(t *testing.T) {
	type entry struct {
		msg  string
		pri  journal.Priority
		vars map[string]string
	}
	var got []entry
	h := &journalHandler{level: LevelTrace, send: func(msg string, p journal.Priority, vars map[string]string) error {
		got = append(got, entry{msg, p, vars})
		return nil
	}}
	log := slog.New(h).With("host_id", "3db0ce66")
	log.Log(context.Background(), LevelNotice, "IP changed", "event", "ip_changed", "iface", "eth1", "old-ip", "192.168.110.60")
	log.WithGroup("store").Warn("slow commit", slog.Group("batch", "ops", 12))
	log.Debug("debug line")

	tests := []struct {
		msg  string
		pri  journal.Priority
		want map[string]string
	}{
		{"IP changed", journal.PriNotice, map[string]string{
			"EVENT": "ip_changed", "IFACE": "eth1", "OLD_IP": "192.168.110.60", "HOST_ID": "3db0ce66", "SYSLOG_IDENTIFIER": "lan-sentinel",
		}},
		{"slow commit", journal.PriWarning, map[string]string{"STORE_BATCH_OPS": "12"}},
		{"debug line", journal.PriDebug, map[string]string{}},
	}
	if len(got) != len(tests) {
		t.Fatalf("got %d entries, want %d", len(got), len(tests))
	}
	for i, tt := range tests {
		if got[i].msg != tt.msg || got[i].pri != tt.pri {
			t.Errorf("entry %d = %q/%d, want %q/%d", i, got[i].msg, got[i].pri, tt.msg, tt.pri)
		}
		for k, v := range tt.want {
			if got[i].vars[k] != v {
				t.Errorf("entry %d: %s = %q, want %q (all: %v)", i, k, got[i].vars[k], v, got[i].vars)
			}
		}
	}
}

func TestJournalField(t *testing.T) {
	for in, want := range map[string]string{"event": "EVENT", "old-ip": "OLD_IP", "_private": "PRIVATE", "a.b": "A_B"} {
		if got := journalField(in); got != want {
			t.Errorf("journalField(%q) = %q, want %q", in, got, want)
		}
	}
}
