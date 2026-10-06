package platform

import (
	"errors"
	"testing"
)

func TestClockState(t *testing.T) {
	for _, tt := range []struct {
		state  int
		status int32
		err    error
		want   ClockState
	}{
		{0, 0x2001, nil, ClockSynced},             // TIME_OK, PLL running
		{0, staUnsync, nil, ClockUnsynced},        // freshly booted, no NTP yet
		{timeError, 0, nil, ClockUnsynced},        // the kernel's own verdict
		{0, staClockErr, nil, ClockUnsynced},      // clock hardware fault
		{0, 0, errors.New("EPERM"), ClockUnknown}, // blocked by a seccomp filter: never assumed synced
	} {
		if got := clockState(tt.state, tt.status, tt.err); got != tt.want {
			t.Errorf("clockState(%d, %#x, %v) = %s, want %s", tt.state, tt.status, tt.err, got, tt.want)
		}
	}
	// Read-only adjtimex needs no capability: unprivileged, the state is known.
	c := New().Clock
	if c.Backend() != "adjtimex" {
		t.Errorf("backend = %s", c.Backend())
	}
	if got := c.State(); got == ClockUnknown {
		t.Errorf("adjtimex unprivileged = %s", got)
	}
}
