package platform

import "golang.org/x/sys/unix"

// ClockState is whether the kernel clock is synchronised to a time source
// (NFR-REL-2), recorded with every event.
type ClockState string

// Clock states. Unknown is explicit: a state that cannot be read is never
// taken for synchronised.
const (
	ClockSynced   ClockState = "synced"
	ClockUnsynced ClockState = "unsynced"
	ClockUnknown  ClockState = "unknown"
)

// ClockSource reports the kernel clock's synchronisation state.
type ClockSource interface {
	Backend() string
	State() ClockState
}

// Kernel time status (linux/timex.h); x/sys/unix does not define them.
const (
	staUnsync   = 0x0040 // STA_UNSYNC: the clock is not synchronised
	staClockErr = 0x1000 // STA_CLOCKERR: clock hardware fault
	timeError   = 5      // TIME_ERROR: adjtimex's state when unsynchronised
)

// adjtimexClock reads the kernel's NTP status with a read-only adjtimex
// (modes 0), whichever NTP client keeps the clock (chrony, ntpd,
// systemd-timesyncd). Reading needs no capability; the unit allows only
// this call of the @clock group, and without CAP_SYS_TIME the kernel
// refuses any change to the clock anyway.
type adjtimexClock struct{}

func (adjtimexClock) Backend() string { return "adjtimex" }

func (adjtimexClock) State() ClockState {
	var tx unix.Timex // Modes 0: read only
	state, err := unix.Adjtimex(&tx)
	return clockState(state, tx.Status, err)
}

func clockState(state int, status int32, err error) ClockState {
	switch {
	case err != nil:
		return ClockUnknown // e.g. EPERM from a seccomp filter
	case state == timeError || status&(staUnsync|staClockErr) != 0:
		return ClockUnsynced
	}
	return ClockSynced
}
