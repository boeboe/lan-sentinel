package clock

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

func recv(t *testing.T, c <-chan time.Time) (time.Time, bool) {
	t.Helper()
	select {
	case v := <-c:
		return v, true
	default:
		return time.Time{}, false
	}
}

func TestSimTimer(t *testing.T) {
	tests := []struct {
		name    string
		after   time.Duration
		advance time.Duration
		fires   bool
	}{
		{"before deadline", 5 * time.Second, 4 * time.Second, false},
		{"at deadline", 5 * time.Second, 5 * time.Second, true},
		{"past deadline", 5 * time.Second, time.Hour, true},
		{"zero duration fires immediately", 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSim(t0)
			tm := s.NewTimer(tt.after)
			s.Advance(tt.advance)
			got, ok := recv(t, tm.C())
			if ok != tt.fires {
				t.Fatalf("fired = %v, want %v", ok, tt.fires)
			}
			if ok && !got.Equal(t0.Add(tt.after)) {
				t.Errorf("fired at %v, want %v", got, t0.Add(tt.after))
			}
		})
	}
}

func TestSimTickerFiresInOrderAndDrops(t *testing.T) {
	s := NewSim(t0)
	tk := s.NewTicker(time.Minute)
	tm := s.NewTimer(90 * time.Second)

	s.Advance(time.Minute)
	if v, ok := recv(t, tk.C()); !ok || !v.Equal(t0.Add(time.Minute)) {
		t.Fatalf("first tick = %v, %v", v, ok)
	}
	// Crossing several ticks without receiving keeps only the first pending
	// tick, like time.Ticker.
	s.Advance(5 * time.Minute)
	if v, ok := recv(t, tk.C()); !ok || !v.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("buffered tick = %v, %v", v, ok)
	}
	if _, ok := recv(t, tk.C()); ok {
		t.Fatal("extra ticks were not dropped")
	}
	if v, ok := recv(t, tm.C()); !ok || !v.Equal(t0.Add(90*time.Second)) {
		t.Fatalf("timer = %v, %v", v, ok)
	}
	if got := s.Now(); !got.Equal(t0.Add(6 * time.Minute)) {
		t.Errorf("Now = %v", got)
	}
}

func TestSimStopResetAndSetBackwards(t *testing.T) {
	s := NewSim(t0)
	tm := s.NewTimer(time.Minute)
	if !tm.Stop() {
		t.Fatal("Stop on active timer returned false")
	}
	s.Advance(time.Hour)
	if _, ok := recv(t, tm.C()); ok {
		t.Fatal("stopped timer fired")
	}
	if tm.Reset(time.Minute) {
		t.Fatal("Reset on stopped timer returned true")
	}
	if s.Waiters() != 1 {
		t.Fatalf("Waiters = %d, want 1", s.Waiters())
	}
	s.Set(t0) // backwards: ignored
	if !s.Now().Equal(t0.Add(time.Hour)) {
		t.Fatalf("Set moved the clock backwards to %v", s.Now())
	}
	s.Advance(time.Minute)
	if _, ok := recv(t, tm.C()); !ok {
		t.Fatal("reset timer did not fire")
	}
	if s.Waiters() != 0 {
		t.Fatalf("Waiters = %d after timer fired", s.Waiters())
	}
}
