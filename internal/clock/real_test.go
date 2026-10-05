package clock

import (
	"testing"
	"time"
)

func TestRealClock(t *testing.T) {
	c := Real()
	if d := time.Since(c.Now()); d < 0 || d > time.Second {
		t.Errorf("Now is off by %v", d)
	}
	tk := c.NewTicker(time.Millisecond)
	<-tk.C()
	tk.Reset(time.Millisecond)
	<-tk.C()
	tk.Stop()

	tm := c.NewTimer(time.Hour)
	if !tm.Stop() {
		t.Error("Stop on an active timer returned false")
	}
	tm.Reset(time.Millisecond)
	<-tm.C()
}

func TestSimTickerReset(t *testing.T) {
	s := NewSim(t0)
	tk := s.NewTicker(0) // non-positive period is clamped, never panics
	tk.Reset(time.Minute)
	s.Advance(time.Minute)
	if _, ok := recv(t, tk.C()); !ok {
		t.Error("reset ticker did not fire")
	}
	tk.Reset(-time.Second)
	s.Advance(-time.Second) // ignored
}
