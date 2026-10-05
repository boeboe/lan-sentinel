package clock

import (
	"sort"
	"sync"
	"time"
)

// Sim is a simulated clock. Time only moves when Advance or Set is called;
// timers and tickers whose deadlines are crossed fire in chronological order,
// with the clock set to each deadline as it fires. Like their time package
// counterparts, channel sends never block: a tick is dropped if the previous
// one has not been received.
type Sim struct {
	mu      sync.Mutex
	now     time.Time
	waiters []*simWaiter
}

// NewSim returns a simulated clock starting at start.
func NewSim(start time.Time) *Sim { return &Sim{now: start} }

type simWaiter struct {
	clock    *Sim
	c        chan time.Time
	deadline time.Time
	period   time.Duration // zero for timers
	active   bool
}

// Now returns the simulated time.
func (s *Sim) Now() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now
}

// NewTicker returns a ticker driven by the simulated clock.
func (s *Sim) NewTicker(d time.Duration) Ticker {
	d = minPeriod(d)
	s.mu.Lock()
	defer s.mu.Unlock()
	w := &simWaiter{clock: s, c: make(chan time.Time, 1), deadline: s.now.Add(d), period: d, active: true}
	s.waiters = append(s.waiters, w)
	return simTicker{w}
}

// NewTimer returns a timer driven by the simulated clock.
func (s *Sim) NewTimer(d time.Duration) Timer {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := &simWaiter{clock: s, c: make(chan time.Time, 1), deadline: s.now.Add(d), active: true}
	s.waiters = append(s.waiters, w)
	s.fireDueLocked()
	return simTimer{w}
}

// Advance moves the clock forward by d, firing everything that falls due.
// A negative d is ignored.
func (s *Sim) Advance(d time.Duration) {
	if d <= 0 {
		return
	}
	s.Set(s.Now().Add(d))
}

// Set moves the clock forward to t. Moving backwards is ignored, so a replay
// with slightly out-of-order timestamps never rewinds timers.
func (s *Sim) Set(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		next := s.nextDueLocked(t)
		if next == nil {
			break
		}
		s.now = next.deadline
		s.fireLocked(next)
	}
	if t.After(s.now) {
		s.now = t
	}
}

// Waiters reports how many timers and tickers are active; tests use it to
// wait until a goroutine has armed its timer.
func (s *Sim) Waiters() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, w := range s.waiters {
		if w.active {
			n++
		}
	}
	return n
}

func (s *Sim) nextDueLocked(limit time.Time) *simWaiter {
	var due []*simWaiter
	for _, w := range s.waiters {
		if w.active && !w.deadline.After(limit) {
			due = append(due, w)
		}
	}
	if len(due) == 0 {
		return nil
	}
	sort.SliceStable(due, func(i, j int) bool { return due[i].deadline.Before(due[j].deadline) })
	return due[0]
}

func (s *Sim) fireDueLocked() {
	for {
		next := s.nextDueLocked(s.now)
		if next == nil {
			return
		}
		s.fireLocked(next)
	}
}

func (s *Sim) fireLocked(w *simWaiter) {
	select {
	case w.c <- w.deadline:
	default:
	}
	if w.period > 0 {
		w.deadline = w.deadline.Add(w.period)
	} else {
		w.active = false
	}
	s.compactLocked()
}

func (s *Sim) compactLocked() {
	kept := s.waiters[:0]
	for _, w := range s.waiters {
		if w.active {
			kept = append(kept, w)
		}
	}
	s.waiters = kept
}

func (w *simWaiter) stop() bool {
	s := w.clock
	s.mu.Lock()
	defer s.mu.Unlock()
	was := w.active
	w.active = false
	s.compactLocked()
	return was
}

func (w *simWaiter) reset(d time.Duration, period bool) bool {
	s := w.clock
	s.mu.Lock()
	defer s.mu.Unlock()
	was := w.active
	w.deadline = s.now.Add(d)
	if period {
		w.period = d
	}
	if !w.active {
		w.active = true
		s.waiters = append(s.waiters, w)
	}
	if !period {
		s.fireDueLocked()
	}
	return was
}

type simTicker struct{ w *simWaiter }

func (t simTicker) C() <-chan time.Time   { return t.w.c }
func (t simTicker) Stop()                 { t.w.stop() }
func (t simTicker) Reset(d time.Duration) { t.w.reset(minPeriod(d), true) }

// minPeriod replaces a non-positive ticker period (which would make
// time.NewTicker panic) with the smallest valid one.
func minPeriod(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Nanosecond
	}
	return d
}

type simTimer struct{ w *simWaiter }

func (t simTimer) C() <-chan time.Time        { return t.w.c }
func (t simTimer) Stop() bool                 { return t.w.stop() }
func (t simTimer) Reset(d time.Duration) bool { return t.w.reset(d, false) }
