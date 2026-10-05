// Package clock abstracts time so that the correlator, timers and the store
// can run on the wall clock in production and on a simulated clock in replay
// and tests.
package clock

import "time"

// Clock is the source of time for every component that reads time.
type Clock interface {
	Now() time.Time
	NewTicker(d time.Duration) Ticker
	NewTimer(d time.Duration) Timer
}

// Ticker mirrors time.Ticker.
type Ticker interface {
	C() <-chan time.Time
	Stop()
	Reset(d time.Duration)
}

// Timer mirrors time.Timer.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration) bool
}

// Real returns the wall clock.
func Real() Clock { return realClock{} }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) NewTicker(d time.Duration) Ticker { return realTicker{time.NewTicker(d)} }

func (realClock) NewTimer(d time.Duration) Timer { return realTimer{time.NewTimer(d)} }

type realTicker struct{ t *time.Ticker }

func (r realTicker) C() <-chan time.Time   { return r.t.C }
func (r realTicker) Stop()                 { r.t.Stop() }
func (r realTicker) Reset(d time.Duration) { r.t.Reset(d) }

type realTimer struct{ t *time.Timer }

func (r realTimer) C() <-chan time.Time        { return r.t.C }
func (r realTimer) Stop() bool                 { return r.t.Stop() }
func (r realTimer) Reset(d time.Duration) bool { return r.t.Reset(d) }
