package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/scheduler"
	"lan-sentinel/internal/store"
)

// Control is what the daemon does on operator requests: the kill switch
// and operator scans (docs/API.md, Operator endpoints).
type Control interface {
	DisableActive(ctx context.Context, actor, reason string) (store.ActiveState, error)
	EnableActive(ctx context.Context, actor, reason string) (store.ActiveState, error)
	PlanScan(ctx context.Context, req probe.Request) (probe.Plan, error)
	Scan(ctx context.Context, req probe.Request, actor string) (scheduler.ScanResult, error)
}

// Errors a Control returns, mapped to 409 Conflict.
var (
	// ErrForced: LAN_SENTINEL_ACTIVE_DISABLED=1 keeps active discovery off.
	ErrForced = errors.New("active discovery is forced off by LAN_SENTINEL_ACTIVE_DISABLED=1; unset it and restart the daemon")
	// ErrNoScanner: replay mode runs no probes.
	ErrNoScanner = errors.New("active discovery does not run in replay mode")
)

// SwitchRequest is the body of /v1/active/disable and /v1/active/enable.
type SwitchRequest struct {
	Reason string `json:"reason"`
}

// maxBody bounds operator request bodies.
const maxBody = 64 << 10

type connKey struct{}

// actor names the Unix user behind the request (SO_PEERCRED).
func actor(r *http.Request) string {
	c, _ := r.Context().Value(connKey{}).(net.Conn)
	if c == nil {
		return "unknown"
	}
	u, err := platform.PeerUser(c)
	if err != nil {
		return "unknown"
	}
	return u
}

// postOnly allows POST only, answering other methods with a JSON 405.
func postOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeJSON(w, http.StatusMethodNotAllowed, errorBody{r.Method + " is not allowed"})
			return
		}
		h(w, r)
	}
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return badParam{fmt.Sprintf("request body: %v", err)}
	}
	return nil
}

func (s *Server) control(w http.ResponseWriter) bool {
	if s.o.Control == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{"operator requests are not available"})
		return false
	}
	return true
}

func (s *Server) controlFail(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrForced) || errors.Is(err, ErrNoScanner) || errors.Is(err, scheduler.ErrScanRunning) {
		writeJSON(w, http.StatusConflict, errorBody{err.Error()})
		return
	}
	s.fail(w, err)
}

func (s *Server) activeDisable(w http.ResponseWriter, r *http.Request) {
	if !s.control(w) {
		return
	}
	var req SwitchRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, err)
		return
	}
	if req.Reason == "" {
		s.fail(w, badParam{"reason is required"})
		return
	}
	st, err := s.o.Control.DisableActive(r.Context(), actor(r), req.Reason)
	if err != nil {
		s.controlFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) activeEnable(w http.ResponseWriter, r *http.Request) {
	if !s.control(w) {
		return
	}
	var req SwitchRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, err)
		return
	}
	st, err := s.o.Control.EnableActive(r.Context(), actor(r), req.Reason)
	if err != nil {
		s.controlFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) scanPlan(w http.ResponseWriter, r *http.Request) {
	if !s.control(w) {
		return
	}
	var req probe.Request
	if err := decode(r, &req); err != nil {
		s.fail(w, err)
		return
	}
	plan, err := s.o.Control.PlanScan(r.Context(), req)
	if err != nil {
		s.controlFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

// scan runs an operator scan and answers once it is done: 200 with the
// result, 409 with the plan when the plan refuses it.
func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	if !s.control(w) {
		return
	}
	var req probe.Request
	if err := decode(r, &req); err != nil {
		s.fail(w, err)
		return
	}
	res, err := s.o.Control.Scan(r.Context(), req, actor(r))
	switch {
	case errors.Is(err, scheduler.ErrScanRefused):
		writeJSON(w, http.StatusConflict, res)
	case err != nil && aborted(res):
		writeJSON(w, http.StatusOK, res) // the result says why it stopped
	case err != nil:
		s.controlFail(w, err) // e.g. done but not recorded
	default:
		writeJSON(w, http.StatusOK, res)
	}
}

// aborted reports whether the scan's error is in its result: the
// interface it stopped on says why.
func aborted(res scheduler.ScanResult) bool {
	n := len(res.Interfaces)
	return n > 0 && res.Interfaces[n-1].Aborted != ""
}
