package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lan-sentinel/internal/store"
)

type codedErr int

func (c codedErr) Error() string { return "database is locked" }
func (c codedErr) Code() int     { return int(c) }

// Errors map to statuses, and a client that went away is not logged.
func TestFailStatuses(t *testing.T) {
	var log strings.Builder
	s := New(Options{})
	s.o.Logger = newTextLogger(&log)
	for _, tt := range []struct {
		err  error
		want int
	}{
		{fmt.Errorf("read: %w", codedErr(5)), http.StatusServiceUnavailable},
		{fmt.Errorf("%w: not committed within 8s", ErrBusy), http.StatusServiceUnavailable},
		{fmt.Errorf("host x: %w", store.ErrNotFound), http.StatusNotFound},
		{badParam{"since: bad"}, http.StatusBadRequest},
		{fmt.Errorf("read: %w", context.Canceled), http.StatusInternalServerError},
		{errors.New("disk on fire"), http.StatusInternalServerError},
	} {
		rec := httptest.NewRecorder()
		s.fail(rec, tt.err)
		if rec.Code != tt.want || !strings.Contains(rec.Body.String(), `"error"`) {
			t.Errorf("%v: %d %s, want %d", tt.err, rec.Code, rec.Body.String(), tt.want)
		}
	}
	if strings.Contains(log.String(), "context canceled") || !strings.Contains(log.String(), "disk on fire") {
		t.Errorf("log:\n%s", log.String())
	}
}

func newTextLogger(w *strings.Builder) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }

// A client sees the statuses as the errors it can test for.
func TestErrorUnwrap(t *testing.T) {
	for _, tt := range []struct {
		status int
		code   string
		want   error
	}{
		{http.StatusNotFound, "", store.ErrNotFound},
		{http.StatusBadRequest, "", store.ErrBadQuery},
		{http.StatusUnprocessableEntity, "", ErrConfigRejected},
		{http.StatusConflict, CodeIdentifyRefused, ErrIdentifyRefused},
		{http.StatusServiceUnavailable, "", ErrBusy},
	} {
		if err := error(&Error{Status: tt.status, Code: tt.code}); !errors.Is(err, tt.want) {
			t.Errorf("%d %q: not %v", tt.status, tt.code, tt.want)
		}
	}
	if err := error(&Error{Status: http.StatusInternalServerError}); errors.Is(err, ErrBusy) || errors.Unwrap(err) != nil {
		t.Errorf("500 unwraps to %v", errors.Unwrap(err))
	}
}
