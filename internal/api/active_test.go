package api_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/scheduler"
	"lan-sentinel/internal/store"
)

// control is a fake api.Control.
type control struct {
	mu      sync.Mutex
	actors  []string
	reasons []string
	err     error
	scan    scheduler.ScanResult
	scanErr error
	plan    probe.Plan
	reload  api.ReloadResult
}

func (c *control) note(actor, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.actors, c.reasons = append(c.actors, actor), append(c.reasons, reason)
}

func (c *control) DisableActive(_ context.Context, actor, reason string) (store.ActiveState, error) {
	c.note(actor, reason)
	return store.ActiveState{Disabled: true, Reason: reason, By: actor}, c.err
}

func (c *control) EnableActive(_ context.Context, actor, reason string) (store.ActiveState, error) {
	c.note(actor, reason)
	return store.ActiveState{}, c.err
}

func (c *control) PlanScan(_ context.Context, req probe.Request) (probe.Plan, error) {
	c.note("", req.Profile)
	return c.plan, c.err
}

func (c *control) Scan(_ context.Context, req probe.Request, actor string) (scheduler.ScanResult, error) {
	c.note(actor, req.Profile)
	return c.scan, c.scanErr
}

func (c *control) ReloadConfig(_ context.Context, actor string) (api.ReloadResult, error) {
	c.note(actor, "reload")
	return c.reload, c.err
}

// currentUser is how PeerUser names this process's user.
func currentUser() string {
	uid := strconv.Itoa(os.Getuid())
	if u, err := user.LookupId(uid); err == nil {
		return u.Username
	}
	return "uid " + uid
}

func startControl(t *testing.T, ctl api.Control) (*api.Client, string, string) {
	t.Helper()
	srv := api.New(api.Options{Control: ctl})
	socket, listen := filepath.Join(t.TempDir(), "api.sock"), freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Start(ctx, socket, listen); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = srv.Wait() })
	return api.NewClient(socket, 5*time.Second), socket, listen
}

func status(err error) int {
	var ae *api.Error
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

func TestKillSwitchEndpoints(t *testing.T) {
	ctl := &control{}
	c, _, _ := startControl(t, ctl)
	ctx := context.Background()
	me := currentUser()

	st, err := c.DisableActive(ctx, "PLC fault")
	if err != nil || !st.Disabled || st.Reason != "PLC fault" {
		t.Fatalf("disable = %+v, %v", st, err)
	}
	if ctl.actors[0] != me {
		t.Errorf("actor = %q, want %q (SO_PEERCRED)", ctl.actors[0], me)
	}
	if _, err := c.DisableActive(ctx, ""); status(err) != http.StatusBadRequest || !errors.Is(err, store.ErrBadQuery) {
		t.Errorf("disable without reason: %v", err)
	}
	if st, err := c.EnableActive(ctx, "fixed"); err != nil || st.Disabled {
		t.Errorf("enable = %+v, %v", st, err)
	}
	ctl.err = api.ErrForced
	if _, err := c.EnableActive(ctx, ""); status(err) != http.StatusConflict || !strings.Contains(err.Error(), "LAN_SENTINEL_ACTIVE_DISABLED") {
		t.Errorf("enable while forced: %v", err)
	}
	if _, err := c.DisableActive(ctx, "x"); status(err) != http.StatusConflict {
		t.Errorf("disable failing with a conflict: %v", err)
	}
	ctl.err = errors.New("bus closed")
	if _, err := c.DisableActive(ctx, "x"); status(err) != http.StatusInternalServerError {
		t.Errorf("disable failing: %v", err)
	}
}

func TestScanEndpoints(t *testing.T) {
	plan := probe.Plan{Allowed: true, Interfaces: []probe.InterfacePlan{{Interface: "eth1", SweepTargets: 253}}}
	ctl := &control{plan: plan, scan: scheduler.ScanResult{Plan: plan, Interfaces: []scheduler.InterfaceResult{{Interface: "eth1", Responders: 3}}}}
	c, _, _ := startControl(t, ctl)
	ctx := context.Background()

	p, err := c.PlanScan(ctx, probe.Request{Profile: "modbus"})
	if err != nil || !p.Allowed || p.Interfaces[0].SweepTargets != 253 || ctl.reasons[0] != "modbus" {
		t.Fatalf("plan = %+v, %v", p, err)
	}
	res, err := c.Scan(ctx, probe.Request{Profile: "modbus"})
	if err != nil || res.Interfaces[0].Responders != 3 || ctl.actors[1] == "" {
		t.Fatalf("scan = %+v, %v", res, err)
	}

	ctl.scanErr = scheduler.ErrScanRefused
	ctl.scan = scheduler.ScanResult{Plan: probe.Plan{Reasons: []string{"kill switch"}}}
	res, err = c.Scan(ctx, probe.Request{})
	if !errors.Is(err, scheduler.ErrScanRefused) || len(res.Plan.Reasons) != 1 {
		t.Errorf("refused scan = %+v, %v", res, err)
	}

	ctl.scanErr = scheduler.ErrScanRunning
	ctl.scan = scheduler.ScanResult{}
	if _, err := c.Scan(ctx, probe.Request{}); status(err) != http.StatusConflict || errors.Is(err, scheduler.ErrScanRefused) {
		t.Errorf("busy scan: %v", err)
	}

	ctl.scanErr = probe.ErrDisabled
	ctl.scan = scheduler.ScanResult{Interfaces: []scheduler.InterfaceResult{{Interface: "eth1", Aborted: "kill switch"}}}
	if res, err := c.Scan(ctx, probe.Request{}); err != nil || res.Interfaces[0].Aborted == "" {
		t.Errorf("aborted scan: %+v, %v", res, err)
	}

	// Done but not recorded: the error is not in the result.
	ctl.scanErr = errors.New("operator scan of eth1 not recorded: bus closed")
	ctl.scan = scheduler.ScanResult{Interfaces: []scheduler.InterfaceResult{{Interface: "eth1"}}}
	if _, err := c.Scan(ctx, probe.Request{}); status(err) != http.StatusInternalServerError || !strings.Contains(err.Error(), "not recorded") {
		t.Errorf("unrecorded scan: %v", err)
	}

	ctl.err = api.ErrNoScanner
	if _, err := c.PlanScan(ctx, probe.Request{}); status(err) != http.StatusConflict {
		t.Errorf("plan in replay mode: %v", err)
	}
}

func TestConfigReloadEndpoint(t *testing.T) {
	ctl := &control{reload: api.ReloadResult{
		Path:       "/etc/lan-sentinel/config.yaml",
		Applied:    []config.Change{{Key: "interfaces[0].active.enabled", Old: "false", New: "true"}},
		NotApplied: []config.Change{{Key: "storage.path", Old: "/data/a.db", New: "/data/b.db"}},
	}}
	c, _, _ := startControl(t, ctl)
	ctx := context.Background()

	res, err := c.ReloadConfig(ctx)
	if err != nil || res.Path != ctl.reload.Path || len(res.Applied) != 1 || res.Applied[0].New != "true" || res.NotApplied[0].Key != "storage.path" {
		t.Fatalf("reload = %+v, %v", res, err)
	}
	if ctl.actors[0] != currentUser() {
		t.Errorf("actor = %q, want the caller (SO_PEERCRED)", ctl.actors[0])
	}

	ctl.err = fmt.Errorf("%w: %w", api.ErrConfigRejected, errors.New("invalid configuration /etc/lan-sentinel/config.yaml:\n  active.arp.interval: must be positive"))
	_, err = c.ReloadConfig(ctx)
	if status(err) != http.StatusUnprocessableEntity || !errors.Is(err, api.ErrConfigRejected) || !strings.Contains(err.Error(), "active.arp.interval") {
		t.Errorf("rejected file: %v", err)
	}
	ctl.err = errors.New("encode config: boom")
	if _, err := c.ReloadConfig(ctx); status(err) != http.StatusInternalServerError || errors.Is(err, api.ErrConfigRejected) {
		t.Errorf("reload failing: %v", err)
	}
}

func TestOperatorRequestsAreChecked(t *testing.T) {
	ctl := &control{}
	_, socket, listen := startControl(t, ctl)
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}}
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		want   int
	}{
		{"get is not allowed", http.MethodGet, "/v1/scans", "", http.StatusMethodNotAllowed},
		{"unknown field", http.MethodPost, "/v1/active/disable", `{"reason":"x","force":true}`, http.StatusBadRequest},
		{"not json", http.MethodPost, "/v1/scans/plan", `{`, http.StatusBadRequest},
		{"bad scan body", http.MethodPost, "/v1/scans", `[]`, http.StatusBadRequest},
		{"bad enable body", http.MethodPost, "/v1/active/enable", `3`, http.StatusBadRequest},
		{"empty body enables", http.MethodPost, "/v1/active/enable", ``, http.StatusOK},
		{"get reload is not allowed", http.MethodGet, "/v1/config/reload", "", http.StatusMethodNotAllowed},
		{"reload takes no fields", http.MethodPost, "/v1/config/reload", `{"path":"/tmp/x.yaml"}`, http.StatusBadRequest},
		{"empty body reloads", http.MethodPost, "/v1/config/reload", ``, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, "http://x"+tt.path, strings.NewReader(tt.body))
			resp, err := hc.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Errorf("status %d, want %d", resp.StatusCode, tt.want)
			}
			if tt.want == http.StatusMethodNotAllowed && resp.Header.Get("Allow") != "POST" {
				t.Errorf("Allow = %q", resp.Header.Get("Allow"))
			}
		})
	}
	// The loopback listener never changes state.
	resp, err := http.Post("http://"+listen+"/v1/active/disable", "application/json", strings.NewReader(`{"reason":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || len(ctl.actors) != 2 {
		t.Errorf("POST on TCP: %d, control calls %d", resp.StatusCode, len(ctl.actors))
	}
	resp, err = http.Post("http://"+listen+"/v1/config/reload", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || len(ctl.actors) != 2 {
		t.Errorf("reload on TCP: %d, control calls %d", resp.StatusCode, len(ctl.actors))
	}
}

func TestOperatorWithoutControlOrPeer(t *testing.T) {
	srv := api.New(api.Options{})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/scans", strings.NewReader(`{}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("without control: %d", rec.Code)
	}
	for _, path := range []string{"/v1/active/disable", "/v1/active/enable", "/v1/scans/plan", "/v1/config/reload"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"reason":"x"}`)))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s without control: %d", path, rec.Code)
		}
	}
	// Without a connection in the context the actor is unknown.
	ctl := &control{}
	srv = api.New(api.Options{Control: ctl})
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/active/disable", strings.NewReader(`{"reason":"x"}`)))
	if rec.Code != http.StatusOK || ctl.actors[0] != "unknown" {
		t.Errorf("actor without peer = %q (%d)", ctl.actors, rec.Code)
	}
}
