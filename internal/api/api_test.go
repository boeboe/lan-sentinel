package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/events"
	"lan-sentinel/internal/metrics"
	"lan-sentinel/internal/store"
	"lan-sentinel/internal/store/storetest"
)

const golden = "../../test/golden/reconstruction/"

var t0 = storetest.T0

// hub is a test event source.
type hub struct {
	mu   sync.Mutex
	subs []chan store.Event
}

func (h *hub) Subscribe(n int) (<-chan store.Event, func()) {
	ch := make(chan store.Event, n)
	h.mu.Lock()
	h.subs = append(h.subs, ch)
	h.mu.Unlock()
	return ch, func() {}
}

func (h *hub) publish(e store.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ch := range h.subs {
		ch <- e
	}
}

func (h *hub) subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

type fixture struct {
	client *api.Client
	exp    storetest.Expected
	hub    *hub
	socket string
	listen string
	cancel context.CancelFunc
	srv    *api.Server
}

func start(t *testing.T) *fixture {
	t.Helper()
	st, _, exp := storetest.Seed(t, golden)
	storetest.AddDHCPServers(t, st)
	r, err := st.Reader(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	cfg := config.Defaults()
	cfg.Interfaces = []config.InterfaceConfig{{Name: "eth1"}, {Name: "eth2"}}
	h := &hub{}
	srv := api.New(api.Options{
		Reader: r, Events: h,
		Status: func(context.Context) api.Status { return api.Status{Version: "test", State: api.StateDegraded} },
		Interfaces: func(ctx context.Context) ([]store.InterfaceInfo, error) {
			ifs, err := r.Interfaces(ctx)
			return api.WithConfig(ifs, cfg), err
		},
		Config: func() any { return cfg },
		Metrics: metrics.Handler(func(*http.Request) []metrics.Family {
			return []metrics.Family{{Name: "lan_sentinel_up", Help: "Up.", Type: metrics.Gauge, Samples: []metrics.Sample{{Value: 1}}}}
		}),
	})
	dir := t.TempDir()
	f := &fixture{exp: exp, hub: h, socket: filepath.Join(dir, "run", "api.sock"), listen: freePort(t), srv: srv}
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	if err := srv.Start(ctx, f.socket, f.listen); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = srv.Wait() })
	f.client = api.NewClient(f.socket, 5*time.Second)
	return f
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestEndpoints(t *testing.T) {
	f := start(t)
	ctx := context.Background()
	c := f.client

	if fi, err := os.Stat(f.socket); err != nil || fi.Mode().Perm() != 0o660 {
		t.Errorf("socket mode: %v %v", err, fi)
	}
	st, err := c.Status(ctx)
	if err != nil || st.Version != "test" || st.State != api.StateDegraded {
		t.Errorf("status: %v %+v", err, st)
	}
	ifs, err := c.Interfaces(ctx)
	if err != nil || len(ifs) != 3 || ifs[2].Name != "eth2" || ifs[2].State != "unknown" || !ifs[1].Passive {
		t.Errorf("interfaces: %v %+v", err, ifs)
	}
	hosts, err := c.Hosts(ctx, store.HostFilter{Interface: "eth1", Live: true})
	if err != nil || len(hosts) != 1 || hosts[0].MAC != f.exp.Hosts["B"] {
		t.Errorf("live hosts on eth1: %v %+v", err, hosts)
	}
	if hosts, err = c.Hosts(ctx, store.HostFilter{NotLive: true, Vendor: "siemens", SeenSince: t0}); err != nil || len(hosts) != 1 {
		t.Errorf("stale Siemens hosts: %v %+v", err, hosts)
	}
	all, err := c.Hosts(ctx, store.HostFilter{Query: "192.168.110.51", QueryKind: store.KindIP})
	if err != nil || len(all) != 2 {
		t.Fatalf("hosts that held Y: %v %+v", err, all)
	}
	h, err := c.Host(ctx, all[0].HostID)
	if err != nil || h.HostID != all[0].HostID || len(h.Addresses) == 0 {
		t.Errorf("host: %v %+v", err, h)
	}
	at := t0.Add(190 * time.Minute)
	res, err := c.Find(ctx, store.FindQuery{Query: "192.168.110.51", Interface: "eth1", At: &at})
	if err != nil || len(res.Hosts) != 2 || !res.Hosts[0].Conflict || res.Hosts[0].ConflictEvent == nil {
		t.Errorf("find Y in conflict: %v %+v", err, res)
	}
	if res, err = c.Find(ctx, store.FindQuery{Query: f.exp.Hosts["A"], Kind: store.KindMAC}); err != nil || len(res.Hosts) != 1 {
		t.Errorf("find by MAC: %v %+v", err, res)
	}
	evs, err := c.History(ctx, store.HistoryQuery{Query: "192.168.110.50", Interface: "eth1", Until: t0.Add(4 * time.Hour)})
	if err != nil || len(evs) != 4 {
		t.Errorf("history of X: %v %d", err, len(evs))
	}
	ev, err := c.Evidence(ctx, all[0].HostID, t0)
	if err != nil || len(ev.Events) == 0 || len(ev.Counts) == 0 {
		t.Errorf("evidence: %v %+v", err, ev)
	}
	obs, err := c.Observations(ctx, store.ObservationFilter{Unbound: true, Limit: 5, Since: t0, Until: t0.Add(24 * time.Hour)})
	if err != nil || len(obs) != 1 {
		t.Errorf("unbound observations: %v %+v", err, obs)
	}
	if rs, err := c.Rollups(ctx, store.ObservationFilter{Interface: "eth1"}); err != nil || len(rs) != 0 {
		t.Errorf("roll-ups: %v %+v", err, rs)
	}
	dup, err := c.Events(ctx, store.EventFilter{Types: []string{"duplicate-ip", "DUPLICATE_IP_RESOLVED"}, Interface: "eth1", Limit: 10})
	if err != nil || len(dup) != 2 {
		t.Errorf("conflict events: %v %+v", err, dup)
	}
	svc, err := c.Services(ctx, store.ServiceFilter{Port: 502, State: "OPEN"})
	if err != nil || len(svc) != 1 {
		t.Errorf("services: %v %+v", err, svc)
	}
	servers, err := c.DHCPServers(ctx, store.DHCPServerFilter{Interface: "eth1"})
	if err != nil || len(servers) != 2 || servers[0].ServerID != "192.168.110.1" || servers[0].Config["router"] != "192.168.110.1" || servers[1].ServerID != "" {
		t.Errorf("dhcp servers: %v %+v", err, servers)
	}
	if rogue, err := c.DHCPServers(ctx, store.DHCPServerFilter{Status: "unexpected"}); err != nil || len(rogue) != 1 || rogue[0].MAC != "02:00:00:00:00:66" {
		t.Errorf("unexpected dhcp servers: %v %+v", err, rogue)
	}
	raw, err := c.Config(ctx)
	if err != nil || !strings.Contains(string(raw), `"name":"eth2"`) {
		t.Errorf("config: %v %s", err, raw)
	}
	if info, err := c.DBInfo(ctx); err != nil || info.Rows["hosts"] != 4 {
		t.Errorf("db: %v %+v", err, info)
	}
	if chk, err := c.DBCheck(ctx); err != nil || !chk.OK {
		t.Errorf("db check: %v %+v", err, chk)
	}

	// Metrics only on the loopback listener, the API on both.
	resp, err := http.Get("http://" + f.listen + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "lan_sentinel_up 1") {
		t.Errorf("metrics: %s", b)
	}
	if resp, err = http.Get("http://" + f.listen + "/v1/status"); err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("status over TCP: %v %v", err, resp)
	} else {
		resp.Body.Close()
	}
}

func TestErrors(t *testing.T) {
	f := start(t)
	ctx := context.Background()
	c := f.client
	if _, err := c.Host(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown host: %v", err)
	}
	var apiErr *api.Error
	if _, err := c.Find(ctx, store.FindQuery{Query: "plc", Kind: store.KindIP}); !errors.Is(err, store.ErrBadQuery) || !errors.As(err, &apiErr) || apiErr.Status != 400 {
		t.Errorf("bad query: %v", err)
	}
	for _, path := range []string{
		"/v1/hosts/find", "/v1/history", "/v1/hosts?presence=sometimes", "/v1/hosts?kind=planet&q=x", "/v1/events?type=nonsense",
		"/v1/events?since=yesterday", "/v1/observations?limit=-1", "/v1/observations?unbound=maybe", "/v1/services?port=x",
		"/v1/hosts/x/history?since=x", "/v1/hosts/x/evidence?since=x", "/v1/events/stream?port=x", "/v1/dhcp/servers?status=rogue",
	} {
		resp, err := http.Get("http://" + f.listen + path)
		if err != nil {
			t.Fatal(err)
		}
		var body struct{ Error string }
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || body.Error == "" {
			t.Errorf("%s: %d %q, want 400 with a message", path, resp.StatusCode, body.Error)
		}
	}
	if _, err := c.History(ctx, store.HistoryQuery{Query: "00000000-0000-0000-0000-000000000000", Kind: store.KindHost}); err != nil {
		t.Errorf("history of an unknown host id over /v1/history: %v", err)
	}
	resp, err := http.Get("http://" + f.listen + "/v1/hosts/00000000-0000-0000-0000-000000000000/history")
	if err != nil || resp.StatusCode != http.StatusNotFound {
		t.Errorf("history of an unknown host: %v %v", err, resp)
	}
	resp.Body.Close()

	// Unreachable: no daemon on the socket.
	gone := api.NewClient(filepath.Join(t.TempDir(), "none.sock"), time.Second)
	if _, err := gone.Status(ctx); !errors.Is(err, api.ErrUnreachable) {
		t.Errorf("no socket: %v", err)
	}
}

func TestStream(t *testing.T) {
	f := start(t)
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan store.Event, 4)
	done := make(chan error, 1)
	go func() {
		done <- f.client.Stream(ctx, "eth1", []string{"service-opened", "IP_CHANGED"}, 502, func(e store.Event) error {
			got <- e
			return nil
		})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for f.hub.subscribers() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no subscriber")
		}
		time.Sleep(5 * time.Millisecond)
	}
	svc := json.RawMessage(`{"ts":"2026-10-01T14:00:00Z","service":{"proto":"tcp","port":502,"state":"OPEN"}}`)
	f.hub.publish(store.Event{Type: "SERVICE_OPENED", Interface: "eth0", Evidence: svc})                                        // other interface
	f.hub.publish(store.Event{Type: "HOST_DISCOVERED", Interface: "eth1", Evidence: json.RawMessage(`{}`)})                     // other type
	f.hub.publish(store.Event{Type: "SERVICE_OPENED", Interface: "eth1", Evidence: json.RawMessage(`{"service":{"port":80}}`)}) // other port
	f.hub.publish(store.Event{Type: "SERVICE_OPENED", Interface: "eth1", New: "tcp/502", Evidence: svc})
	select {
	case e := <-got:
		if e.New != "tcp/502" {
			t.Errorf("streamed %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event streamed")
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("stream after cancel: %v", err)
	}

	// The daemon going away ends the stream with ErrUnreachable.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { done <- f.client.Stream(ctx2, "", nil, 0, func(store.Event) error { return nil }) }()
	for f.hub.subscribers() < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	f.cancel()
	if err := <-done; !errors.Is(err, api.ErrUnreachable) {
		t.Errorf("stream when the daemon stops: %v", err)
	}
}

func TestSocketHandling(t *testing.T) {
	f := start(t)
	ctx := context.Background()
	// A second server on the same socket is refused while the first runs.
	second := api.New(api.Options{})
	if err := second.Start(ctx, f.socket, ""); err == nil || !strings.Contains(err.Error(), "another daemon") {
		t.Errorf("second server: %v", err)
	}
	// A regular file in the way is refused; a stale socket is replaced.
	dir := t.TempDir()
	file := filepath.Join(dir, "file.sock")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := second.Start(ctx, file, ""); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("file in the way: %v", err)
	}
	stale := filepath.Join(dir, "stale.sock")
	l, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = l.Close()
	sctx, cancel := context.WithCancel(ctx)
	if err := second.Start(sctx, stale, ""); err != nil {
		t.Errorf("stale socket: %v", err)
	}
	cancel()
	if err := second.Wait(); err != nil {
		t.Errorf("wait: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("socket left after shutdown: %v", err)
	}
	// A busy TCP address fails Start and removes the socket again.
	third := api.New(api.Options{})
	sock := filepath.Join(dir, "third.sock")
	if err := third.Start(ctx, sock, f.listen); err == nil {
		t.Error("busy listen address accepted")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("socket left after a failed start: %v", err)
	}
	if err := api.New(api.Options{}).Wait(); err != nil {
		t.Errorf("wait without start: %v", err)
	}
}

func TestEventType(t *testing.T) {
	for _, name := range []string{"ip-changed", "IP_CHANGED", "ip_changed", "db-recreated"} {
		if _, ok := api.EventType(name); !ok {
			t.Errorf("EventType(%q) not found", name)
		}
	}
	if _, ok := api.EventType("nonsense"); ok {
		t.Error("unknown type resolved")
	}
}

func TestRoutesAndLoopbackGuard(t *testing.T) {
	f := start(t)
	do := func(method, url, host string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body struct{ Error string }
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body.Error
	}
	base := "http://" + f.listen
	for _, tt := range []struct {
		method, path, host string
		want               int
	}{
		{http.MethodGet, "/v1/nope", "", http.StatusNotFound},
		{http.MethodPost, "/v1/status", "", http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/status", "evil.example:9734", http.StatusForbidden},
		{http.MethodGet, "/v1/status", "localhost:9734", http.StatusOK},
		{http.MethodGet, "/v1/status", "[::1]:9734", http.StatusOK},
		{http.MethodPost, "/metrics", "", http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/evidence", "", http.StatusBadRequest},
	} {
		if code, msg := do(tt.method, base+tt.path, tt.host); code != tt.want || (code != http.StatusOK && msg == "") {
			t.Errorf("%s %s (Host %q) = %d %q, want %d with a JSON error", tt.method, tt.path, tt.host, code, msg, tt.want)
		}
	}
	// The socket refuses writes too.
	sock := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", f.socket)
	}}}
	resp, err := sock.Post("http://x/v1/db/check", "application/json", nil)
	if err != nil || resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET, HEAD" {
		t.Errorf("POST over the socket: %v %v", err, resp)
	}
	resp.Body.Close()

	evs, err := f.client.EvidenceFor(context.Background(), store.HostFilter{Query: f.exp.Hosts["A"]}, time.Time{})
	if err != nil || len(evs) != 1 || evs[0].Host.MAC != f.exp.Hosts["A"] {
		t.Errorf("evidence for: %v %+v", err, evs)
	}
	if _, err := f.client.Events(context.Background(), store.EventFilter{MAC: "nonsense"}); !errors.Is(err, store.ErrBadQuery) {
		t.Errorf("bad MAC filter: %v", err)
	}
}

// A client that cannot open the socket gets a permission error, not
// "unreachable": the daemon may well be running.
func TestSocketPermission(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores socket permissions")
	}
	f := start(t)
	if err := os.Chmod(f.socket, 0); err != nil {
		t.Fatal(err)
	}
	_, err := f.client.Status(context.Background())
	if !errors.Is(err, os.ErrPermission) || errors.Is(err, api.ErrUnreachable) {
		t.Errorf("status on an inaccessible socket: %v", err)
	}
}

// The stream unsubscribes when the client goes away (real event engine).
func TestStreamUnsubscribes(t *testing.T) {
	st, _, _ := storetest.Seed(t, golden)
	r, err := st.Reader(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	engine := events.NewEngine(st, slog.New(slog.DiscardHandler), nil)
	srv := api.New(api.Options{Reader: r, Events: engine})
	socket := filepath.Join(t.TempDir(), "api.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx, socket, ""); err != nil {
		t.Fatal(err)
	}
	sctx, scancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- api.NewClient(socket, time.Second).Stream(sctx, "", nil, 0, func(store.Event) error { return nil })
	}()
	waitUntil(t, func() bool { return engine.Subscribers() == 1 })
	scancel()
	<-done
	waitUntil(t, func() bool { return engine.Subscribers() == 0 })
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
