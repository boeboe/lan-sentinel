// Package api is the local REST API (docs/API.md): JSON over the Unix socket
// /run/lan-sentinel/api.sock (mode 0660), and optionally over a 127.0.0.1
// listener that also serves /metrics. It reads through store.Reader, the
// same queries `--offline` uses, so online and offline answers agree. The
// client in this package is what the CLI uses online.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/events"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe/scheduler"
	"lan-sentinel/internal/store"
)

// Health states of `daemon status`.
const (
	StateOK        = "ok"
	StateDegraded  = "degraded"
	StateUnhealthy = "unhealthy"
)

// Status is the answer of /v1/status (`daemon status`).
type Status struct {
	Version    string                    `json:"version"`
	Commit     string                    `json:"commit"`
	Platform   string                    `json:"platform"`
	PID        int                       `json:"pid"`
	Started    time.Time                 `json:"started"`
	Now        time.Time                 `json:"now"`
	Replay     bool                      `json:"replay"`
	State      string                    `json:"state"`
	Problems   []string                  `json:"problems,omitempty"`
	Database   DatabaseStatus            `json:"database"`
	Active     store.ActiveState         `json:"active"`
	Clock      platform.ClockState       `json:"clock"` // kernel clock: synced, unsynced or unknown
	Interfaces []InterfaceStatus         `json:"interfaces"`
	Hosts      map[string]map[string]int `json:"hosts"` // interface → presence → count
	LastScan   *store.Scan               `json:"last_scan"`
}

// DatabaseStatus is the database part of the status.
type DatabaseStatus struct {
	Path          string `json:"path"`
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	Size          int64  `json:"size"`
	UsedSize      int64  `json:"used_size"`
	WALSize       int64  `json:"wal_size"`
	SchemaVersion int    `json:"schema_version"`
}

// InterfaceStatus is an interface with its collectors.
type InterfaceStatus struct {
	store.InterfaceInfo
	Collectors []CollectorStatus `json:"collectors"`
}

// CollectorStatus is a collector's state and, for a probe, its last
// periodic pass.
type CollectorStatus struct {
	platform.CollectorStatus
	LastPass *scheduler.PassSummary `json:"last_pass,omitempty"`
}

// Subscriber streams live events (events.Engine).
type Subscriber interface {
	Subscribe(buffer int) (<-chan store.Event, func())
}

// Options configures a Server.
type Options struct {
	Reader     *store.Reader
	Status     func(ctx context.Context) Status
	Interfaces func(ctx context.Context) ([]store.InterfaceInfo, error)
	Config     func() any // the effective configuration
	Events     Subscriber
	Metrics    http.Handler // served on the TCP listener only; nil disables it
	// Control serves the operator endpoints (kill switch, scans); nil
	// answers them with 503.
	Control Control
	Logger  *slog.Logger
}

// Server serves the API.
type Server struct {
	o    Options
	mux  *http.ServeMux
	done chan error
}

// New returns a server.
func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{o: o, mux: http.NewServeMux()}
	for path, h := range map[string]http.HandlerFunc{
		"/v1/status":              s.status,
		"/v1/interfaces":          s.interfaces,
		"/v1/hosts":               s.hosts,
		"/v1/hosts/find":          s.find,
		"/v1/hosts/{id}":          s.host,
		"/v1/hosts/{id}/history":  s.hostHistory,
		"/v1/hosts/{id}/evidence": s.evidence,
		"/v1/evidence":            s.evidenceFor,
		"/v1/history":             s.history,
		"/v1/observations":        s.observations,
		"/v1/events":              s.events,
		"/v1/events/stream":       s.stream,
		"/v1/services":            s.services,
		"/v1/dhcp/servers":        s.dhcpServers,
		"/v1/config":              s.config,
		"/v1/db":                  s.db,
		"/v1/db/check":            s.dbCheck,
	} {
		s.mux.HandleFunc(path, readOnly(h))
	}
	for path, h := range map[string]http.HandlerFunc{
		"/v1/active/disable": s.activeDisable,
		"/v1/active/enable":  s.activeEnable,
		"/v1/scans/plan":     s.scanPlan,
		"/v1/scans":          s.scan,
		"/v1/config/reload":  s.configReload,

		"/v1/hosts/{id}/description": s.hostDescription,
	} {
		s.mux.HandleFunc(path, postOnly(h))
	}
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, errorBody{"no such endpoint: " + r.URL.Path})
	})
	return s
}

// readOnly allows GET (and HEAD) only, answering other methods with a JSON
// 405: every v1 endpoint but the operator ones reads.
func readOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeJSON(w, http.StatusMethodNotAllowed, errorBody{r.Method + " is not allowed"})
			return
		}
		h(w, r)
	}
}

// loopbackOnly refuses requests whose Host header is not a loopback name
// or address (a web page in a local browser could otherwise reach the
// listener through DNS rebinding) and anything but reads, so endpoints
// that change state stay on the Unix socket, where file permissions and
// SO_PEERCRED apply.
func loopbackOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if hst, _, err := net.SplitHostPort(r.Host); err == nil {
			host = hst
		}
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			writeJSON(w, http.StatusForbidden, errorBody{"Host must be a loopback address"})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeJSON(w, http.StatusMethodNotAllowed, errorBody{"the TCP listener only serves reads"})
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Handler returns the API handler (without /metrics).
func (s *Server) Handler() http.Handler { return s.mux }

// Start listens on the Unix socket (and on listen, a loopback address, if
// set) and serves in the background until ctx is cancelled; Wait returns
// once the servers have shut down. The socket is created with mode 0660 so
// only its owner (root, under the reference unit) and group can use it.
func (s *Server) Start(ctx context.Context, socket, listen string) error {
	ul, err := listenUnix(socket)
	if err != nil {
		return err
	}
	servers := []*http.Server{s.server(ctx, s.mux)}
	listeners := []net.Listener{ul}
	if listen != "" {
		tl, err := net.Listen("tcp", listen)
		if err != nil {
			_ = ul.Close()
			_ = os.Remove(socket)
			return fmt.Errorf("api listener %s: %w", listen, err)
		}
		mux := http.NewServeMux()
		mux.Handle("/v1/", s.mux)
		if s.o.Metrics != nil {
			mux.Handle("GET /metrics", s.o.Metrics)
		}
		servers, listeners = append(servers, s.server(ctx, loopbackOnly(mux))), append(listeners, tl)
	}
	s.done = make(chan error, 1)
	errc := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { errc <- srv.Serve(listeners[i]) }()
	}
	s.o.Logger.Info("api listening", "socket", socket, "listen", listen)
	go func() {
		var err error
		select {
		case <-ctx.Done():
		case err = <-errc:
		}
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, srv := range servers {
			_ = srv.Shutdown(sctx)
		}
		_ = os.Remove(socket)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			err = fmt.Errorf("api: %w", err)
		} else {
			err = nil
		}
		s.done <- err
	}()
	return nil
}

// Wait blocks until the servers started by Start have shut down.
func (s *Server) Wait() error {
	if s.done == nil {
		return nil
	}
	return <-s.done
}

func (s *Server) server(ctx context.Context, h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnContext:       func(ctx context.Context, c net.Conn) context.Context { return context.WithValue(ctx, connKey{}, c) },
		ErrorLog:          slog.NewLogLogger(s.o.Logger.Handler(), slog.LevelDebug),
	}
}

// listenUnix replaces a stale socket and creates a new one, mode 0660.
func listenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("api socket directory: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("api socket %s: exists and is not a socket", path)
		}
		if c, err := net.Dial("unix", path); err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("api socket %s: another daemon is listening", path)
		}
		_ = os.Remove(path)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("api socket %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("api socket %s: %w", path, err)
	}
	return l, nil
}

// errorBody is every error response.
type errorBody struct {
	Error string `json:"error"`
}

// badParam is an invalid query parameter.
type badParam struct{ msg string }

func (b badParam) Error() string { return b.msg }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var bp badParam
	switch {
	case errors.As(err, &bp), errors.Is(err, store.ErrBadQuery):
		status = http.StatusBadRequest
	case errors.Is(err, store.ErrNotFound):
		status = http.StatusNotFound
	case store.IsBusy(err):
		status = http.StatusServiceUnavailable
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// The client gave up (Ctrl-C, --timeout): nothing to log.
	default:
		s.o.Logger.Warn("api request failed", "err", err)
	}
	writeJSON(w, status, errorBody{err.Error()})
}

func (s *Server) reply(w http.ResponseWriter, v any, err error) {
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// params parses query parameters, remembering the first error.
type params struct {
	r   *http.Request
	err error
}

func (p *params) str(name string) string { return p.r.URL.Query().Get(name) }

func (p *params) time(name string) time.Time {
	v := p.str(name)
	if v == "" || p.err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		p.err = badParam{fmt.Sprintf("%s: want an RFC 3339 time, got %q", name, v)}
	}
	return t
}

func (p *params) timePtr(name string) *time.Time {
	t := p.time(name)
	if t.IsZero() {
		return nil
	}
	return &t
}

func (p *params) int(name string) int {
	v := p.str(name)
	if v == "" || p.err != nil {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		p.err = badParam{fmt.Sprintf("%s: want a non-negative integer, got %q", name, v)}
	}
	return n
}

func (p *params) bool(name string) bool {
	v := p.str(name)
	if v == "" || p.err != nil {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		p.err = badParam{fmt.Sprintf("%s: want true or false, got %q", name, v)}
	}
	return b
}

func (p *params) kind() store.QueryKind {
	k := store.QueryKind(p.str("kind"))
	if k != "" && !slices.Contains([]store.QueryKind{store.KindHost, store.KindMAC, store.KindIP, store.KindName}, k) && p.err == nil {
		p.err = badParam{fmt.Sprintf("kind: want host, mac, ip or name, got %q", k)}
	}
	return k
}

// types resolves event type parameters given as spec or CLI names.
func (p *params) types() []string {
	var out []string
	for _, v := range p.r.URL.Query()["type"] {
		for _, name := range strings.Split(v, ",") {
			t, ok := EventType(name)
			if !ok && p.err == nil {
				p.err = badParam{fmt.Sprintf("type: unknown event type %q", name)}
			}
			out = append(out, string(t))
		}
	}
	return out
}

// EventType resolves an event type from its spec name (IP_CHANGED) or CLI
// name (ip-changed).
func EventType(name string) (events.Type, bool) {
	if s, ok := events.Lookup(events.Type(strings.ToUpper(name))); ok {
		return s.Type, true
	}
	return events.ByCLIName(strings.ToLower(name))
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.o.Status(r.Context()))
}

func (s *Server) interfaces(w http.ResponseWriter, r *http.Request) {
	ifs, err := s.o.Interfaces(r.Context())
	s.reply(w, ifs, err)
}

func (s *Server) hosts(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	f := store.HostFilter{Interface: p.str("interface"), Query: p.str("q"), QueryKind: p.kind(), Vendor: p.str("vendor"),
		Device: p.str("device"), Port: p.int("port"), SeenSince: p.time("seen_since")}
	switch pr := p.str("presence"); pr {
	case "", "any":
	case "live":
		f.Live = true
	case "notlive":
		f.NotLive = true
	default:
		p.err = badParam{fmt.Sprintf("presence: want live or notlive, got %q", pr)}
	}
	if p.err != nil {
		s.fail(w, p.err)
		return
	}
	hosts, err := s.o.Reader.Hosts(r.Context(), f)
	s.reply(w, nonNil(hosts), err)
}

func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

func (s *Server) find(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	q := store.FindQuery{Query: p.str("q"), Kind: p.kind(), Interface: p.str("interface"), At: p.timePtr("at")}
	if q.Query == "" && p.err == nil {
		p.err = badParam{"q: required"}
	}
	if p.err != nil {
		s.fail(w, p.err)
		return
	}
	res, err := s.o.Reader.Find(r.Context(), q)
	s.reply(w, res, err)
}

func (s *Server) host(w http.ResponseWriter, r *http.Request) {
	h, err := s.o.Reader.Host(r.Context(), r.PathValue("id"))
	s.reply(w, h, err)
}

func (s *Server) hostHistory(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	q := store.HistoryQuery{Query: r.PathValue("id"), Kind: store.KindHost, Since: p.time("since"), Until: p.time("until")}
	if p.err != nil {
		s.fail(w, p.err)
		return
	}
	if _, err := s.o.Reader.Host(r.Context(), q.Query); err != nil {
		s.fail(w, err)
		return
	}
	evs, err := s.o.Reader.History(r.Context(), q)
	s.reply(w, evs, err)
}

func (s *Server) evidence(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	since := p.time("since")
	if p.err != nil {
		s.fail(w, p.err)
		return
	}
	ev, err := s.o.Reader.Evidence(r.Context(), r.PathValue("id"), since)
	s.reply(w, ev, err)
}

// evidenceFor answers `hosts evidence` for every host that ever matched q,
// in one snapshot.
func (s *Server) evidenceFor(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	f := store.HostFilter{Query: p.str("q"), QueryKind: p.kind(), Interface: p.str("interface")}
	since := p.time("since")
	if f.Query == "" && p.err == nil {
		p.err = badParam{"q: required"}
	}
	if p.err != nil {
		s.fail(w, p.err)
		return
	}
	evs, err := s.o.Reader.EvidenceFor(r.Context(), f, since)
	s.reply(w, evs, err)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	q := store.HistoryQuery{Query: p.str("q"), Kind: p.kind(), Interface: p.str("interface"), Since: p.time("since"), Until: p.time("until")}
	if q.Query == "" && p.err == nil {
		p.err = badParam{"q: required"}
	}
	if p.err != nil {
		s.fail(w, p.err)
		return
	}
	evs, err := s.o.Reader.History(r.Context(), q)
	s.reply(w, evs, err)
}

func (s *Server) observations(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	f := store.ObservationFilter{HostID: p.str("host"), Interface: p.str("interface"), MAC: p.str("mac"), IP: p.str("ip"),
		Source: p.str("source"), Unbound: p.bool("unbound"), Since: p.time("since"), Until: p.time("until"), Limit: p.int("limit")}
	rollups := p.bool("rollups")
	if p.err != nil {
		s.fail(w, p.err)
		return
	}
	if rollups {
		rs, err := s.o.Reader.Rollups(r.Context(), f)
		s.reply(w, rs, err)
		return
	}
	obs, err := s.o.Reader.Observations(r.Context(), f)
	s.reply(w, obs, err)
}

func (s *Server) eventFilter(p *params) store.EventFilter {
	return store.EventFilter{Since: p.time("since"), Until: p.time("until"), Types: p.types(), Interface: p.str("interface"),
		MAC: p.str("mac"), IP: p.str("ip"), HostID: p.str("host"), Limit: p.int("limit")}
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	f := s.eventFilter(p)
	if p.err != nil {
		s.fail(w, p.err)
		return
	}
	evs, err := s.o.Reader.Events(r.Context(), f)
	s.reply(w, evs, err)
}

// stream writes live events as JSON lines until the client goes away
// (`watch`). Filters: interface, type (repeatable) and port (service
// events of that port).
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	iface, types, port := p.str("interface"), p.types(), p.int("port")
	if p.err != nil {
		s.fail(w, p.err)
		return
	}
	if s.o.Events == nil {
		s.fail(w, errors.New("event stream unavailable"))
		return
	}
	ch, cancel := s.o.Events.Subscribe(256)
	defer cancel()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	enc := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			if !matches(e, iface, types, port) {
				continue
			}
			if err := enc.Encode(e); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

// matches applies the stream filters.
func matches(e store.Event, iface string, types []string, port int) bool {
	if iface != "" && e.Interface != iface {
		return false
	}
	if len(types) > 0 && !slices.Contains(types, e.Type) {
		return false
	}
	if port > 0 {
		var ev struct {
			Service *struct {
				Port int `json:"port"`
			} `json:"service"`
		}
		if json.Unmarshal(e.Evidence, &ev) != nil || ev.Service == nil || ev.Service.Port != port {
			return false
		}
	}
	return true
}

func (s *Server) services(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	f := store.ServiceFilter{Port: p.int("port"), State: p.str("state"), Interface: p.str("interface")}
	if p.err != nil {
		s.fail(w, p.err)
		return
	}
	svc, err := s.o.Reader.Services(r.Context(), f)
	s.reply(w, svc, err)
}

func (s *Server) dhcpServers(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	f := store.DHCPServerFilter{Interface: p.str("interface"), Status: p.str("status")}
	switch strings.ToLower(f.Status) {
	case "", "allowed", "unexpected", "unchecked":
	default:
		s.fail(w, badParam{"status: want allowed, unexpected or unchecked, got " + strconv.Quote(f.Status)})
		return
	}
	servers, err := s.o.Reader.DHCPServers(r.Context(), f)
	s.reply(w, servers, err)
}

func (s *Server) config(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.o.Config())
}

func (s *Server) db(w http.ResponseWriter, r *http.Request) {
	info, err := s.o.Reader.DBInfo(r.Context())
	s.reply(w, info, err)
}

func (s *Server) dbCheck(w http.ResponseWriter, r *http.Request) {
	res, err := s.o.Reader.Check(r.Context())
	s.reply(w, res, err)
}

// WithConfig completes interfaces from the database with the configuration:
// passive, active and replay modes, and configured interfaces the database
// does not know yet. Interfaces no longer configured are kept (history).
func WithConfig(ifs []store.InterfaceInfo, cfg *config.Config) []store.InterfaceInfo {
	byName := map[string]int{}
	for i := range ifs {
		byName[ifs[i].Name] = i
	}
	for _, ic := range cfg.Interfaces {
		i, ok := byName[ic.Name]
		if !ok {
			ifs = append(ifs, store.InterfaceInfo{Name: ic.Name, State: "unknown", Prefixes: []string{}})
			i = len(ifs) - 1
		}
		ifs[i].Passive, ifs[i].Active, ifs[i].Replay = ic.PassiveEnabled(), ic.Active.Enabled, ic.IsReplay()
	}
	slices.SortFunc(ifs, func(a, b store.InterfaceInfo) int { return strings.Compare(a.Name, b.Name) })
	return ifs
}
