package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/scheduler"
	"lan-sentinel/internal/store"
)

// ErrUnreachable means the daemon could not be reached (CLI exit 3).
var ErrUnreachable = errors.New("daemon unreachable")

// Error is an error response from the API.
type Error struct {
	Status  int
	Message string
	Body    []byte // the raw answer
}

func (e *Error) Error() string { return e.Message }

// Unwrap maps 404 and 400 to the store's errors and 422 to
// ErrConfigRejected.
func (e *Error) Unwrap() error {
	switch e.Status {
	case http.StatusNotFound:
		return store.ErrNotFound
	case http.StatusBadRequest:
		return store.ErrBadQuery
	case http.StatusUnprocessableEntity:
		return ErrConfigRejected
	}
	return nil
}

// Client talks to the API over the Unix socket.
type Client struct {
	socket  string
	timeout time.Duration
	http    *http.Client
	stream  *http.Client
}

// NewClient returns a client for the socket. timeout bounds each request
// except the event stream.
func NewClient(socket string, timeout time.Duration) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &Client{socket: socket, timeout: timeout, http: &http.Client{Transport: tr, Timeout: timeout},
		stream: &http.Client{Transport: tr}}
}

func (c *Client) do(ctx context.Context, hc *http.Client, path string, q url.Values) (*http.Response, error) {
	return c.send(ctx, hc, http.MethodGet, path, q, nil)
}

func (c *Client) send(ctx context.Context, hc *http.Client, method, path string, q url.Values, body io.Reader) (*http.Response, error) {
	u := "http://lan-sentinel" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			if errors.Is(op.Err, os.ErrPermission) {
				// The daemon may well be running; the caller lacks access.
				return nil, fmt.Errorf("api socket %s: %w", c.socket, op.Err)
			}
			return nil, fmt.Errorf("%w at %s: %w", ErrUnreachable, c.socket, op.Err)
		}
		return nil, fmt.Errorf("api %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var body errorBody
		if json.Unmarshal(raw, &body) != nil || body.Error == "" {
			body.Error = resp.Status
		}
		return nil, &Error{Status: resp.StatusCode, Message: body.Error, Body: raw}
	}
	return resp, nil
}

// post sends v as JSON and decodes the answer into out.
func (c *Client) post(ctx context.Context, hc *http.Client, path string, v, out any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	resp, err := c.send(ctx, hc, http.MethodPost, path, nil, bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("api %s: decode: %w", path, err)
	}
	return nil
}

// DisableActive sets the kill switch.
func (c *Client) DisableActive(ctx context.Context, reason string) (store.ActiveState, error) {
	var st store.ActiveState
	err := c.post(ctx, c.http, "/v1/active/disable", SwitchRequest{Reason: reason}, &st)
	return st, err
}

// EnableActive clears the kill switch.
func (c *Client) EnableActive(ctx context.Context, reason string) (store.ActiveState, error) {
	var st store.ActiveState
	err := c.post(ctx, c.http, "/v1/active/enable", SwitchRequest{Reason: reason}, &st)
	return st, err
}

// IdentifyRun sends one identification probe through the daemon.
func (c *Client) IdentifyRun(ctx context.Context, hostID, probe string) (store.IdentifyAttempt, error) {
	var a store.IdentifyAttempt
	err := c.post(ctx, c.http, "/v1/hosts/"+url.PathEscape(hostID)+"/identify", IdentifyRequest{Probe: probe}, &a)
	return a, err
}

// SetDescription sets a host's description; "" removes it.
func (c *Client) SetDescription(ctx context.Context, hostID, description string) (store.HostSummary, error) {
	var h store.HostSummary
	err := c.post(ctx, c.http, "/v1/hosts/"+url.PathEscape(hostID)+"/description", DescriptionRequest{Description: &description}, &h)
	return h, err
}

// ReloadConfig makes the daemon re-read its configuration file. A rejected
// file is an *Error that wraps ErrConfigRejected.
func (c *Client) ReloadConfig(ctx context.Context) (ReloadResult, error) {
	var res ReloadResult
	err := c.post(ctx, c.http, "/v1/config/reload", struct{}{}, &res)
	return res, err
}

// PlanScan computes a scan plan in the daemon.
func (c *Client) PlanScan(ctx context.Context, req probe.Request) (probe.Plan, error) {
	var p probe.Plan
	err := c.post(ctx, c.http, "/v1/scans/plan", req, &p)
	return p, err
}

// Scan runs an operator scan and waits for it, without the request
// timeout. A refused scan returns scheduler.ErrScanRefused with the plan
// in the result.
func (c *Client) Scan(ctx context.Context, req probe.Request) (scheduler.ScanResult, error) {
	var res scheduler.ScanResult
	err := c.post(ctx, c.stream, "/v1/scans", req, &res)
	var ae *Error
	if errors.As(err, &ae) && ae.Status == http.StatusConflict && json.Unmarshal(ae.Body, &res) == nil && len(res.Plan.Interfaces)+len(res.Plan.Reasons) > 0 {
		return res, scheduler.ErrScanRefused
	}
	return res, err
}

func (c *Client) get(ctx context.Context, path string, q url.Values, v any) error {
	resp, err := c.do(ctx, c.http, path, q)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("api %s: decode: %w", path, err)
	}
	return nil
}

// values builds query parameters, leaving out empty ones.
type values url.Values

func (v values) str(k, s string) values {
	if s != "" {
		url.Values(v).Set(k, s)
	}
	return v
}

func (v values) time(k string, t time.Time) values {
	if !t.IsZero() {
		url.Values(v).Set(k, t.UTC().Format(time.RFC3339Nano))
	}
	return v
}

func (v values) int(k string, n int) values {
	if n > 0 {
		url.Values(v).Set(k, strconv.Itoa(n))
	}
	return v
}

func (v values) bool(k string, b bool) values {
	if b {
		url.Values(v).Set(k, "true")
	}
	return v
}

// Status returns the daemon status.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var s Status
	return s, c.get(ctx, "/v1/status", nil, &s)
}

// Interfaces lists the interfaces.
func (c *Client) Interfaces(ctx context.Context) ([]store.InterfaceInfo, error) {
	var out []store.InterfaceInfo
	return out, c.get(ctx, "/v1/interfaces", nil, &out)
}

// Hosts lists hosts.
func (c *Client) Hosts(ctx context.Context, f store.HostFilter) ([]store.HostSummary, error) {
	presence := ""
	switch {
	case f.Live && !f.NotLive:
		presence = "live"
	case f.NotLive && !f.Live:
		presence = "notlive"
	}
	q := values{}.str("interface", f.Interface).str("q", f.Query).str("kind", string(f.QueryKind)).str("presence", presence).
		str("vendor", f.Vendor).str("device", f.Device).int("port", f.Port).time("seen_since", f.SeenSince)
	var out []store.HostSummary
	return out, c.get(ctx, "/v1/hosts", url.Values(q), &out)
}

// Host returns one host.
func (c *Client) Host(ctx context.Context, id string) (store.Host, error) {
	var h store.Host
	return h, c.get(ctx, "/v1/hosts/"+url.PathEscape(id), nil, &h)
}

// Find answers a find query.
func (c *Client) Find(ctx context.Context, f store.FindQuery) (store.FindResult, error) {
	q := values{}.str("q", f.Query).str("kind", string(f.Kind)).str("interface", f.Interface)
	if f.At != nil {
		q = q.time("at", *f.At)
	}
	var res store.FindResult
	return res, c.get(ctx, "/v1/hosts/find", url.Values(q), &res)
}

// History returns a timeline.
func (c *Client) History(ctx context.Context, h store.HistoryQuery) ([]store.Event, error) {
	q := values{}.str("q", h.Query).str("kind", string(h.Kind)).str("interface", h.Interface).time("since", h.Since).time("until", h.Until)
	var out []store.Event
	return out, c.get(ctx, "/v1/history", url.Values(q), &out)
}

// EvidenceFor returns the evidence for every host that ever matched the
// filter's query, from one snapshot.
func (c *Client) EvidenceFor(ctx context.Context, f store.HostFilter, since time.Time) ([]store.Evidence, error) {
	q := values{}.str("q", f.Query).str("kind", string(f.QueryKind)).str("interface", f.Interface).time("since", since)
	var out []store.Evidence
	return out, c.get(ctx, "/v1/evidence", url.Values(q), &out)
}

// Evidence returns the evidence for one host.
func (c *Client) Evidence(ctx context.Context, id string, since time.Time) (store.Evidence, error) {
	var ev store.Evidence
	return ev, c.get(ctx, "/v1/hosts/"+url.PathEscape(id)+"/evidence", url.Values(values{}.time("since", since)), &ev)
}

func observationValues(f store.ObservationFilter) values {
	return values{}.str("host", f.HostID).str("interface", f.Interface).str("mac", f.MAC).str("ip", f.IP).str("source", f.Source).
		bool("unbound", f.Unbound).time("since", f.Since).time("until", f.Until).int("limit", f.Limit)
}

// Observations lists raw observations.
func (c *Client) Observations(ctx context.Context, f store.ObservationFilter) ([]store.Observation, error) {
	var out []store.Observation
	return out, c.get(ctx, "/v1/observations", url.Values(observationValues(f)), &out)
}

// Rollups lists hourly roll-ups.
func (c *Client) Rollups(ctx context.Context, f store.ObservationFilter) ([]store.Rollup, error) {
	var out []store.Rollup
	return out, c.get(ctx, "/v1/observations", url.Values(observationValues(f).bool("rollups", true)), &out)
}

func eventValues(f store.EventFilter) values {
	q := values{}.time("since", f.Since).time("until", f.Until).str("interface", f.Interface).str("mac", f.MAC).str("ip", f.IP).
		str("host", f.HostID).int("limit", f.Limit)
	for _, t := range f.Types {
		url.Values(q).Add("type", t)
	}
	return q
}

// Events lists events.
func (c *Client) Events(ctx context.Context, f store.EventFilter) ([]store.Event, error) {
	var out []store.Event
	return out, c.get(ctx, "/v1/events", url.Values(eventValues(f)), &out)
}

// Services lists services.
func (c *Client) Services(ctx context.Context, f store.ServiceFilter) ([]store.ServiceRow, error) {
	var out []store.ServiceRow
	return out, c.get(ctx, "/v1/services", url.Values(values{}.int("port", f.Port).str("state", f.State).str("interface", f.Interface)), &out)
}

// DHCPServers lists the DHCP servers seen.
func (c *Client) DHCPServers(ctx context.Context, f store.DHCPServerFilter) ([]store.DHCPServer, error) {
	var out []store.DHCPServer
	return out, c.get(ctx, "/v1/dhcp/servers", url.Values(values{}.str("interface", f.Interface).str("status", f.Status)), &out)
}

// DBInfo describes the database.
func (c *Client) DBInfo(ctx context.Context) (store.DBInfo, error) {
	var info store.DBInfo
	return info, c.get(ctx, "/v1/db", nil, &info)
}

// DBCheck runs the integrity check.
func (c *Client) DBCheck(ctx context.Context) (store.CheckResult, error) {
	var res store.CheckResult
	return res, c.get(ctx, "/v1/db/check", nil, &res)
}

// Config returns the daemon's effective configuration as JSON.
func (c *Client) Config(ctx context.Context) (json.RawMessage, error) {
	var raw json.RawMessage
	return raw, c.get(ctx, "/v1/config", nil, &raw)
}

// Stream calls fn for every live event matching the filters until ctx is
// cancelled or the daemon goes away.
func (c *Client) Stream(ctx context.Context, iface string, types []string, port int, fn func(store.Event) error) error {
	q := values{}.str("interface", iface).int("port", port)
	for _, t := range types {
		url.Values(q).Add("type", t)
	}
	resp, err := c.do(ctx, c.stream, "/v1/events/stream", url.Values(q))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var e store.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return fmt.Errorf("event stream: %w", err)
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("event stream: %w", err)
	}
	return fmt.Errorf("event stream: %w (connection closed)", ErrUnreachable)
}
