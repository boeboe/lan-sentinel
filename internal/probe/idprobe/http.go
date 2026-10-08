package idprobe

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"strconv"
	"strings"

	"lan-sentinel/internal/buildinfo"
	"lan-sentinel/internal/probe"
)

// HTTP is GET / HTTP/1.0 on tcp/80 (ADR 0011). One request, no redirect,
// no decompression, no auth retry. Body is capped at 8 KiB.
type HTTP struct{}

const (
	httpPort       = 80
	httpBudgetCost = 4 // 3 TCP + 1 write
	httpMaxBody    = 8 << 10
	httpMaxRead    = 16 << 10
	httpConfServer = 0.6
	httpConfTitle  = 0.5
)

var errHTTP = fmt.Errorf("%w: http", errExchange)

// Name implements Probe.
func (HTTP) Name() string { return "http" }

// Protocol implements Probe.
func (HTTP) Protocol() probe.Protocol { return probe.TCP }

// Port implements Probe.
func (HTTP) Port() uint16 { return httpPort }

// BudgetCost implements Probe.
func (HTTP) BudgetCost() int { return httpBudgetCost }

// Limits implements Probe.
func (HTTP) Limits() Limits { return Limits{MaxWrites: 1, MaxRead: httpMaxRead} }

// Exchange implements Probe.
func (HTTP) Exchange(ctx context.Context, s Session) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	req := "GET / HTTP/1.0\r\nConnection: close\r\nUser-Agent: " + httpUserAgent() + "\r\n\r\n"
	if _, err := s.Write([]byte(req)); err != nil {
		return Response{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(s, httpMaxRead))
	if err != nil && !isBenignRead(err) {
		return Response{}, err
	}
	return parseHTTP(raw)
}

func httpUserAgent() string {
	v := strings.TrimPrefix(buildinfo.Version, "v")
	major, _, _ := strings.Cut(v, ".")
	if major == "" {
		major = "dev"
	}
	return "lan-sentinel/" + major
}

func parseHTTP(raw []byte) (Response, error) {
	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		head, body, ok = bytes.Cut(raw, []byte("\n\n"))
	}
	if !ok {
		return Response{}, fmt.Errorf("%w: no header terminator", errHTTP)
	}
	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(head, "\r\n\r\n"...))))
	line, err := r.ReadLine()
	if err != nil {
		return Response{}, fmt.Errorf("%w: status line: %w", errHTTP, err)
	}
	status, ok := httpStatus(line)
	if !ok {
		return Response{}, fmt.Errorf("%w: status line", errHTTP)
	}
	hdr, err := r.ReadMIMEHeader()
	if err != nil {
		return Response{}, fmt.Errorf("%w: headers: %w", errHTTP, err)
	}
	if len(body) > httpMaxBody {
		body = body[:httpMaxBody]
	}
	details := map[string]string{"status": status}
	if scheme := authScheme(hdr.Get("Www-Authenticate")); scheme != "" {
		details["www_authenticate"] = scheme
	}
	ident := map[string]string{}
	conf := map[string]float64{}
	if srv := sanitize([]byte(hdr.Get("Server"))); srv != "" {
		ident["server"] = srv
		conf["server"] = httpConfServer
	}
	if title := htmlTitle(string(body)); title != "" {
		ident["title"] = title
		conf["title"] = httpConfTitle
	}
	return Response{Details: details, Identity: ident, Confidence: conf}, nil
}

func httpStatus(line string) (string, bool) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return "", false
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return "", false
	}
	return parts[1], true
}

func authScheme(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	scheme, _, _ := strings.Cut(v, " ")
	scheme, _, _ = strings.Cut(scheme, ",")
	return sanitize([]byte(scheme))
}

func htmlTitle(body string) string {
	// HTML tags are ASCII. strings.ToLower can change length (U+0130),
	// so those indices must not be used on the original body.
	fold := asciiLower(body)
	i := strings.Index(fold, "<title")
	if i < 0 {
		return ""
	}
	gt := strings.IndexByte(fold[i:], '>')
	if gt < 0 {
		return ""
	}
	start := i + gt + 1
	if start > len(body) {
		return ""
	}
	endRel := strings.Index(fold[start:], "</title>")
	if endRel < 0 || start+endRel > len(body) {
		return ""
	}
	return sanitize([]byte(body[start : start+endRel]))
}

// asciiLower folds A–Z only, so the result has the same byte length as s.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func isBenignRead(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
