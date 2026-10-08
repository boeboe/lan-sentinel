package idprobe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"lan-sentinel/internal/probe"
)

// SSHBanner reads one server identification line on tcp/22 (ADR 0011).
// It sends no client banner and no KEXINIT. Silence if the server waits.
type SSHBanner struct{}

const (
	sshPort       = 22
	sshBudgetCost = 3 // TCP setup and close, no write
	sshMaxRead    = 255
	sshConfidence = 0.8
)

var errSSH = fmt.Errorf("%w: ssh-banner", errExchange)

// Name implements Probe.
func (SSHBanner) Name() string { return "ssh-banner" }

// Protocol implements Probe.
func (SSHBanner) Protocol() probe.Protocol { return probe.TCP }

// Port implements Probe.
func (SSHBanner) Port() uint16 { return sshPort }

// BudgetCost implements Probe.
func (SSHBanner) BudgetCost() int { return sshBudgetCost }

// Limits implements Probe.
func (SSHBanner) Limits() Limits { return Limits{MaxWrites: 0, MaxRead: sshMaxRead} }

// Exchange implements Probe.
func (SSHBanner) Exchange(ctx context.Context, s Session) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(s, sshMaxRead))
	if err != nil && !isBenignRead(err) {
		return Response{}, err
	}
	return parseSSHBanner(raw)
}

func parseSSHBanner(raw []byte) (Response, error) {
	line, _, _ := bytes.Cut(raw, []byte("\n"))
	line = bytes.TrimRight(line, "\r")
	sw := sshSoftware(string(line))
	if sw == "" {
		return Response{}, fmt.Errorf("%w: identification line", errSSH)
	}
	return Response{
		Identity:   map[string]string{"software": sw},
		Confidence: map[string]float64{"software": sshConfidence},
		Details:    map[string]string{"banner": sanitize(line)},
	}, nil
}

func sshSoftware(line string) string {
	if !strings.HasPrefix(line, "SSH-") {
		return ""
	}
	rest := line[4:]
	i := strings.IndexByte(rest, '-')
	if i < 0 || i+1 >= len(rest) {
		return ""
	}
	sw, _, _ := strings.Cut(rest[i+1:], " ")
	return sanitize([]byte(sw))
}
