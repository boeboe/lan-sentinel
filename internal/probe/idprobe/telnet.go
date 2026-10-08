package idprobe

import (
	"context"
	"fmt"

	"lan-sentinel/internal/probe"
)

// Telnet reads at most 512 bytes on tcp/23 and answers IAC only with
// WONT/DONT, at most 8 times (ADR 0011). No newline, login or user data.
type Telnet struct{}

const (
	telnetPort       = 23
	telnetBudgetCost = 11 // 3 TCP + 8 IAC replies
	telnetMaxRead    = 512
	telnetMaxIAC     = 8
	telnetConfidence = 0.6
	iac              = 255
	telnetSE         = 240
	telnetSB         = 250
	telnetWill       = 251
	telnetWont       = 252
	telnetDo         = 253
	telnetDont       = 254
)

var errTelnet = fmt.Errorf("%w: telnet", errExchange)

// Name implements Probe.
func (Telnet) Name() string { return "telnet" }

// Protocol implements Probe.
func (Telnet) Protocol() probe.Protocol { return probe.TCP }

// Port implements Probe.
func (Telnet) Port() uint16 { return telnetPort }

// BudgetCost implements Probe.
func (Telnet) BudgetCost() int { return telnetBudgetCost }

// Limits implements Probe.
func (Telnet) Limits() Limits { return Limits{MaxWrites: telnetMaxIAC, MaxRead: telnetMaxRead} }

// Exchange implements Probe.
func (Telnet) Exchange(ctx context.Context, s Session) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	var (
		raw     []byte
		buf     = make([]byte, 64)
		replies int
		text    []byte
		pending []byte
	)
	for len(raw) < telnetMaxRead {
		if err := ctx.Err(); err != nil {
			return Response{}, err
		}
		n, err := s.Read(buf)
		if n > 0 {
			raw = append(raw, buf[:n]...)
			chunk := append(pending, buf[:n]...)
			var more [][]byte
			text, more, pending = feedTelnet(text, chunk)
			for _, r := range more {
				if replies >= telnetMaxIAC {
					break
				}
				if _, werr := s.Write(r); werr != nil {
					return Response{}, werr
				}
				replies++
			}
		}
		if err != nil {
			break
		}
	}
	banner := sanitize(text)
	if banner == "" {
		return Response{}, fmt.Errorf("%w: no banner", errTelnet)
	}
	return Response{
		Identity:   map[string]string{"banner": banner},
		Confidence: map[string]float64{"banner": telnetConfidence},
	}, nil
}

func parseTelnet(raw []byte) (banner string, replies [][]byte) {
	text, more, _ := feedTelnet(nil, raw)
	return sanitize(text), more
}

func feedTelnet(text, in []byte) (out []byte, replies [][]byte, pending []byte) {
	out = text
	i := 0
	for i < len(in) {
		if in[i] != iac {
			out = append(out, in[i])
			i++
			continue
		}
		if i+1 >= len(in) {
			return out, replies, in[i:]
		}
		cmd := in[i+1]
		switch cmd {
		case iac:
			out = append(out, iac)
			i += 2
		case telnetWill, telnetDo:
			if i+2 >= len(in) {
				return out, replies, in[i:]
			}
			opt := in[i+2]
			refuse := byte(telnetDont)
			if cmd == telnetDo {
				refuse = telnetWont
			}
			replies = append(replies, []byte{iac, refuse, opt})
			i += 3
		case telnetWont, telnetDont:
			if i+2 >= len(in) {
				return out, replies, in[i:]
			}
			i += 3
		case telnetSB:
			j := i + 2
			for j+1 < len(in) {
				if in[j] == iac && in[j+1] == telnetSE {
					j += 2
					i = j
					break
				}
				j++
			}
			if j+1 >= len(in) {
				return out, replies, in[i:]
			}
		default:
			i += 2
		}
	}
	return out, replies, nil
}
