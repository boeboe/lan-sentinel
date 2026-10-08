package idprobe

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"lan-sentinel/internal/probe"
)

// FTP is the 220 greeting, SYST and QUIT on tcp/21 (ADR 0011).
// No FEAT, USER, PASS, PWD or data connection.
type FTP struct{}

const (
	ftpPort       = 21
	ftpBudgetCost = 5 // 3 TCP + SYST + QUIT
	ftpMaxRead    = 2048
	ftpConfidence = 0.6
)

var errFTP = fmt.Errorf("%w: ftp", errExchange)

// Name implements Probe.
func (FTP) Name() string { return "ftp" }

// Protocol implements Probe.
func (FTP) Protocol() probe.Protocol { return probe.TCP }

// Port implements Probe.
func (FTP) Port() uint16 { return ftpPort }

// BudgetCost implements Probe.
func (FTP) BudgetCost() int { return ftpBudgetCost }

// Limits implements Probe.
func (FTP) Limits() Limits { return Limits{MaxWrites: 2, MaxRead: ftpMaxRead} }

// Exchange implements Probe.
func (FTP) Exchange(ctx context.Context, s Session) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	br := bufio.NewReader(io.LimitReader(s, ftpMaxRead))
	code, greet, err := readFTPReply(br)
	if err != nil {
		return Response{}, err
	}
	if code != 220 {
		return Response{}, fmt.Errorf("%w: greeting %d", errFTP, code)
	}
	ident := map[string]string{}
	conf := map[string]float64{}
	if b := sanitize([]byte(greet)); b != "" {
		ident["banner"] = b
		conf["banner"] = ftpConfidence
	}
	if _, err := s.Write([]byte("SYST\r\n")); err != nil {
		return Response{}, err
	}
	code, syst, err := readFTPReply(br)
	if err != nil && !isBenignRead(err) {
		return Response{}, err
	}
	if err == nil && (code == 215 || code == 200) {
		if t := sanitize([]byte(syst)); t != "" {
			ident["syst"] = t
			conf["syst"] = ftpConfidence
		}
	}
	if _, err := s.Write([]byte("QUIT\r\n")); err != nil {
		return Response{}, err
	}
	_, _, _ = readFTPReply(br)
	if len(ident) == 0 {
		return Response{}, fmt.Errorf("%w: empty greeting", errFTP)
	}
	return Response{Identity: ident, Confidence: conf}, nil
}

func readFTPReply(r *bufio.Reader) (int, string, error) {
	var text strings.Builder
	var code int
	for {
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return 0, "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return 0, "", fmt.Errorf("%w: short line", errFTP)
		}
		n, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, "", fmt.Errorf("%w: reply code", errFTP)
		}
		if code == 0 {
			code = n
		}
		body := ""
		if len(line) > 4 {
			body = line[4:]
		}
		if text.Len() > 0 && body != "" {
			text.WriteByte(' ')
		}
		text.WriteString(body)
		if len(line) == 3 || line[3] == ' ' {
			return code, text.String(), nil
		}
		if line[3] != '-' {
			return 0, "", fmt.Errorf("%w: reply separator", errFTP)
		}
	}
}

// parseFTPReply is the parser fuzz target: a complete reply blob.
func parseFTPReply(raw []byte) (int, string, error) {
	return readFTPReply(bufio.NewReader(bytes.NewReader(raw)))
}
