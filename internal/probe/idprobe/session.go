package idprobe

import (
	"io"
	"net"
	"time"
)

// session wraps a connection and stops writes and reads past Limits.
// It is a net.Conn so probes that need one (TLS) can type-assert.
type session struct {
	conn      net.Conn
	writes    int
	maxWrites int
	read      int
	maxRead   int
}

var _ net.Conn = (*session)(nil)

func newSession(conn net.Conn, lim Limits) *session {
	if lim.MaxWrites < 0 {
		lim.MaxWrites = 0
	}
	if lim.MaxRead < 1 {
		lim.MaxRead = 1
	}
	return &session{conn: conn, maxWrites: lim.MaxWrites, maxRead: lim.MaxRead}
}

func (s *session) Write(p []byte) (int, error) {
	if s.writes >= s.maxWrites {
		return 0, ErrLimit
	}
	s.writes++
	return s.conn.Write(p)
}

func (s *session) Read(p []byte) (int, error) {
	if s.read >= s.maxRead {
		return 0, io.EOF
	}
	if remain := s.maxRead - s.read; len(p) > remain {
		p = p[:remain]
	}
	n, err := s.conn.Read(p)
	s.read += n
	return n, err
}

func (s *session) Close() error { return s.conn.Close() }

func (s *session) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *session) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

func (s *session) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *session) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *session) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
