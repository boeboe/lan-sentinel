package idprobe

import (
	"io"
	"net"
)

// session wraps a connection and stops writes and reads past Limits.
type session struct {
	conn      net.Conn
	writes    int
	maxWrites int
	read      int
	maxRead   int
}

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
