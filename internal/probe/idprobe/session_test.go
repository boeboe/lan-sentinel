package idprobe

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestSessionCapsWritesAndReads(t *testing.T) {
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	go func() { _, _ = io.Copy(io.Discard, c2) }()
	_ = c1.SetDeadline(time.Now().Add(time.Second))
	s := newSession(c1, Limits{MaxWrites: 2, MaxRead: 5})
	if _, err := s.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("b")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("c")); !errors.Is(err, ErrLimit) {
		t.Errorf("third write = %v", err)
	}
	_ = c1.Close()
	_ = c2.Close()

	r1, r2 := net.Pipe()
	t.Cleanup(func() { _ = r1.Close(); _ = r2.Close() })
	go func() {
		_, _ = r2.Write([]byte("abcdefghij"))
		_ = r2.Close()
	}()
	_ = r1.SetDeadline(time.Now().Add(time.Second))
	rs := newSession(r1, Limits{MaxWrites: 1, MaxRead: 5})
	buf := make([]byte, 16)
	n, err := rs.Read(buf)
	if err != nil || n != 5 {
		t.Fatalf("read = %d, %v", n, err)
	}
	if _, err := rs.Read(buf); !errors.Is(err, io.EOF) {
		t.Errorf("read past cap = %v", err)
	}
}

func TestSessionZeroWrites(t *testing.T) {
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	s := newSession(c1, Limits{MaxWrites: 0, MaxRead: 8})
	if _, err := s.Write([]byte("x")); !errors.Is(err, ErrLimit) {
		t.Errorf("write with cap 0 = %v", err)
	}
	_ = c2.Close()
}
