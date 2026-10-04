package sessionagent

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// tcpPair is a TCP connection over loopback: near is the test's end, far the
// end handed to the code under test.
func tcpPair(t *testing.T) (near, far *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn := <-accepted
	if conn == nil {
		t.Fatal("no connection was accepted")
	}
	t.Cleanup(func() { _ = dialed.Close(); _ = conn.Close() })
	return dialed.(*net.TCPConn), conn.(*net.TCPConn)
}

// spliced is a stream that splice carries between two loopback connections.
// caller and sandbox are the test's ends of them.
type spliced struct {
	caller, sandbox *net.TCPConn
	// done closes when splice returns.
	done chan struct{}
	// cut is what the caller's connection reports of its end: set, an end of
	// the caller's input is its connection's and not the caller's.
	cut atomic.Bool
	// aborted is set when splice closed the caller's connection under its
	// session, and not in order.
	aborted atomic.Bool
}

func newSpliced(t *testing.T, idle time.Duration) *spliced {
	t.Helper()
	caller, callerFar := tcpPair(t)
	sandbox, sandboxFar := tcpPair(t)
	s := &spliced{caller: caller, sandbox: sandbox, done: make(chan struct{})}
	go func() {
		splice(stream{
			caller: callerFar, fromCaller: callerFar, callerCut: s.cut.Load,
			abortCaller: func() error { s.aborted.Store(true); return callerFar.Close() },
			sandbox:     sandboxFar,
		}, idle)
		close(s.done)
	}()
	return s
}

func (s *spliced) over(t *testing.T, what string) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		t.Fatal(what)
	}
}

// reset checks that conn reads a failure: its peer reset it. A connection
// that reads the end of its stream was closed in order.
func reset(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(make([]byte, 1))
	var netErr net.Error
	switch {
	case n != 0 || err == nil:
		t.Fatalf("%s still carries: read %d bytes, %v", what, n, err)
	case errors.As(err, &netErr) && netErr.Timeout():
		t.Fatalf("%s was left open", what)
	case errors.Is(err, io.EOF):
		t.Fatalf("%s read the end of its stream, in order, where the stream had failed", what)
	}
}

// A stream that carries nothing in either direction has failed, and both ends
// are told so. One that carries something in one direction only is not idle.
func TestSpliceEndsAnIdleStream(t *testing.T) {
	const idle = 400 * time.Millisecond
	s := newSpliced(t, idle)
	// Three times the idle limit, with bytes moving one way only.
	for i := 0; i < 12; i++ {
		time.Sleep(idle / 4)
		if _, err := s.caller.Write([]byte("x")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		_ = s.sandbox.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(s.sandbox, make([]byte, 1)); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	select {
	case <-s.done:
		t.Fatal("a stream that carried bytes in one direction was ended as idle")
	default:
	}
	select {
	case <-s.done:
	case <-time.After(10 * idle):
		t.Fatal("a stream that carries nothing was left open")
	}
	reset(t, s.sandbox, "the sandbox's connection")
	if !s.aborted.Load() {
		t.Fatal("the caller of an idle stream was told the stream had ended in order")
	}
}

// The end of the caller's input is passed on as the end of the sandbox's
// input, and no more: the sandbox's answer still reaches the caller. The
// stream is over when the other direction ends too, and nothing has failed.
func TestSplicePassesOnTheEndOfOneDirection(t *testing.T) {
	s := newSpliced(t, time.Minute)
	if _, err := s.caller.Write([]byte("question")); err != nil {
		t.Fatal(err)
	}
	if err := s.caller.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = s.sandbox.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, err := io.ReadAll(s.sandbox); err != nil || string(got) != "question" {
		t.Fatalf("the sandbox read %q, %v", got, err)
	}
	select {
	case <-s.done:
		t.Fatal("the stream ended with the caller's input, before the sandbox answered")
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := s.sandbox.Write([]byte("answer")); err != nil {
		t.Fatalf("the sandbox could not answer after the caller's input ended: %v", err)
	}
	if err := s.sandbox.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = s.caller.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, err := io.ReadAll(s.caller); err != nil || string(got) != "answer" {
		t.Fatalf("the caller read %q, %v", got, err)
	}
	s.over(t, "the stream was left open after both directions ended")
	if s.aborted.Load() {
		t.Fatal("a stream both sides ended in order was ended as a failure")
	}
}

// The caller's connection can end without the caller having ended its input:
// whoever carries the connection closes it. The sandbox is not told that
// its caller was done. It reads a failure.
func TestSpliceDoesNotPassOnAnEndTheCallerDidNotSend(t *testing.T) {
	s := newSpliced(t, time.Minute)
	if _, err := s.caller.Write([]byte("half a question")); err != nil {
		t.Fatal(err)
	}
	_ = s.sandbox.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(s.sandbox, make([]byte, len("half a question"))); err != nil {
		t.Fatal(err)
	}
	// The connection ends the way it does when its caller is done: only the
	// connection says it was not the caller.
	s.cut.Store(true)
	if err := s.caller.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	s.over(t, "the stream outlived its caller's connection")
	reset(t, s.sandbox, "the sandbox's connection")
	if !s.aborted.Load() {
		t.Fatal("the stream was not ended as a failure")
	}
}

// A connection that fails takes the other one with it, as a failure: the
// sandbox learns that its caller is gone, not that it was done.
func TestSpliceCutsBothWhenOneFails(t *testing.T) {
	s := newSpliced(t, time.Minute)
	// A reset, as a caller that went away without a word leaves behind.
	if err := s.caller.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = s.caller.Close()
	s.over(t, "the stream outlived its caller's connection")
	reset(t, s.sandbox, "the sandbox's connection")

	// And the other way around: a sandbox that breaks off is no sandbox
	// that finished its answer.
	s = newSpliced(t, time.Minute)
	if err := s.sandbox.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = s.sandbox.Close()
	s.over(t, "the stream outlived the sandbox's connection")
	if !s.aborted.Load() {
		t.Fatal("the caller of a sandbox that broke off was told the stream had ended in order")
	}
}
