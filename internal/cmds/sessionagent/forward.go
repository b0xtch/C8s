package sessionagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/internal/streamend"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	// maxForwards and maxForwardsPerKey bound the streams open at once. A
	// stream holds one of the agent's connections for as long as it lasts, so
	// the first stays below maxConnections by what the other routes need. The
	// second keeps one key from holding every stream.
	maxForwards       = 64
	maxForwardsPerKey = 32
	// forwardDialTimeout bounds the connect to the sandbox's own loopback.
	forwardDialTimeout = 5 * time.Second
	// forwardIdle ends a stream that carried nothing in either direction for
	// this long. Its caller can be gone without the guest being told: the
	// connection runs through the host.
	forwardIdle = 30 * time.Minute
)

// errNoSandboxNetwork is a runner's answer when the guest runs no sandbox
// image: there is no network namespace of a sandbox to connect in.
var errNoSandboxNetwork = errors.New("this guest runs no sandbox image, so it has no sandbox port to connect to")

// forwards counts the streams open to the sandbox's ports, in all and for
// each key that opened them.
type forwards struct {
	mu     sync.Mutex
	open   int
	perKey map[int]int
}

// take reserves a stream for the forward key at place key.
func (f *forwards) take(key int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.open >= maxForwards || f.perKey[key] >= maxForwardsPerKey {
		return false
	}
	if f.perKey == nil {
		f.perKey = map[int]int{}
	}
	f.open++
	f.perKey[key]++
	return true
}

func (f *forwards) release(key int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.open--
	f.perKey[key]--
}

// serveForward opens a stream to one of the sandbox's ports and carries it on
// the request's connection, for a key the guest's bind grants that. The
// port is one those documents list, on the loopback of the sandbox's own
// network namespace: the caller names a port and never an address, and no
// document lists a port the agent itself listens on there.
func (a *Agent) serveForward(w http.ResponseWriter, r *http.Request) {
	release, ok := a.hold(w)
	if !ok {
		return
	}
	defer release()
	body, ok := httputil.ReadCappedBody(w, r, session.MaxForwardRequestBytes)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	key, ok := a.grantedKey(w, r, body, session.Access.ForwardKeys)
	if !ok {
		return
	}
	var req session.ForwardRequest
	if !decodeStrict(body, &req) || req.Port < 1 || req.Port > 65535 {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "forward needs one TCP port")
		return
	}
	// Without the upgrade a caller would be left holding a connection it does
	// not know became a stream.
	if !httpguts.HeaderValuesContainsToken(r.Header["Connection"], "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), session.ForwardProtocol) {
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", session.ForwardProtocol)
		httputil.WriteError(w, http.StatusUpgradeRequired, types.ErrorCodeInvalidRequest, "forward upgrades its connection to "+session.ForwardProtocol)
		return
	}
	if !a.forward().Opens(req.Port) {
		httputil.WriteError(w, http.StatusForbidden, types.ErrorCodeInvalidRequest, fmt.Sprintf("the guest's bind does not open port %d of the sandbox", req.Port))
		return
	}
	if !a.sandboxRunning() {
		httputil.WriteError(w, http.StatusConflict, types.ErrorCodeInvalidRequest, "the sandbox has not been admitted yet")
		return
	}
	if !a.forwards.take(key) {
		w.Header().Set("Retry-After", "1")
		httputil.WriteError(w, http.StatusTooManyRequests, types.ErrorCodeTooManyRequests, "too many streams to the sandbox are open")
		return
	}
	defer a.forwards.release(key)

	ctx, cancel := context.WithTimeout(r.Context(), forwardDialTimeout)
	sandbox, err := a.cfg.Runner.Dial(ctx, req.Port)
	cancel()
	if err != nil {
		// Which ports answer is the sandbox's own state and is not logged.
		reason := fmt.Sprintf("could not connect to port %d of the sandbox", req.Port)
		if errors.Is(err, syscall.ECONNREFUSED) {
			reason = fmt.Sprintf("nothing listens on port %d of the sandbox", req.Port)
		}
		httputil.WriteError(w, http.StatusBadGateway, types.ErrorCodePortUnreachable, reason)
		return
	}
	defer sandbox.Close()
	hijacker, ok := w.(http.Hijacker)
	// Served outside Serve, the connection under the caller's session is not
	// at hand, and neither is how it ends.
	tracked := connOf(r.Context())
	if !ok || tracked == nil {
		httputil.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "this agent cannot hand a connection over to a stream")
		return
	}
	caller, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer caller.Close()
	// The request is answered. What follows is the stream's own, and counted
	// as that.
	release()
	const answer = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + session.ForwardProtocol + "\r\n\r\n"
	if _, err := buffered.WriteString(answer); err != nil || buffered.Flush() != nil {
		return
	}
	// A caller that wrote behind its request has those bytes in the reader.
	var fromCaller io.Reader = caller
	if n := buffered.Reader.Buffered(); n > 0 {
		early, _ := buffered.Peek(n)
		fromCaller = io.MultiReader(bytes.NewReader(bytes.Clone(early)), caller)
	}
	splice(stream{
		caller: caller, fromCaller: fromCaller, callerCut: tracked.Ended, abortCaller: tracked.Close,
		sandbox: sandbox,
	}, forwardIdle)
}

// stream is the two ends of one stream, as splice needs them.
type stream struct {
	// caller is the caller's TLS session, and fromCaller what is read from it.
	caller     net.Conn
	fromCaller io.Reader
	// callerCut reports whether the caller's connection has ended under its
	// session. An end of input read after that is not the caller's word.
	callerCut func() bool
	// abortCaller closes the caller's connection without ending its session,
	// so that the caller reads a failure and not the end of the stream.
	abortCaller func() error
	sandbox     net.Conn
}

// splice carries one stream between a caller and the sandbox's port, and
// keeps the two ways it can end apart for both of them.
//
// A direction its sender ended is ended in order for its reader, and the
// other direction stays open: a caller can send, end its input and still read
// the answer. The stream is over when both directions have ended so, and its
// connections are then the caller's of splice to close.
//
// Anything else is a failure: a connection that fails, a caller's connection
// that ends with no close_notify from the caller, or no byte moving for idle.
// A failure is passed on as one. The sandbox's connection is reset, and the
// caller's is closed under its session. Whoever carries the caller's
// connection can end it between two records, and must not thereby tell the
// sandbox that its caller was done.
func splice(s stream, idle time.Duration) {
	start := time.Now()
	// moved is when a byte last moved, in either direction, since start.
	var moved atomic.Int64
	abort := sync.OnceFunc(func() {
		_ = s.abortCaller()
		_ = streamend.Reset(s.sandbox)
	})
	done := make(chan struct{}, 2)
	carry := func(dst net.Conn, src io.Reader, reads net.Conn, cut func() bool) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32<<10)
		for {
			_ = reads.SetReadDeadline(start.Add(time.Duration(moved.Load()) + idle))
			n, err := src.Read(buf)
			if n > 0 {
				moved.Store(int64(time.Since(start)))
				if _, err := dst.Write(buf[:n]); err != nil {
					abort()
					return
				}
			}
			switch {
			case err == nil:
			case errors.Is(err, io.EOF) && !cut():
				// The sender ended its stream. A reader that cannot be told
				// so alone is told nothing in order.
				if half, ok := dst.(interface{ CloseWrite() error }); !ok || half.CloseWrite() != nil {
					abort()
				}
				return
			case errors.Is(err, os.ErrDeadlineExceeded) && time.Since(start)-time.Duration(moved.Load()) < idle:
				// The other direction carried something in the meantime.
			default:
				abort()
				return
			}
		}
	}
	go carry(s.sandbox, s.fromCaller, s.caller, s.callerCut)
	// The sandbox's connection is the guest's own loopback: its end is the
	// sandbox's.
	go carry(s.caller, s.sandbox, s.sandbox, func() bool { return false })
	<-done
	<-done
}
