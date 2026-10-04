package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const (
	// frameBytes is the most this end puts in one frame.
	frameBytes = 32 << 10
	// closeGrace is how long a closed connection's last bytes get to reach
	// the guest before the stream is cut.
	closeGrace = 2 * time.Second
)

// Dialer opens connections to the TLS port of a bound TD through the daemon,
// for session.Through. The daemon carries the bytes and ends no TLS session,
// so the client at this end verifies the guest as it would on any road.
func (c *Client) Dialer(td string) session.Dialer {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		// The stream outlives the dial: ctx bounds only its opening.
		streamCtx, cancel := context.WithCancel(context.Background())
		stop := context.AfterFunc(ctx, cancel)
		stream, err := c.api.Connect(streamCtx)
		if err == nil {
			err = stream.Send(&sessionv1alpha1.Bytes{Td: td})
		}
		if !stop() || err != nil {
			cancel()
			if err == nil {
				err = ctx.Err()
			}
			return nil, err
		}
		conn := &conn{stream: stream, cancel: cancel, td: td, frames: make(chan []byte), done: make(chan struct{})}
		go conn.receive()
		return conn, nil
	}
}

// conn is one Connect stream as a net.Conn.
type conn struct {
	stream sessionv1alpha1.Sessions_ConnectClient
	cancel context.CancelFunc
	td     string

	// frames carries what the daemon sent, one frame at a time, so a reader
	// that stops reading stops the daemon sending.
	frames chan []byte
	// ended is why frames was closed: io.EOF when the guest ended the
	// connection.
	ended error
	rest  []byte
	rmu   sync.Mutex
	wmu   sync.Mutex

	read, write deadline
	done        chan struct{}
	closing     sync.Once
}

func (c *conn) receive() {
	defer close(c.frames)
	defer c.cancel()
	for {
		frame, err := c.stream.Recv()
		if err != nil {
			// The daemon ends the stream in order when the guest ended the
			// connection, and with an error for every other end.
			c.ended = err
			return
		}
		if len(frame.GetData()) == 0 {
			continue
		}
		select {
		case c.frames <- frame.GetData():
		case <-c.done:
			// Closed at this end: what still arrives is dropped, until the
			// daemon ends the stream.
		}
	}
}

func (c *conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.rest) == 0 {
		select {
		case frame, ok := <-c.frames:
			if !ok {
				return 0, c.ended
			}
			c.rest = frame
		case <-c.read.expired():
			return 0, os.ErrDeadlineExceeded
		case <-c.done:
			return 0, net.ErrClosed
		}
	}
	n := copy(p, c.rest)
	c.rest = c.rest[n:]
	return n, nil
}

func (c *conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		select {
		case <-c.done:
			return written, net.ErrClosed
		case <-c.write.expired():
			return written, os.ErrDeadlineExceeded
		default:
		}
		chunk := p[:min(len(p), frameBytes)]
		// Send waits for the daemon to take the frame. A deadline that passes
		// meanwhile ends the stream, which is what ends the wait.
		late := c.write.guard(c.cancel)
		// A frame handed to Send is not the sender's to change.
		err := c.stream.Send(&sessionv1alpha1.Bytes{Data: bytes.Clone(chunk)})
		if late() {
			return written, os.ErrDeadlineExceeded
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				// The stream ended under the write: Recv says how.
				err = io.ErrClosedPipe
			}
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// CloseWrite tells the guest this end has sent all it will.
func (c *conn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.stream.CloseSend()
}

func (c *conn) Close() error {
	c.closing.Do(func() {
		// Not while a write waits on the daemon: that write ends with the
		// stream.
		orderly := c.wmu.TryLock()
		if orderly {
			orderly = c.stream.CloseSend() == nil
			c.wmu.Unlock()
		}
		close(c.done)
		if !orderly {
			c.cancel()
			return
		}
		// What was written last, a TLS close_notify for one, has yet to reach
		// the guest. The daemon ends the stream once the guest has answered
		// the end of this side.
		time.AfterFunc(closeGrace, c.cancel)
	})
	return nil
}

func (c *conn) LocalAddr() net.Addr  { return addr("") }
func (c *conn) RemoteAddr() net.Addr { return addr(c.td) }

func (c *conn) SetDeadline(t time.Time) error {
	c.read.set(t)
	c.write.set(t)
	return nil
}
func (c *conn) SetReadDeadline(t time.Time) error  { c.read.set(t); return nil }
func (c *conn) SetWriteDeadline(t time.Time) error { c.write.set(t); return nil }

// addr names an end of a stream through the daemon.
type addr string

func (addr) Network() string  { return "c8s-connect" }
func (a addr) String() string { return string(a) }

// deadline is a point in time a read or a write gives up at.
type deadline struct {
	mu    sync.Mutex
	at    time.Time
	timer *time.Timer
	// passed is closed once the deadline has passed, and replaced when a new
	// one is set after that.
	passed chan struct{}
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	if d.passed == nil || isClosed(d.passed) {
		d.passed = make(chan struct{})
	}
	d.at = t
	if t.IsZero() {
		return
	}
	passed := d.passed
	if wait := time.Until(t); wait > 0 {
		d.timer = time.AfterFunc(wait, func() { close(passed) })
	} else {
		close(passed)
	}
}

// expired is closed when the deadline has passed.
func (d *deadline) expired() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.passed == nil {
		d.passed = make(chan struct{})
	}
	return d.passed
}

// guard runs f if the deadline, as it stands now, passes before the returned
// function is called, which reports whether it did.
func (d *deadline) guard(f func()) (passed func() bool) {
	d.mu.Lock()
	at := d.at
	d.mu.Unlock()
	if at.IsZero() {
		return func() bool { return false }
	}
	timer := time.AfterFunc(time.Until(at), f)
	return func() bool { return !timer.Stop() }
}

func isClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
