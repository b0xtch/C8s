package sessiond

import (
	"bytes"
	"context"
	"errors"
	"io"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// frameBytes is the most the daemon reads from a guest into one frame.
const frameBytes = 32 << 10

// Connect carries bytes between a caller and the TLS port of a bound TD. The
// caller's TLS session ends in the guest: the daemon sees ciphertext, sizes
// and timing.
//
// A TD nobody has bound carries no connection. The only bytes that reach it
// are the daemon's own requests and the bind of its claim, so a caller that
// knows a ready TD's name cannot bind it for itself.
func (d *Daemon) Connect(stream sessionv1alpha1.Sessions_ConnectServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if len(first.GetData()) != 0 {
		return status.Error(codes.InvalidArgument, "the first frame names the TD and carries no data")
	}
	if port := first.GetPort(); port != 0 && port != session.AgentPort {
		return status.Errorf(codes.InvalidArgument, "a guest is reached on its TLS port alone (%d)", session.AgentPort)
	}
	d.mu.Lock()
	t, ok := d.tds[first.GetTd()]
	switch {
	case !ok:
		d.mu.Unlock()
		return status.Error(codes.NotFound, "no such TD")
	case t.rec.State != StateBound && t.rec.State != StateRunning:
		state := t.rec.State
		d.mu.Unlock()
		return status.Errorf(codes.FailedPrecondition, "the TD is %s: it carries connections once it is bound", state)
	case d.streams >= maxStreams:
		d.mu.Unlock()
		return status.Error(codes.ResourceExhausted, "too many connections in flight")
	}
	d.streams++
	address, ended := t.rec.Address, t.ctx
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.streams--
		d.mu.Unlock()
	}()

	// The stream ends with the caller, with the TD, and with the daemon.
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	defer context.AfterFunc(ended, cancel)()
	go func() {
		select {
		case <-d.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	conn, err := d.dial(ctx, "tcp", address)
	if err != nil {
		return status.Error(codes.Unavailable, "the guest could not be reached")
	}
	defer conn.Close()
	// Closing is what ends a read or a write that waits on the guest.
	defer context.AfterFunc(ctx, func() { _ = conn.Close() })()

	go func() {
		for {
			frame, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				// The caller has sent all it will. The guest may still answer.
				if half, ok := conn.(interface{ CloseWrite() error }); ok {
					_ = half.CloseWrite()
				}
				return
			}
			if err != nil {
				cancel()
				return
			}
			if _, err := conn.Write(frame.GetData()); err != nil {
				cancel()
				return
			}
		}
	}()
	buf := make([]byte, frameBytes)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			// A frame handed to Send is not the sender's to change.
			if err := stream.Send(&sessionv1alpha1.Bytes{Data: bytes.Clone(buf[:n])}); err != nil {
				return err
			}
		}
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil && ended.Err() != nil:
			return status.Error(codes.Aborted, "the TD ended")
		case err != nil && stream.Context().Err() != nil:
			return status.FromContextError(stream.Context().Err()).Err()
		case err != nil:
			return status.Error(codes.Unavailable, "the connection to the guest failed")
		}
	}
}
