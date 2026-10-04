package sessionlauncher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/vsock"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const (
	// relayed bounds the connections a guest holds to its key service at a
	// time: the one it keeps, and room to replace it.
	relayed = 4
	// relayDial bounds reaching the key service for one connection.
	relayDial = 10 * time.Second
	// relayPause is how long the relay waits after an accept that failed.
	relayPause = time.Second
)

// relay carries a guest's connections to the key service its launch document
// pins, so that a guest needs no address, no route and no opening in a packet
// filter to be given its keys. It reads nothing of what it carries: that is
// the guest's attested channel, whose far end the guest holds to the pin. A
// launcher that carries it elsewhere, or nowhere, has a guest that takes no
// credential.
type relay struct {
	ln net.Listener
	// own reports whether a connection came from this launcher's guest.
	own func(net.Conn) bool
	// dial reaches the key service.
	dial func(context.Context) (net.Conn, error)
	log  *slog.Logger
}

// run carries connections until ctx ends, and returns once each has ended.
func (r *relay) run(ctx context.Context) {
	stop := context.AfterFunc(ctx, func() { _ = r.ln.Close() })
	defer stop()
	slots := make(chan struct{}, relayed)
	var carried sync.WaitGroup
	defer carried.Wait()
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			r.log.Warn("the key service relay took no connection", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(relayPause):
			}
			continue
		}
		// The port is the host's, and every guest on the host reaches it.
		if !r.own(conn) {
			_ = conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		carried.Go(func() {
			defer func() { <-slots }()
			r.carry(ctx, conn)
		})
	}
}

// carry joins one connection of the guest's to the key service until either
// end closes.
func (r *relay) carry(ctx context.Context, guest net.Conn) {
	defer guest.Close()
	dialing, cancel := context.WithTimeout(ctx, relayDial)
	service, err := r.dial(dialing)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			r.log.Warn("the key service is not reached for the guest", "error", err)
		}
		return
	}
	defer service.Close()
	stop := context.AfterFunc(ctx, func() {
		_ = guest.Close()
		_ = service.Close()
	})
	defer stop()
	var ways sync.WaitGroup
	for _, way := range [][2]net.Conn{{service, guest}, {guest, service}} {
		ways.Go(func() {
			// Plain reads and writes: the bytes are few, and no fast path of
			// either socket family is leaned on.
			_, _ = io.Copy(struct{ io.Writer }{way[0]}, struct{ io.Reader }{way[1]})
			// Nothing carried here is half closed: one way's end is the end.
			_ = way[0].Close()
			_ = way[1].Close()
		})
	}
	ways.Wait()
}

// keyServiceRelay listens for this launcher's guest and carries what it takes
// to the pinned key service. The port it returns is what the guest dials.
func keyServiceRelay(pin *session.KeyService, cid uint32, log *slog.Logger) (*relay, uint32, error) {
	u, err := url.Parse(pin.URL)
	if err != nil || u.Host == "" {
		return nil, 0, fmt.Errorf("key service URL %q", pin.URL)
	}
	ln, err := vsock.Listen(vsock.AnyPort, relayed)
	if err != nil {
		return nil, 0, err
	}
	dialer := &net.Dialer{}
	return &relay{
		ln:  ln,
		own: func(conn net.Conn) bool { peer, ok := conn.(*vsock.Conn); return ok && peer.Peer() == cid },
		dial: func(ctx context.Context) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", u.Host)
		},
		log: log,
	}, ln.Port(), nil
}
