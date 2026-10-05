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
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/vsock"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const (
	// relayed bounds the connections a guest holds to its key service at a
	// time: the one it keeps, and room to replace it. A guest's connections
	// to one of the vendor's services are bounded the same.
	relayed = 4
	// published bounds the connections a launcher carries at a time to one
	// port its guest serves: a key service replica holds one for each guest
	// of its pools, and its owners' beside them.
	published = 4096
	// relayDial bounds reaching the far end for one connection.
	relayDial = 10 * time.Second
	// relayPause is how long the relay waits after an accept that failed.
	relayPause = time.Second
)

// relay carries connections between a guest and what its launcher reaches
// for it, so that the guest needs no address, no route and no opening in a
// packet filter: a guest's connections to the key service its launch
// document pins, a key service replica's to the vendor's service, and
// everyone's to a port such a replica serves. It reads nothing of what it
// carries: each is a TLS session that ends in a guest, or at the vendor, and
// whoever opened it holds its far end to a pin or a certificate. A launcher
// that carries one elsewhere, or nowhere, has a guest that is given nothing.
type relay struct {
	// name says what the relay carries, for its log.
	name string
	ln   net.Listener
	// own reports whether the relay carries a connection: one from this
	// launcher's guest, for a relay only its guest may use.
	own func(net.Conn) bool
	// dial reaches the far end.
	dial func(context.Context) (net.Conn, error)
	// slots bounds the connections carried at a time.
	slots int
	log   *slog.Logger
}

// run carries connections until ctx ends, and returns once each has ended.
func (r *relay) run(ctx context.Context) {
	stop := context.AfterFunc(ctx, func() { _ = r.ln.Close() })
	defer stop()
	slots := make(chan struct{}, max(r.slots, 1))
	var carried sync.WaitGroup
	var count atomic.Int64
	defer func() {
		carried.Wait()
		r.log.Info("a relay ended", "relay", r.name, "connections", count.Load())
	}()
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			r.log.Warn("a relay took no connection", "relay", r.name, "error", err)
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
		count.Add(1)
		carried.Go(func() {
			defer func() { <-slots }()
			r.carry(ctx, conn)
		})
	}
}

// carry joins one connection to the far end until either end closes.
func (r *relay) carry(ctx context.Context, guest net.Conn) {
	defer guest.Close()
	dialing, cancel := context.WithTimeout(ctx, relayDial)
	service, err := r.dial(dialing)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			r.log.Warn("a relay did not reach its far end", "relay", r.name, "error", err)
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
		name: "key service",
		ln:   ln,
		own:  fromGuest(cid),
		dial: func(ctx context.Context) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", u.Host)
		},
		slots: relayed,
		log:   log,
	}, ln.Port(), nil
}

// fromGuest reports whether a connection came over vsock from the guest with
// this context id. The port a relay listens on is the host's, and every
// guest on the host reaches it.
func fromGuest(cid uint32) func(net.Conn) bool {
	return func(conn net.Conn) bool {
		peer, ok := conn.(*vsock.Conn)
		return ok && peer.Peer() == cid
	}
}

// vendorRelay listens for this launcher's guest and carries what it takes to
// one of the vendor's services, at address, which is all it reaches: the
// guest names no destination. The port it returns is what the guest dials
// for that service.
func vendorRelay(service, address string, cid uint32, log *slog.Logger) (*relay, uint32, error) {
	ln, err := vsock.Listen(vsock.AnyPort, relayed)
	if err != nil {
		return nil, 0, err
	}
	dialer := &net.Dialer{}
	return &relay{
		name: "vendor " + service,
		ln:   ln,
		own:  fromGuest(cid),
		dial: func(ctx context.Context) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", address)
		},
		slots: relayed,
		log:   log,
	}, ln.Port(), nil
}

// vendorRoads makes a road for the guest with this context id to each of
// the vendor's services for its platform, and returns the port the guest
// dials for each. The roads it made are returned with an error too: their
// listeners are the caller's to close.
func vendorRoads(cfg *Config, cid uint32, log *slog.Logger) ([]*relay, map[string]uint32, error) {
	services, err := session.VendorServices(cfg.Platform)
	if err != nil {
		return nil, nil, err
	}
	var roads []*relay
	ports := map[string]uint32{}
	for _, service := range services {
		road, port, err := vendorRelay(service, cfg.sim.vendor(service), cid, log)
		if err != nil {
			return roads, nil, err
		}
		roads = append(roads, road)
		ports[service] = port
	}
	return roads, ports, nil
}

// publishRelay listens on a TCP port of the host and carries what it takes
// to a port the guest serves on its socket to the host: how a guest with no
// network device is reached. Anyone who reaches the host's port reaches the
// guest's, as with a forwarded port.
func publishRelay(forward Forward, cid uint32, log *slog.Logger) (*relay, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(forward.Address, strconv.Itoa(forward.Host)))
	if err != nil {
		return nil, err
	}
	guest := uint32(forward.Guest)
	return &relay{
		name: "published port " + strconv.Itoa(forward.Host),
		ln:   ln,
		own:  func(net.Conn) bool { return true },
		// The kernel bounds the wait for a guest that does not listen yet.
		dial:  func(context.Context) (net.Conn, error) { return vsock.Dial(cid, guest) },
		slots: published,
		log:   log,
	}, nil
}
