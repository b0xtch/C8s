//go:build linux

package sessionagent

import (
	"context"
	"fmt"
	"net"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/vsock"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// hostDials are the roads to this guest's host that its host names in
// host.json: vsock ports of the host's, which need no address, no route and
// no opening in a packet filter. The guest listens on none.
type hostDials struct {
	// KeyService reaches the key service the launch document pins when the
	// host carries the connection. Nil is a host that offers none, whose
	// guest dials the key service's address. Either way the far end is held
	// to the pin before anything is sent, so where the host carries it
	// changes nothing but whether it arrives.
	KeyService func(context.Context, string, string) (net.Conn, error)
	// Collateral reaches the host's answer to an ask for Intel's documents.
	// Nil is a host that offers none.
	Collateral func(context.Context) (net.Conn, error)
	// Vendor reaches the vendor's service at the host name and port asked
	// for, on a connection the host carries: for a TLS session that ends at
	// the vendor. Nil is a host that names no such road.
	Vendor func(ctx context.Context, network, addr string) (net.Conn, error)
}

// readHostDials reads which ports the host named.
func readHostDials(launchDir string) (hostDials, error) {
	var dials hostDials
	host, err := session.ReadHostConfig(filepath.Join(launchDir, session.HostConfigFile))
	if err != nil || host == nil {
		return dials, err
	}
	if port := host.KeyServicePort; port != 0 {
		dials.KeyService = func(context.Context, string, string) (net.Conn, error) { return dialHost(port) }
	}
	if port := host.CollateralPort; port != 0 {
		dials.Collateral = func(context.Context) (net.Conn, error) { return dialHost(port) }
	}
	if ports := host.VendorPorts; len(ports) > 0 {
		dials.Vendor = func(_ context.Context, _, addr string) (net.Conn, error) {
			port, ok := ports[addr]
			if !ok {
				return nil, fmt.Errorf("this guest's host carries no connection to %s", addr)
			}
			return dialHost(port)
		}
	}
	return dials, nil
}

// VendorDial is how a guest with no network device reaches the vendor's
// service: over the connections its host carries, as the host's file in
// launchDir names them. Without any it is a dialer that reaches nothing,
// since such a guest has no other road.
func VendorDial(launchDir string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	dials, err := readHostDials(launchDir)
	if err != nil {
		return nil, err
	}
	if dials.Vendor != nil {
		return dials.Vendor, nil
	}
	return func(_ context.Context, _, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("this guest's host named no road to the vendor's service, and %s is not reached", addr)
	}, nil
}

// dialHost connects to a vsock port of the guest's host.
func dialHost(port uint32) (net.Conn, error) {
	conn, err := vsock.Dial(vsock.HostCID, port)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
