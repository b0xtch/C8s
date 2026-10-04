//go:build linux

package sessionagent

import (
	"context"
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
	return dials, nil
}

// dialHost connects to a vsock port of the guest's host.
func dialHost(port uint32) (net.Conn, error) {
	conn, err := vsock.Dial(vsock.HostCID, port)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
