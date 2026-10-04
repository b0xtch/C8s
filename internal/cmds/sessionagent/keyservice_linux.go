//go:build linux

package sessionagent

import (
	"context"
	"net"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/vsock"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// hostKeyServiceDial is how this guest reaches its key service when its host
// carries the connection: over the host's vsock port, which needs no address,
// no route and no opening in a packet filter. Nil is a host that offers none,
// whose guest dials the key service's address. Either way the far end is held
// to the pin before anything is sent, so where the host carries it changes
// nothing but whether it arrives.
func hostKeyServiceDial(launchDir string) (func(context.Context, string, string) (net.Conn, error), error) {
	host, err := session.ReadHostConfig(filepath.Join(launchDir, session.HostConfigFile))
	if err != nil || host == nil || host.KeyServicePort == 0 {
		return nil, err
	}
	port := host.KeyServicePort
	return func(context.Context, string, string) (net.Conn, error) {
		conn, err := vsock.Dial(vsock.HostCID, port)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}, nil
}
