//go:build linux

package sessionagent

import (
	"fmt"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// tcpListeners asks the kernel for the listening TCP sockets of one address
// family in the network namespace this thread is in, and returns their local
// ports.
func tcpListeners(family int) ([]int, error) {
	req := nl.NewNetlinkRequest(sockDiagByFamily, unix.NLM_F_DUMP)
	req.AddData(listenersRequest{family: uint8(family)})
	answers, err := req.Execute(unix.NETLINK_SOCK_DIAG, sockDiagByFamily)
	if err != nil {
		return nil, fmt.Errorf("ask the kernel for its listening sockets: %w", err)
	}
	ports := make([]int, 0, len(answers))
	for _, answer := range answers {
		port, err := listenerPort(answer, uint8(family))
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, nil
}
