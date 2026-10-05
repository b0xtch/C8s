package sessionagent

import (
	"encoding/binary"
	"fmt"
)

// The kernel answers a question about sockets through sock_diag: a request
// that names an address family, a protocol and the states asked for, and one
// message a socket in answer. Asked for listening TCP sockets alone, it walks
// the table of those and stops: the table of connected sockets, which is as
// large as the guest's memory makes it, is not read. /proc/net/tcp walks
// both for every read.

const (
	// sockDiagByFamily is the netlink message type of such a request and of
	// each answer to it (SOCK_DIAG_BY_FAMILY).
	sockDiagByFamily = 20
	// tcpStateListen is a listening socket's state as the kernel numbers it
	// (TCP_LISTEN), and so the bit that asks for it.
	tcpStateListen = 10
	// inetDiagRequestSize and inetDiagMessageSize are the sizes of the
	// kernel's inet_diag_req_v2 and inet_diag_msg.
	inetDiagRequestSize = 56
	inetDiagMessageSize = 72
	ipProtoTCP          = 6
)

// listenersRequest is the inet_diag_req_v2 that asks for the listening TCP
// sockets of one address family, in the namespace of the socket it is sent on.
type listenersRequest struct{ family uint8 }

func (r listenersRequest) Len() int { return inetDiagRequestSize }

func (r listenersRequest) Serialize() []byte {
	b := make([]byte, inetDiagRequestSize)
	// sdiag_family, sdiag_protocol, idiag_ext, pad, then idiag_states in the
	// machine's byte order. The socket id that follows is left zero: any.
	b[0], b[1] = r.family, ipProtoTCP
	binary.NativeEndian.PutUint32(b[4:8], 1<<tcpStateListen)
	return b
}

// listenerPort reads one answer, an inet_diag_msg, and returns the local
// port of the listening socket it describes.
func listenerPort(msg []byte, family uint8) (int, error) {
	if len(msg) < inetDiagMessageSize {
		return 0, fmt.Errorf("an answer of %d bytes, shorter than the kernel's description of a socket", len(msg))
	}
	// idiag_family, idiag_state, timer, retrans, then the socket id, whose
	// first two bytes are the local port in network byte order.
	if msg[0] != family || msg[1] != tcpStateListen {
		return 0, fmt.Errorf("the kernel answered with a socket of family %d in state %d, where listening sockets of family %d were asked for", msg[0], msg[1], family)
	}
	return int(binary.BigEndian.Uint16(msg[4:6])), nil
}
