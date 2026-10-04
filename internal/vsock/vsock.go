// Package vsock carries streams between a guest and its host over the
// hypervisor's socket family, which no packet filter and no route stands in
// the way of.
package vsock

import "strconv"

// Context ids every kernel knows: the guest's host, and the kernel's own
// loopback.
const (
	HostCID  uint32 = 2
	LocalCID uint32 = 1
)

// Addr is one end of a vsock stream.
type Addr struct{ CID, Port uint32 }

// Network is the name of the socket family.
func (Addr) Network() string { return "vsock" }

func (a Addr) String() string {
	return strconv.FormatUint(uint64(a.CID), 10) + ":" + strconv.FormatUint(uint64(a.Port), 10)
}
