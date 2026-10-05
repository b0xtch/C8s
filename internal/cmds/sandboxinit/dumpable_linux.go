//go:build linux

package sandboxinit

import "golang.org/x/sys/unix"

// undumpable keeps other processes of this one's user from attaching to it,
// and from opening its memory and its descriptors through /proc. The kernel
// lifts it again at the exec that makes this process something else.
func undumpable() {
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
