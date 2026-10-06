// Package coresched starts a program apart from every other on the host's
// cores: with a core-scheduling cookie of its own, so that the two hardware
// threads of a core never run its threads and another program's at the same
// time. A host starts each guest's VMM so, and no core is then shared by two
// guests at once. What a thread does on one hardware thread of a core can
// show on the other, and this is the kernel's way to keep tenants off each
// other's cores without turning the second thread off.
package coresched

import "os/exec"

// Start starts cmd apart. place, if set, runs first on the thread that
// starts cmd, and may give that thread the CPUs cmd is to keep to: a
// process starts with what the thread that starts it has. That thread ends
// with the start, so nothing else of the caller inherits either.
//
// apart is false, with no error, on a host whose cores have one hardware
// thread each: there is nothing to keep apart there. A host whose cores
// have two and whose kernel has no core scheduling starts nothing.
func Start(cmd *exec.Cmd, place func() error) (apart bool, err error) {
	return start(cmd, place)
}
