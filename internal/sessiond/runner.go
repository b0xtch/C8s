package sessiond

import "context"

// Runner boots TDs. It is the daemon's only hold on the host: everything
// else in the package is bookkeeping and relaying.
type Runner interface {
	// Start boots one TD and returns once its process runs. The guest serves
	// later: the daemon asks it.
	Start(ctx context.Context, spec Spec) (Instance, error)
	// Adopt finds the TD an earlier daemon on this host started. It fails
	// when the TD is gone.
	Adopt(spec Spec, handle Handle) (Instance, error)
}

// Spec is one TD to boot.
type Spec struct {
	// ID is the TD's name, and Dir its own directory.
	ID  string
	Dir string
	// Slot numbers the TD among those alive on the host, from zero: its
	// network address is cut from it.
	Slot  int
	Pool  *Pool
	Class Class
}

// Handle finds a TD's process again after the daemon restarted: its id, and
// the time it started at, which tells it from a later process of the same id.
type Handle struct {
	PID   int    `json:"pid"`
	Start uint64 `json:"start"`
}

// Instance is one booted TD.
type Instance interface {
	// Address is where the guest's TLS port is reached from this host.
	Address() string
	Handle() Handle
	// Done is closed once the TD's process is gone and its memory is the
	// host's again.
	Done() <-chan struct{}
	// Stop ends the TD. It needs nothing from the guest, returns at once and
	// may be called more than once.
	Stop()
}
