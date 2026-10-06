//go:build linux

package sessionagent

// SetUserNamespaceLimit names the file the agent writes the guest's limit on
// user namespaces to. A test binary points it away from the machine's own
// before it makes any sandbox's namespaces: the limit holds for everything
// on the machine, for as long as it is up.
func SetUserNamespaceLimit(path string) { userNamespaceLimit = path }

// KeepTo keeps the test binary's threads to its first n processors, as an
// agent's flag keeps an agent's.
var KeepTo = keepTo

// WarmCommands reports whether a command's process waits in the runner's
// container for whichever command comes next, and how many commands ran as
// one so far.
func (r *ImageRunner) WarmCommands() (waiting bool, used int64) {
	r.mu.Lock()
	made := r.made
	if r.prepared != nil {
		made = r.prepared.made
	}
	r.mu.Unlock()
	if made == nil || made.warm == nil {
		return false, 0
	}
	return len(made.warm) == 1, made.warmUsed.Load()
}

// AheadDone is closed when the runner has done all the unpacking ahead it was
// asked for. It is nil for a runner that was asked for none.
func (r *ImageRunner) AheadDone() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.aheadDone
}
