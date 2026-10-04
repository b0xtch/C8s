//go:build linux

package sessionagent

// SetUserNamespaceLimit names the file the agent writes the guest's limit on
// user namespaces to. A test binary points it away from the machine's own
// before it makes any sandbox's namespaces: the limit holds for everything
// on the machine, for as long as it is up.
func SetUserNamespaceLimit(path string) { userNamespaceLimit = path }

// AheadDone is closed when the runner has done all the unpacking ahead it was
// asked for. It is nil for a runner that was asked for none.
func (r *ImageRunner) AheadDone() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.aheadDone
}
