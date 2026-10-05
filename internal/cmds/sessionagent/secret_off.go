//go:build !(goexperiment.runtimesecret && linux && (amd64 || arm64))

package sessionagent

// erasesTemporaries is false in a build without the runtime's secret mode
// (GOEXPERIMENT=runtimesecret, on Linux): a key that is erased is zeroed
// where it was kept, and what a computation on it left on the stack or the
// heap stays until it is overwritten. A session guest's program is built
// with it, and refuses to run a guest without (see the run command).
const erasesTemporaries = false

func inSecret(f func()) { f() }
