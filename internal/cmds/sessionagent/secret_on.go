//go:build goexperiment.runtimesecret && linux && (amd64 || arm64)

package sessionagent

import "runtime/secret"

// erasesTemporaries says this build erases what a computation on a secret
// leaves behind: see inSecret.
const erasesTemporaries = true

// inSecret runs f so that the registers and the stack it used are erased
// before inSecret returns, and what it allocated is erased once the
// collector finds it unreachable.
func inSecret(f func()) { secret.Do(f) }
