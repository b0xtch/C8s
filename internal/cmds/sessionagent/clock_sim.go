//go:build c8s_simtee

package sessionagent

// ownClock is every build's, and takes the TSC under the name it has before
// the kernel settled its rate too. A TEE tells its guest that rate. A guest
// with none measures it against a timer its host emulates, and where a read
// of that timer is slow it never finishes. The counter is the same one, and
// nothing times a simulated guest that its host could not bend.
func ownClock(source string) bool { return source == ownClockSource || source == "tsc-early" }
