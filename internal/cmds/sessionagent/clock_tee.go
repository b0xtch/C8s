//go:build !c8s_simtee

package sessionagent

// ownClock reports whether source is the clocksource a confidential guest
// keeps itself.
func ownClock(source string) bool { return source == ownClockSource }
