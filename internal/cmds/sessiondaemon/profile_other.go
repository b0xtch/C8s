//go:build !unix

package sessiondaemon

import "log/slog"

// profileOnSignals does nothing where a process takes no such signals.
func profileOnSignals(_ string, log *slog.Logger) (stop func()) {
	log.Warn("this system has no signals to profile between: --cpu-profile writes nothing")
	return func() {}
}
