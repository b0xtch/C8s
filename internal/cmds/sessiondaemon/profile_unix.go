//go:build unix

package sessiondaemon

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"
)

// profileOnSignals writes the daemon's CPU profile over each stretch from a
// SIGUSR1 to the SIGUSR2 that follows it, to path with the stretch's number
// after it: what the daemon spends over a burst of binds, say, apart from
// what filling its pools costs it. What it returns ends the profiling, and
// with it a stretch that no SIGUSR2 ended.
func profileOnSignals(path string, log *slog.Logger) (stop func()) {
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGUSR2)
	quit, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var file *os.File
		end := func() {
			if file == nil {
				return
			}
			pprof.StopCPUProfile()
			if err := file.Close(); err != nil {
				log.Warn("a CPU profile could not be kept", "file", file.Name(), "error", err)
			}
			file = nil
		}
		defer end()
		for n := 0; ; {
			select {
			case <-quit:
				return
			case got := <-signals:
				if got == syscall.SIGUSR2 {
					end()
					continue
				}
				if file != nil {
					continue
				}
				f, err := os.Create(fmt.Sprintf("%s.%d", path, n))
				if err == nil {
					if err = pprof.StartCPUProfile(f); err != nil {
						_ = f.Close()
					}
				}
				if err != nil {
					log.Warn("no CPU profile is written for this stretch", "error", err)
					continue
				}
				file = f
				n++
			}
		}
	}()
	return func() {
		signal.Stop(signals)
		close(quit)
		<-done
	}
}
