//go:build unix && !linux

package imagestore

import "os"

// ForgetFile does nothing here: only a Linux guest has a host that backs
// its page cache.
func ForgetFile(*os.File, int64, int64) {}
