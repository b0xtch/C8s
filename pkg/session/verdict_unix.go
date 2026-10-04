//go:build unix

package session

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByUs reports whether the file is the calling user's.
func ownedByUs(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}
