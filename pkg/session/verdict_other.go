//go:build !unix

package session

import "io/fs"

// ownedByUs is true where a file has no owner to compare.
func ownedByUs(fs.FileInfo) bool { return true }
