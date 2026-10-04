//go:build !unix

package sessionlauncher

import "os"

// tryLock has no lock to take here: every launcher fetches for itself.
func tryLock(*os.File) (bool, error) { return true, nil }
