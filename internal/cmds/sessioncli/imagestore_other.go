//go:build !unix

package sessioncli

import "github.com/spf13/cobra"

// An image store is written where images can be pulled: see imagestore_unix.go.
func imageStoreCmds() []*cobra.Command { return nil }
