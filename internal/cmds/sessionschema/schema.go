// Package sessionschema prints the schemas of this build's session agent:
// what it takes in a bind, and everything it says to a caller without a key.
// The guest's own program and the operator's CLI both carry the command, so
// that the program an image runs is the one that states its schemas.
package sessionschema

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// schemas are the documents this build's agent is held to, by name.
var schemas = map[string]func() []byte{
	"bind":       session.BindSchema,
	"disclosure": disclosure.Document,
}

// Exit codes, as the session CLI's: 0 printed or the same, 1 usage error, 2
// a published file that is another schema, 3 output that could not be
// written.
const (
	ExitOK          = 0
	ExitUsage       = 1
	ExitRefused     = 2
	ExitUnavailable = 3
)

// NewCmd returns the command that prints the schemas of this build's agent.
// A guest image carries both on its verity root and its build publishes both
// beside the image's manifest, written by the same program the image runs.
func NewCmd() *cobra.Command {
	var check string
	cmd := &cobra.Command{
		Use:   "schema {bind|disclosure}",
		Short: "Print what this build's agent takes in a bind, or everything it says to a caller without a key",
		Long: `Print one of the two schemas of this build's agent.

bind is every member a bind may carry and the purposes the agent accepts: a
bind with any other member is refused. disclosure is every message the agent
sends a caller it has not authenticated, with the bound of each field: a
code from a list, a flag, a counter, a digest or a public document.

Both are read from the definitions the agent is compiled from. With --check,
nothing is printed: the command compares the schema with a published file and
exits 0 when they are the same bytes, 2 when they differ.`,
		Args:         cobra.ExactArgs(1),
		ValidArgs:    []string{"bind", "disclosure"},
		SilenceUsage: true,
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(Run(args[0], check, cmd.OutOrStdout(), cmd.ErrOrStderr()))
		},
	}
	cmd.Flags().StringVar(&check, "check", "", "compare with this published file and print nothing")
	return cmd
}

// Run prints the named schema, or compares it with the file check names.
func Run(name, check string, stdout, stderr io.Writer) int {
	render, ok := schemas[name]
	if !ok {
		fmt.Fprintf(stderr, "no schema %q: bind or disclosure\n", name)
		return ExitUsage
	}
	if check == "" {
		if _, err := stdout.Write(render()); err != nil {
			return ExitUnavailable
		}
		return ExitOK
	}
	published, err := os.ReadFile(check)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	if !bytes.Equal(published, render()) {
		fmt.Fprintf(stderr, "%s is not this build's %s schema\n", check, name)
		return ExitRefused
	}
	return ExitOK
}
