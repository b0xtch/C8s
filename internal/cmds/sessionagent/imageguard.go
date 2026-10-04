package sessionagent

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// SchemaGuard holds the schemas on the image's measured root to the ones
// this agent is compiled from. The image's build wrote both files with the
// binary it staged, and published copies of them with the image's reference
// values. A guest whose files say anything else is not the image that was
// published, and does not serve.
type SchemaGuard struct {
	// Disclosure and Bind are the two files. An empty path is not checked.
	Disclosure, Bind string
}

// Check fails unless each file is this agent's schema, byte for byte.
func (g SchemaGuard) Check() error {
	for _, schema := range []struct {
		name, path string
		render     func() []byte
	}{{"disclosure", g.Disclosure, disclosure.Document}, {"bind", g.Bind, session.BindSchema}} {
		if schema.path == "" {
			continue
		}
		onImage, err := session.ReadBounded(schema.path, 1<<20)
		if err != nil {
			return fmt.Errorf("the image's %s schema: %w", schema.name, err)
		}
		if !bytes.Equal(onImage, schema.render()) {
			return fmt.Errorf("the image's %s schema at %s is not this agent's", schema.name, schema.path)
		}
	}
	return nil
}

// nullConsole is the kernel's console that discards what is written to it.
const nullConsole = "ttynull"

// ConsoleGuard checks that the kernel writes to no console a host could
// read. A session image's kernel is built with no console driver but the one
// that discards, so a guest with any other is not that image.
type ConsoleGuard struct {
	// Consoles is the kernel's list of registered consoles, /proc/consoles.
	Consoles string
}

// Check fails if the kernel has a console that leads anywhere.
func (g ConsoleGuard) Check() error {
	list, err := os.Open(g.Consoles)
	if err != nil {
		return fmt.Errorf("the kernel's consoles: %w", err)
	}
	defer list.Close()
	lines := bufio.NewScanner(list)
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) == 0 {
			continue
		}
		// A name and the index the kernel gave it: ttynull0.
		if strings.TrimRight(fields[0], "0123456789") != nullConsole {
			return fmt.Errorf("the kernel has console %s: a session guest writes to none its host could read", fields[0])
		}
	}
	if err := lines.Err(); err != nil {
		return fmt.Errorf("the kernel's consoles: %w", err)
	}
	return nil
}
