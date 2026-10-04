package sessionagent

import (
	"bytes"
	"fmt"

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
