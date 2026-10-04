package sessionagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

func TestSchemaGuard(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	own := SchemaGuard{Disclosure: write("disclosure.json", disclosure.Document()), Bind: write("bind.json", session.BindSchema())}
	if err := own.Check(); err != nil {
		t.Fatalf("an image with this agent's schemas: %v", err)
	}
	if err := (SchemaGuard{}).Check(); err != nil {
		t.Fatalf("no file to check: %v", err)
	}
	for name, guard := range map[string]SchemaGuard{
		"another disclosure schema": {Disclosure: write("d2.json", append(disclosure.Document(), ' ')), Bind: own.Bind},
		"another bind schema":       {Disclosure: own.Disclosure, Bind: write("b2.json", []byte(strings.Replace(string(session.BindSchema()), `"start"`, `"start","fork"`, 1)))},
		"the two swapped":           {Disclosure: own.Bind, Bind: own.Disclosure},
		"no disclosure schema":      {Disclosure: filepath.Join(dir, "absent"), Bind: own.Bind},
		"an empty bind schema":      {Disclosure: own.Disclosure, Bind: write("empty.json", nil)},
	} {
		if err := guard.Check(); err == nil {
			t.Errorf("%s: the agent would serve", name)
		}
	}
}
