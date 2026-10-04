package sessioncli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// The command prints the schemas the agent is compiled from, byte for byte,
// which is what an image build writes onto the image and publishes.
func TestSchemaCommand(t *testing.T) {
	for name, want := range map[string][]byte{"bind": session.BindSchema(), "disclosure": disclosure.Document()} {
		var stdout, stderr bytes.Buffer
		if code := runSchema(name, "", &stdout, &stderr); code != ExitOK || !bytes.Equal(stdout.Bytes(), want) {
			t.Fatalf("%s: exit %d, %d bytes, %s", name, code, stdout.Len(), stderr.String())
		}
		published := filepath.Join(t.TempDir(), name+".json")
		if err := os.WriteFile(published, want, 0o644); err != nil {
			t.Fatal(err)
		}
		stdout.Reset()
		if code := runSchema(name, published, &stdout, &stderr); code != ExitOK || stdout.Len() != 0 {
			t.Fatalf("%s --check on its own schema: exit %d, printed %d bytes", name, code, stdout.Len())
		}
		// One byte more is another schema.
		if err := os.WriteFile(published, append(bytes.Clone(want), '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		if code := runSchema(name, published, &stdout, &stderr); code != ExitRefused {
			t.Fatalf("%s --check on another file: exit %d", name, code)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := runSchema("log", "", &stdout, &stderr); code != ExitUsage || stdout.Len() != 0 {
		t.Fatalf("an unknown schema: exit %d", code)
	}
	if code := runSchema("bind", filepath.Join(t.TempDir(), "absent"), &stdout, &stderr); code != ExitUsage {
		t.Fatalf("--check on no file: exit %d", code)
	}
	// The files in the repository are the published ones.
	for name, path := range map[string]string{
		"bind":       "../../../pkg/session/testdata/bind-schema.json",
		"disclosure": "../../../pkg/session/disclosure/testdata/disclosure-schema.json",
	} {
		if code := runSchema(name, path, &stdout, &stderr); code != ExitOK {
			t.Errorf("%s is not this build's %s schema", path, name)
		}
	}
}
