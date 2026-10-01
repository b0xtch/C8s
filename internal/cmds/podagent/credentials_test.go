package podagent

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The workload user is not root. It reaches its credentials only if every
// directory above them lets it through, and it must be the only user who can
// list them.
func TestCredentialDirectoryIsReachableAndPrivate(t *testing.T) {
	// The umask a systemd service runs with.
	defer syscall.Umask(syscall.Umask(0o022))
	dir := filepath.Join(t.TempDir(), "c8s", "credentials")
	if _, err := newCredentialStore(dir, -1, -1); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Stat(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if parent.Mode().Perm()&0o005 != 0o005 {
		t.Fatalf("parent directory mode is %o: the workload user cannot traverse it", parent.Mode().Perm())
	}
	leaf, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Mode().Perm() != 0o750 {
		t.Fatalf("credential directory mode is %o, want 750", leaf.Mode().Perm())
	}

	// A directory that already exists is brought back to the private mode.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := newCredentialStore(dir, -1, -1); err != nil {
		t.Fatal(err)
	}
	if leaf, _ = os.Stat(dir); leaf.Mode().Perm() != 0o750 {
		t.Fatalf("an existing credential directory was left at mode %o", leaf.Mode().Perm())
	}
}
