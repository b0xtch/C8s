package sessionagent

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The sandbox user is not root. It reaches its credentials only if every
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
		t.Fatalf("parent directory mode is %o: the sandbox user cannot traverse it", parent.Mode().Perm())
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

// A credential belongs to the sandbox before it appears under its name, so a
// credential that cannot be handed over never replaces the one that was there.
func TestCredentialIsHandedOverBeforeItAppears(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root may hand a file to anyone")
	}
	dir := filepath.Join(t.TempDir(), "credentials")
	store, err := newCredentialStore(dir, -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	if held, err := store.put("token", []byte("first")); err != nil || held {
		t.Fatalf("put: held %v, %v", held, err)
	}
	// To this user itself: nothing to refuse.
	store.uid, store.gid = os.Getuid(), os.Getgid()
	if held, err := store.put("other", []byte("second")); err != nil || held {
		t.Fatalf("put for this user: held %v, %v", held, err)
	}
	// To root, which this user may not do.
	store.uid, store.gid = 0, 0
	if _, err := store.put("third", []byte("third")); err == nil {
		t.Fatal("a credential was handed to a user this process may not hand files to")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("the directory holds %v, %v", entries, err)
	}
	// A credential that could not be handed over was not taken: it may come
	// again.
	store.uid, store.gid = os.Getuid(), os.Getgid()
	if held, err := store.put("third", []byte("third")); err != nil || held {
		t.Fatalf("put again for this user: held %v, %v", held, err)
	}
}

// The guest takes each credential once. The same value again is answered as
// held and writes nothing; another value under the name is refused.
func TestCredentialIsTakenOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	store, err := newCredentialStore(dir, -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	if held, err := store.put("token", []byte("first")); err != nil || held {
		t.Fatalf("put: held %v, %v", held, err)
	}
	path := filepath.Join(dir, "token")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if held, err := store.put("token", []byte("first")); err != nil || !held {
		t.Fatalf("the same value again: held %v, %v", held, err)
	}
	if after, err := os.Stat(path); err != nil || !os.SameFile(before, after) {
		t.Fatalf("the same value again wrote the credential: %v", err)
	}
	if _, err := store.put("token", []byte("second")); !errors.Is(err, errCredentialHeld) {
		t.Fatalf("another value under the name: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "first" {
		t.Fatalf("the credential is now %q, %v", got, err)
	}
}
