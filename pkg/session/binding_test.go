//go:build unix

package session

import (
	"os"
	"path/filepath"
	"testing"
)

// A binding is taken only from a directory this user owns and nobody else
// may open, with its files writable by nobody else and its access key
// readable by nobody else. A kept verdict beside it answers to its own rule.
func TestOwnBinding(t *testing.T) {
	fresh := func(t *testing.T) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "binding")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, mode := range map[string]os.FileMode{
			PubkeyFile: 0o644, DocumentFile: 0o644, SignatureFile: 0o644, BindFile: 0o644, BindSignatureFile: 0o644,
			AccessKeyFile: 0o600, VerdictFile: 0o666,
		} {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("x"), mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	if err := ownBinding(fresh(t)); err != nil {
		t.Fatalf("a binding as WriteBinding leaves it: %v", err)
	}
	for name, change := range map[string]func(dir string) error{
		"a directory others may open": func(dir string) error { return os.Chmod(dir, 0o755) },
		"a bind others may write":     func(dir string) error { return os.Chmod(filepath.Join(dir, BindFile), 0o664) },
		"a access key others may read": func(dir string) error {
			return os.Chmod(filepath.Join(dir, AccessKeyFile), 0o640)
		},
		"a bind that is a link": func(dir string) error {
			path := filepath.Join(dir, BindFile)
			if err := os.Rename(path, path+".real"); err != nil {
				return err
			}
			return os.Symlink(path+".real", path)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := fresh(t)
			if err := change(dir); err != nil {
				t.Fatal(err)
			}
			if err := ownBinding(dir); err == nil {
				t.Fatal("taken")
			}
		})
	}
}
