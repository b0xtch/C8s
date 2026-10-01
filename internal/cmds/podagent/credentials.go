package podagent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// credentialStore writes released credentials where the workload reads them.
// The directory must be RAM-backed: guest memory is the only storage the host
// cannot read.
type credentialStore struct {
	dir      string
	uid, gid int
	mu       sync.Mutex
}

func newCredentialStore(dir string, uid, gid int) (*credentialStore, error) {
	if dir == "" {
		return nil, errors.New("credential directory is required")
	}
	// The workload user must be able to reach the directory, so its parents
	// are traversable by everyone. Only the leaf is private.
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return nil, fmt.Errorf("create credential directory: %w", err)
	}
	if err := os.Mkdir(dir, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("create credential directory: %w", err)
	}
	// Mkdir honours the umask and leaves an existing directory as it was.
	if err := os.Chmod(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create credential directory: %w", err)
	}
	if err := requireRAMBacked(dir); err != nil {
		return nil, err
	}
	if uid >= 0 || gid >= 0 {
		if err := os.Chown(dir, uid, gid); err != nil {
			return nil, fmt.Errorf("hand credential directory to the workload: %w", err)
		}
	}
	return &credentialStore{dir: dir, uid: uid, gid: gid}, nil
}

// put writes name atomically and reports whether it replaced an earlier value.
// name was validated against the launch document's declarations by the caller.
func (s *credentialStore) put(name string, value []byte) (replaced bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return false, err
	}
	defer root.Close()
	if _, err := root.Lstat(name); err == nil {
		replaced = true
	}
	if err := fileutil.WriteAtomicRoot(root, name, value, 0o400); err != nil {
		return false, fmt.Errorf("write credential: %w", err)
	}
	if s.uid >= 0 || s.gid >= 0 {
		if err := root.Lchown(name, s.uid, s.gid); err != nil {
			_ = root.Remove(name)
			return false, fmt.Errorf("hand credential to the workload: %w", err)
		}
	}
	return replaced, nil
}
