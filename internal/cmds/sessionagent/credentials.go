package sessionagent

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// credentialStore writes released credentials where the sandbox reads them.
// The directory must be RAM-backed: guest memory is the only storage the host
// cannot read.
//
// It takes each credential once. A client that sends one again, after a
// hand-over that half happened, is told the guest holds that value; another
// value under the same name is refused. taken is the SHA-256 of what was
// taken, by name.
type credentialStore struct {
	dir      string
	uid, gid int
	mu       sync.Mutex
	taken    map[string][sha256.Size]byte
}

// errCredentialHeld refuses a credential under a name the guest took another
// value under.
var errCredentialHeld = errors.New("the guest took another value under this name, and takes each credential once")

func newCredentialStore(dir string, uid, gid int) (*credentialStore, error) {
	if dir == "" {
		return nil, errors.New("credential directory is required")
	}
	// The sandbox user must be able to reach the directory, so its parents
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
			return nil, fmt.Errorf("hand credential directory to the sandbox: %w", err)
		}
	}
	return &credentialStore{dir: dir, uid: uid, gid: gid, taken: map[string][sha256.Size]byte{}}, nil
}

// setOwner hands the directory, and every credential written from now on, to
// another user. The caller does this before any credential can be written.
func (s *credentialStore) setOwner(uid, gid int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if uid >= 0 || gid >= 0 {
		if err := os.Chown(s.dir, uid, gid); err != nil {
			return fmt.Errorf("hand credential directory to the sandbox: %w", err)
		}
	}
	s.uid, s.gid = uid, gid
	return nil
}

// put writes name atomically, the first time it is given. held reports a
// repeat of the value already taken, which writes nothing; another value is
// errCredentialHeld. name was validated against the launch document's
// declarations by the caller.
func (s *credentialStore) put(name string, value []byte) (held bool, err error) {
	sum := sha256.Sum256(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, ok := s.taken[name]; ok {
		if subtle.ConstantTimeCompare(prior[:], sum[:]) == 1 {
			return true, nil
		}
		return false, errCredentialHeld
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return false, err
	}
	defer root.Close()
	// The sandbox's own before it has its name: a sandbox that watches the
	// directory reads the credential the moment it appears.
	if err := fileutil.WriteAtomicRootOwned(root, name, value, 0o400, s.uid, s.gid); err != nil {
		return false, fmt.Errorf("write credential: %w", err)
	}
	s.taken[name] = sum
	return false, nil
}
