package sessionagent

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/imagestore"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// OpenImageStore finds the host's image store among the guest's disks, by
// the serial its launcher gives it, and reads its index. sysBlock is
// /sys/block and dev is /dev. A guest launched without a store has none, and
// one whose store does not read as a store goes on without it: images then
// come from their registries, as they would have.
//
// The disk stays open for the life of the agent.
func OpenImageStore(sysBlock, dev string, log *slog.Logger) *imagestore.Store {
	// In the order of the disks' names.
	serials, _ := filepath.Glob(filepath.Join(sysBlock, "*", "serial"))
	for _, path := range serials {
		serial, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(serial)) != session.ImageStoreSerial {
			continue
		}
		disk := filepath.Join(dev, filepath.Base(filepath.Dir(path)))
		store, size, err := openStoreDisk(disk)
		if err != nil {
			log.Warn("the host's image store is unusable: images come from their registries", "disk", disk, "error", err)
			return nil
		}
		log.Info("the host's image store", "disk", disk, "blobs", store.Len(), "bytes", size)
		return store
	}
	return nil
}

func openStoreDisk(path string) (*imagestore.Store, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	// A block device has no size to stat.
	size, err := f.Seek(0, io.SeekEnd)
	if err == nil {
		var store *imagestore.Store
		if store, err = imagestore.OpenStore(f, size); err == nil {
			// A blob is read from the disk once. The pages the read leaves
			// are memory the guest's host backs for the rest of its life.
			store.Forget = func(off, n int64) { imagestore.ForgetFile(f, off, n) }
			return store, size, nil
		}
	}
	_ = f.Close()
	return nil, 0, err
}
