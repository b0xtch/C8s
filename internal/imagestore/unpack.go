//go:build unix

// Package imagestore pulls and unpacks the OCI image a session guest's launch document
// names. It runs as the guest's root and treats the image as hostile input:
// the registry and the network belong to the host, and the image's author is
// the tenant, who must not gain the agent's authority through it.
package imagestore

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/containerd/containerd/v2/pkg/archive"
)

const (
	// IDBase is the guest id that the sandbox's id 0 maps to, and IDCount is
	// how many ids follow it. The runtime config maps the same range.
	IDBase  = 100000
	IDCount = 65536

	paxXattr = "SCHILY.xattr."
)

// UnpackLimits bounds what one image may put on the guest's scratch volume.
type UnpackLimits struct {
	Entries int64
	Bytes   int64
}

// UnpackStats is what an unpack did, for the agent's log.
type UnpackStats struct {
	Entries        int64
	Bytes          int64
	SkippedDevices int
}

// flushEvery is how much of an image the unpacker lets wait in memory for
// its disk. Written out all at once, later, by the kernel's own timer, an
// image's pages take as much memory again to encrypt, in a guest whose host
// backs every page it has ever used, and that at a time nobody chose.
const flushEvery = 16 << 20

// syncTree writes out what the file system of the tree at root holds in
// memory, and waits for it. Tests replace it.
var syncTree = syncFilesystem

// Unpacker applies an image's layers, in order, onto one directory.
type Unpacker struct {
	root   string
	limits UnpackLimits
	stats  UnpackStats
	// sameOwner is false only in tests, which cannot chown to the mapped range.
	sameOwner bool
}

// flushing reads a layer and has the tree it is unpacked to written out
// every flushEvery bytes, so that no more than that waits for the disk.
type flushing struct {
	r       io.Reader
	root    string
	pending int64
}

func (f *flushing) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if f.pending += int64(n); f.pending >= flushEvery {
		f.pending = 0
		// A tree that cannot be written out fails where it is next written.
		_ = syncTree(f.root)
	}
	return n, err
}

// NewUnpacker prepares root, which must not exist, as an empty root filesystem.
func NewUnpacker(root string, limits UnpackLimits) (*Unpacker, error) {
	if limits.Entries <= 0 || limits.Bytes <= 0 {
		return nil, errors.New("unpack limits must be positive")
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		return nil, fmt.Errorf("create root filesystem: %w", err)
	}
	return &Unpacker{root: root, limits: limits, sameOwner: true}, nil
}

// Apply unpacks one uncompressed layer. A failed layer leaves root unusable.
func (u *Unpacker) Apply(ctx context.Context, layer io.Reader) error {
	opts := []archive.ApplyOpt{archive.WithFilter(u.filter)}
	if !u.sameOwner {
		opts = append(opts, archive.WithNoSameOwner())
	}
	if _, err := archive.Apply(ctx, u.root, &flushing{r: layer, root: u.root}, opts...); err != nil {
		return fmt.Errorf("unpack layer: %w", err)
	}
	return nil
}

// filter rewrites each entry for the sandbox's user namespace and refuses
// what must never reach the guest's disk. It runs before the entry is created.
func (u *Unpacker) filter(hdr *tar.Header) (bool, error) {
	u.stats.Entries++
	if u.stats.Entries > u.limits.Entries {
		return false, fmt.Errorf("image has more than %d entries", u.limits.Entries)
	}
	switch hdr.Typeflag {
	case tar.TypeChar, tar.TypeBlock:
		// The unpacker is real root, so this would be a working device node
		// that the sandbox owns: for one, the TDX guest device.
		u.stats.SkippedDevices++
		return false, nil
	}
	if hdr.FileInfo().Mode().IsRegular() {
		if hdr.Size < 0 || hdr.Size > u.limits.Bytes-u.stats.Bytes {
			return false, fmt.Errorf("image unpacks to more than %d bytes", u.limits.Bytes)
		}
		u.stats.Bytes += hdr.Size
	}
	if hdr.Uid < 0 || hdr.Uid >= IDCount || hdr.Gid < 0 || hdr.Gid >= IDCount {
		return false, fmt.Errorf("%s is owned by %d:%d, outside the %d ids a sandbox has", hdr.Name, hdr.Uid, hdr.Gid, IDCount)
	}
	hdr.Uid += IDBase
	hdr.Gid += IDBase
	for key := range hdr.PAXRecords {
		if name, ok := strings.CutPrefix(key, paxXattr); ok && !keepXattr(name) {
			delete(hdr.PAXRecords, key)
		}
	}
	return true, nil
}

// keepXattr allows the attributes an unprivileged image build can set. The
// rest steer the kernel: trusted.overlay.* redirects overlayfs lookups, and
// ACLs and security labels carry ids and policy from another system.
func keepXattr(name string) bool {
	return strings.HasPrefix(name, "user.") || name == "security.capability"
}

// Finish hands the tree to the sandbox's id range and confirms that nothing
// in it is a device node. Directories the layers implied without listing were
// created as this process, and are shifted here. The tree is on its disk
// when Finish returns: nothing of it is left for the kernel to write later.
func (u *Unpacker) Finish() (UnpackStats, error) {
	root, err := os.OpenRoot(u.root)
	if err != nil {
		return UnpackStats{}, fmt.Errorf("finish root filesystem: %w", err)
	}
	defer root.Close()
	err = fs.WalkDir(root.FS(), ".", func(name string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeDevice != 0 {
			return fmt.Errorf("%s is a device node", name)
		}
		if !u.sameOwner {
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: no ownership information", name)
		}
		uid, uidErr := shiftID(int(st.Uid))
		gid, gidErr := shiftID(int(st.Gid))
		if uidErr != nil || gidErr != nil {
			return fmt.Errorf("%s is owned by %d:%d, outside both id ranges", name, st.Uid, st.Gid)
		}
		if uid == int(st.Uid) && gid == int(st.Gid) {
			return nil
		}
		if err := root.Lchown(name, uid, gid); err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil
		}
		// Lchown clears setuid and setgid bits on files, so restore the mode.
		return root.Chmod(name, info.Mode().Perm()|info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky))
	})
	if err != nil {
		return UnpackStats{}, fmt.Errorf("finish root filesystem: %w", err)
	}
	if err := syncTree(u.root); err != nil {
		return UnpackStats{}, fmt.Errorf("write the root filesystem out: %w", err)
	}
	return u.stats, nil
}

// shiftID maps an id the unpacker itself created into the sandbox's range
// and leaves an id already there alone.
func shiftID(id int) (int, error) {
	switch {
	case id >= IDBase && id < IDBase+IDCount:
		return id, nil
	case id >= 0 && id < IDCount:
		return id + IDBase, nil
	}
	return 0, fmt.Errorf("id %d is outside both id ranges", id)
}
