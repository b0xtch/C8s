//go:build unix

package imagestore

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/containerd/containerd/v2/pkg/archive"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/imagestore/imagestoretest"
)

var roomy = UnpackLimits{Entries: 1000, Bytes: 1 << 20}

type entry = imagestoretest.Entry

var dir, file, charDevice = imagestoretest.Dir, imagestoretest.File, imagestoretest.CharDevice

func layer(entries ...entry) io.Reader {
	return bytes.NewReader(imagestoretest.Layer(entries...))
}

// newUnpacker returns an unpacker on a fresh root. Unprivileged tests cannot
// chown into the mapped range, so they unpack as the test's own user.
func newUnpacker(t *testing.T, limits UnpackLimits, sameOwner bool) *Unpacker {
	t.Helper()
	u, err := NewUnpacker(filepath.Join(t.TempDir(), "rootfs"), limits)
	if err != nil {
		t.Fatal(err)
	}
	u.sameOwner = sameOwner
	return u
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: the agent unpacks as the guest's root, and only root can chown or mknod")
	}
}

func TestFilterShiftsOwnership(t *testing.T) {
	u := newUnpacker(t, roomy, false)
	for _, c := range []struct{ uid, gid, wantUID, wantGID int }{
		{0, 0, IDBase, IDBase},
		{1000, 33, IDBase + 1000, IDBase + 33},
		{IDCount - 1, IDCount - 1, IDBase + IDCount - 1, IDBase + IDCount - 1},
	} {
		hdr := &tar.Header{Name: "f", Typeflag: tar.TypeReg, Uid: c.uid, Gid: c.gid}
		keep, err := u.filter(hdr)
		if err != nil || !keep {
			t.Fatalf("%d:%d: keep=%v err=%v", c.uid, c.gid, keep, err)
		}
		if hdr.Uid != c.wantUID || hdr.Gid != c.wantGID {
			t.Fatalf("%d:%d shifted to %d:%d, want %d:%d", c.uid, c.gid, hdr.Uid, hdr.Gid, c.wantUID, c.wantGID)
		}
	}
}

func TestFilterRefusesIDsOutsideTheRange(t *testing.T) {
	for _, c := range []struct{ uid, gid int }{{IDCount, 0}, {0, IDCount}, {-1, 0}, {0, -1}, {IDBase, IDBase}} {
		u := newUnpacker(t, roomy, false)
		if _, err := u.filter(&tar.Header{Name: "f", Typeflag: tar.TypeReg, Uid: c.uid, Gid: c.gid}); err == nil {
			t.Fatalf("ids %d:%d were accepted", c.uid, c.gid)
		}
	}
}

func TestFilterSkipsDeviceNodes(t *testing.T) {
	u := newUnpacker(t, roomy, false)
	for _, typ := range []byte{tar.TypeChar, tar.TypeBlock} {
		keep, err := u.filter(&tar.Header{Name: "dev/x", Typeflag: typ, Devmajor: 10, Devminor: 257})
		if err != nil || keep {
			t.Fatalf("type %q: keep=%v err=%v, want a silent skip", typ, keep, err)
		}
	}
	if u.stats.SkippedDevices != 2 {
		t.Fatalf("skipped %d devices, want 2", u.stats.SkippedDevices)
	}
}

func TestFilterKeepsOnlyUnprivilegedXattrs(t *testing.T) {
	u := newUnpacker(t, roomy, false)
	hdr := &tar.Header{Name: "f", Typeflag: tar.TypeReg, PAXRecords: map[string]string{
		paxXattr + "user.note":                "kept",
		paxXattr + "security.capability":      "kept",
		paxXattr + "trusted.overlay.redirect": "/etc",
		paxXattr + "trusted.overlay.opaque":   "y",
		paxXattr + "security.selinux":         "label",
		paxXattr + "system.posix_acl_access":  "acl",
		"mtime":                               "1.5",
	}}
	if keep, err := u.filter(hdr); err != nil || !keep {
		t.Fatalf("keep=%v err=%v", keep, err)
	}
	want := map[string]bool{paxXattr + "user.note": true, paxXattr + "security.capability": true, "mtime": true}
	if len(hdr.PAXRecords) != len(want) {
		t.Fatalf("records left: %v", hdr.PAXRecords)
	}
	for key := range hdr.PAXRecords {
		if !want[key] {
			t.Fatalf("record %q survived", key)
		}
	}
}

func TestFilterEnforcesLimits(t *testing.T) {
	u := newUnpacker(t, UnpackLimits{Entries: 2, Bytes: 10}, false)
	for i := 0; i < 2; i++ {
		if _, err := u.filter(&tar.Header{Name: "d", Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := u.filter(&tar.Header{Name: "d", Typeflag: tar.TypeDir}); err == nil {
		t.Fatal("a third entry passed a limit of two")
	}

	u = newUnpacker(t, UnpackLimits{Entries: 10, Bytes: 10}, false)
	if _, err := u.filter(&tar.Header{Name: "a", Typeflag: tar.TypeReg, Size: 6}); err != nil {
		t.Fatal(err)
	}
	if _, err := u.filter(&tar.Header{Name: "b", Typeflag: tar.TypeReg, Size: 5}); err == nil {
		t.Fatal("11 bytes passed a limit of 10")
	}
	if _, err := u.filter(&tar.Header{Name: "c", Typeflag: tar.TypeReg, Size: -1}); err == nil {
		t.Fatal("a negative size was accepted")
	}
}

func TestApplyUnpacksFilesAndLeavesDevicesOut(t *testing.T) {
	u := newUnpacker(t, roomy, false)
	err := u.Apply(context.Background(), layer(dir("etc"), file("etc/motd", "hello\n"),
		entry{Header: tar.Header{Name: "etc/alias", Typeflag: tar.TypeSymlink, Linkname: "motd", Mode: 0o777}},
		dir("dev"), charDevice("dev/tdx_guest"),
	))
	if err != nil {
		t.Fatal(err)
	}
	stats, err := u.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(u.root, "etc/alias")); err != nil || string(got) != "hello\n" {
		t.Fatalf("etc/alias: %q, %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(u.root, "dev/tdx_guest")); !os.IsNotExist(err) {
		t.Fatalf("the device entry left something behind: %v", err)
	}
	if stats.SkippedDevices != 1 || stats.Entries != 5 || stats.Bytes != 6 {
		t.Fatalf("stats %+v", stats)
	}
}

func TestApplyKeepsEveryEntryInsideRoot(t *testing.T) {
	u := newUnpacker(t, roomy, false)
	outside := filepath.Join(filepath.Dir(u.root), "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	// Whether such a layer is refused or contained is containerd's choice.
	// What must hold is that nothing lands outside root.
	_ = u.Apply(context.Background(), layer(entry{Header: tar.Header{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: outside, Mode: 0o777}},
		file("escape/through-symlink", "x"),
		file("../outside/through-dotdot", "x"),
		entry{Header: tar.Header{Name: "hard", Typeflag: tar.TypeLink, Linkname: "../outside/target", Mode: 0o644}},
	))
	left, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("entries escaped the root filesystem: %v", left)
	}
}

func TestApplyHonoursWhiteouts(t *testing.T) {
	u := newUnpacker(t, roomy, false)
	ctx := context.Background()
	if err := u.Apply(ctx, layer(dir("a"), file("a/gone", "1"), file("a/kept", "2"))); err != nil {
		t.Fatal(err)
	}
	if err := u.Apply(ctx, layer(file("a/.wh.gone", ""))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(u.root, "a/gone")); !os.IsNotExist(err) {
		t.Fatalf("a/gone survived its whiteout: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(u.root, "a/kept")); err != nil {
		t.Fatal(err)
	}
}

func TestApplyStopsAtTheByteLimit(t *testing.T) {
	u := newUnpacker(t, UnpackLimits{Entries: 10, Bytes: 8}, false)
	err := u.Apply(context.Background(), layer(file("big", strings.Repeat("x", 9))))
	if err == nil || !strings.Contains(err.Error(), "more than 8 bytes") {
		t.Fatalf("err = %v", err)
	}
}

func owner(t *testing.T, path string) (uid, gid int, mode fs.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return int(st.Uid), int(st.Gid), info.Mode()
}

func TestAsRootOwnershipLandsInTheMappedRange(t *testing.T) {
	requireRoot(t)
	u := newUnpacker(t, roomy, true)
	err := u.Apply(context.Background(), layer(entry{Header: tar.Header{Name: "usr/bin/su", Typeflag: tar.TypeReg, Mode: 0o4755}, Body: "x"},
		entry{Header: tar.Header{Name: "home/app/data", Typeflag: tar.TypeReg, Mode: 0o600, Uid: 1000, Gid: 1000}, Body: "y"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Finish(); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][2]int{
		".":             {IDBase, IDBase},
		"usr":           {IDBase, IDBase}, // implied by the layer, created as root
		"usr/bin/su":    {IDBase, IDBase},
		"home/app/data": {IDBase + 1000, IDBase + 1000},
	} {
		uid, gid, _ := owner(t, filepath.Join(u.root, path))
		if uid != want[0] || gid != want[1] {
			t.Errorf("%s is owned by %d:%d, want %d:%d", path, uid, gid, want[0], want[1])
		}
	}
	if _, _, mode := owner(t, filepath.Join(u.root, "usr/bin/su")); mode&fs.ModeSetuid == 0 {
		t.Errorf("usr/bin/su lost its setuid bit: %v", mode)
	}
}

func TestAsRootADeviceEntryCreatesNoNode(t *testing.T) {
	requireRoot(t)
	// Control: without the filter, containerd makes the node. If this stops
	// being true the assertion below would pass for the wrong reason.
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.Mkdir(plain, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Apply(context.Background(), plain, layer(charDevice("tdx_guest"))); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(filepath.Join(plain, "tdx_guest")); err != nil || info.Mode()&fs.ModeCharDevice == 0 {
		t.Fatalf("control: an unfiltered unpack as root did not create the device node (%v, %v)", info, err)
	}

	u := newUnpacker(t, roomy, true)
	if err := u.Apply(context.Background(), layer(charDevice("tdx_guest"))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(u.root, "tdx_guest")); !os.IsNotExist(err) {
		t.Fatalf("a device node reached the root filesystem: %v", err)
	}
}

func TestAsRootFinishRefusesADeviceNode(t *testing.T) {
	requireRoot(t)
	u := newUnpacker(t, roomy, true)
	if err := unix.Mknod(filepath.Join(u.root, "node"), unix.S_IFCHR|0o600, int(unix.Mkdev(1, 3))); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Finish(); err == nil || !strings.Contains(err.Error(), "device node") {
		t.Fatalf("err = %v", err)
	}
}

// An image is written out as it is unpacked, and whole when the unpacker
// finishes: no more of it than flushEvery waits in memory for its disk, and
// none is left for the kernel to write later. A tree that cannot be written
// out at the end is not handed on.
func TestUnpackWritesAnImageOutAsItGoesAndWholeAtItsEnd(t *testing.T) {
	var synced []string
	fail := error(nil)
	was := syncTree
	syncTree = func(root string) error {
		synced = append(synced, root)
		return fail
	}
	t.Cleanup(func() { syncTree = was })

	big := strings.Repeat("x", flushEvery/2+1)
	u := newUnpacker(t, UnpackLimits{Entries: 100, Bytes: 4 * flushEvery}, false)
	if err := u.Apply(context.Background(), layer(file("a", big), file("b", big), file("c", big), file("d", big), file("e", "small"))); err != nil {
		t.Fatal(err)
	}
	// Four files of half a measure and a little each: two full measures.
	if len(synced) != 2 || synced[0] != u.root || synced[1] != u.root {
		t.Fatalf("the tree was written out %d times while %d bytes were unpacked: %v", len(synced), 4*len(big), synced)
	}
	if _, err := u.Finish(); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 3 || synced[2] != u.root {
		t.Fatalf("the tree was written out %d times by the unpacker's end, want once more", len(synced))
	}

	u = newUnpacker(t, roomy, false)
	if err := u.Apply(context.Background(), layer(file("a", "small"))); err != nil {
		t.Fatal(err)
	}
	fail = syscall.EIO
	if _, err := u.Finish(); err == nil || !strings.Contains(err.Error(), "write the root filesystem out") {
		t.Fatalf("Finish of a tree that could not be written out: %v", err)
	}
}
