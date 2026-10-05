//go:build !c8s_simtee

package sessioninit

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestPrepareRootOnTDX(t *testing.T) {
	f := tdxGuest()
	if err := prepareRoot(f); err != nil {
		t.Fatal(err)
	}

	// The root: one read-only verity mapping under the command line's hash,
	// mounted read-only.
	root := f.mappings[0]
	if root.name != "root" || !root.opts.ReadOnly || root.target.Type != "verity" {
		t.Fatalf("root mapping %+v", root)
	}
	for _, want := range []string{" " + testRootHash + " ", "252:2 252:3", " 4096 4096 64 1 sha256 ", "panic_on_corruption"} {
		if !strings.Contains(root.target.Params, want) {
			t.Errorf("verity table %q lacks %q", root.target.Params, want)
		}
	}
	if m := f.mounted(newRoot); m == nil || m.source != "/dev/dm-0" || m.fstype != "erofs" || m.flags&msReadOnly == 0 {
		t.Fatalf("root mount %+v", m)
	}

	// The state volume: encrypted under a key that is in no table any more,
	// made by the root's own mke2fs, inside the root.
	scratch := f.mappings[1]
	if scratch.name != "scratch" || !scratch.opts.Secure || scratch.target.Type != "crypt" || scratch.target.Length != 8388608 {
		t.Fatalf("scratch mapping %+v", scratch)
	}
	if !strings.Contains(scratch.target.Params, strings.Repeat("42", 64)) || !strings.Contains(scratch.target.Params, " 252:16 ") {
		t.Fatalf("crypt table %q", scratch.target.Params)
	}
	if len(f.ran) != 1 || f.ran[0][0] != newRoot || f.ran[0][1] != "/usr/sbin/mke2fs" || f.ran[0][len(f.ran[0])-1] != "/dev/dm-1" {
		t.Fatalf("helpers run: %v", f.ran)
	}
	if m := f.mounted(stateDir); m == nil || m.source != "/dev/dm-1" || m.fstype != "ext4" {
		t.Fatalf("state mount %+v", m)
	}

	// One overlay for each listed directory, once, in the lists' order.
	want := []string{"home", "var", "root", "etc/c8s-session/state"}
	for i, dir := range want {
		m := f.mounted(newRoot + "/" + dir)
		if m == nil || m.fstype != "overlay" {
			t.Fatalf("no overlay on %s", dir)
		}
		prefix := stateDir + "/" + string(rune('1'+i))
		if m.data != "lowerdir="+newRoot+"/"+dir+",upperdir="+prefix+"/upper,workdir="+prefix+"/work" {
			t.Errorf("overlay on %s: %s", dir, m.data)
		}
	}
	if len(f.owners) != len(want) {
		t.Errorf("owners copied: %v", f.owners)
	}
	if m := f.mounted(newRoot + "/run"); m == nil || m.fstype != "tmpfs" {
		t.Fatal("no /run")
	}

	// The programs the guest runs next are read ahead, each once.
	if want := []string{newRoot + "/usr/local/bin/c8s-session-guest", newRoot + "/usr/sbin/nft"}; !reflect.DeepEqual(f.warmed, want) {
		t.Errorf("read ahead: %v", f.warmed)
	}

	// The launch key: staged as it was read, read-only, and its digest
	// extended into RTMR[3] in one write.
	key := f.files["/opkey/"+launchKeyFile]
	if !bytes.Equal(f.writes[newRoot+launchKeyDir+"/"+launchKeyName], key) {
		t.Fatal("the staged key is not the volume's")
	}
	digest := sha512.Sum384(key)
	if !bytes.Equal(f.writes[rtmr3Path], digest[:]) {
		t.Fatalf("RTMR[3] extended with %x", f.writes[rtmr3Path])
	}
	var readOnly bool
	for _, m := range f.mounts {
		if m.target == newRoot+launchKeyDir && m.flags&(msBind|msRemount|msReadOnly) == msBind|msRemount|msReadOnly {
			readOnly = true
		}
	}
	if !readOnly {
		t.Error("the staged key's directory is not read-only")
	}
	if m := f.mounted("/opkey"); m == nil || m.flags&msNoSymFollow == 0 || m.flags&msReadOnly == 0 {
		t.Errorf("launch volume mount %+v", m)
	}
	if len(f.unmounts) != 1 || f.unmounts[0] != "/opkey" {
		t.Errorf("unmounted %v", f.unmounts)
	}
}

// A boot configuration the init cannot read is no reason to stop before the
// root is up: reading ahead is a hint.
func TestPrepareRootWithoutABootConfiguration(t *testing.T) {
	for name, data := range map[string][]byte{"missing": nil, "broken": []byte("{")} {
		f := tdxGuest()
		delete(f.files, newRoot+bootConfigPath)
		if data != nil {
			f.files[newRoot+bootConfigPath] = data
		}
		if err := prepareRoot(f); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(f.warmed) != 0 {
			t.Fatalf("%s: read ahead %v", name, f.warmed)
		}
	}
}

func TestPrepareRootWithoutScratchDisk(t *testing.T) {
	f := tdxGuest()
	f.disks = append(f.disks[:1], f.disks[2:]...)
	if err := prepareRoot(f); err != nil {
		t.Fatal(err)
	}
	if len(f.mappings) != 1 || len(f.ran) != 0 {
		t.Fatalf("mappings %v, helpers %v", f.mappings, f.ran)
	}
	if m := f.mounted(stateDir); m == nil || m.fstype != "tmpfs" {
		t.Fatalf("state mount %+v", m)
	}
}

func TestPrepareRootUnbound(t *testing.T) {
	f := tdxGuest()
	f.disks = f.disks[:2]
	if err := prepareRoot(f); err != nil {
		t.Fatal(err)
	}
	if _, wrote := f.writes[rtmr3Path]; wrote {
		t.Fatal("RTMR[3] extended without a launch key")
	}
	if f.mounted("/opkey") != nil {
		t.Fatal("mounted a launch volume that is not there")
	}
}

func TestPrepareRootWaitsForTheBootDisk(t *testing.T) {
	f := tdxGuest()
	f.disksAfter = 50_000_000 // 50 ms
	if err := prepareRoot(f); err != nil {
		t.Fatal(err)
	}
	if f.slept < f.disksAfter {
		t.Fatalf("slept %v", f.slept)
	}
}

func TestPrepareRootRootFilesystems(t *testing.T) {
	f := tdxGuest()
	f.refuseFilesystem["erofs"] = true
	if err := prepareRoot(f); err == nil {
		// The kernel file systems use other types, so only the root's mount
		// falls through to the next type.
		if m := f.mounted(newRoot); m == nil || m.fstype != "squashfs" {
			t.Fatalf("root mount %+v", m)
		}
	} else {
		t.Fatal(err)
	}
}

func TestPrepareRootRefuses(t *testing.T) {
	cases := map[string]struct {
		change func(f *fakeGuest)
		want   string
	}{
		"no root hash":                  {func(f *fakeGuest) { f.files["/proc/cmdline"] = []byte("quiet") }, "no roothash="},
		"a root hash that is no digest": {func(f *fakeGuest) { f.files["/proc/cmdline"] = []byte("roothash=abc") }, "is not a SHA-256"},
		"no boot disk":                  {func(f *fakeGuest) { f.disks = f.disks[1:] }, "no disk carries a root partition"},
		"a tree of another digest":      {func(f *fakeGuest) { f.disks[0].data = bootDiskImage("sha512") }, "the verity tree uses sha512"},
		"a tree larger than its partition": {func(f *fakeGuest) {
			copy(f.disks[0].data[700*lbaSize:], veritySuperblock(65, "sha256"))
		}, "the root partition holds"},
		"no verity superblock":               {func(f *fakeGuest) { f.disks[0].data[700*lbaSize] = 'X' }, "no signature"},
		"a root that does not mount":         {func(f *fakeGuest) { f.failMount[newRoot] = errors.New("bad superblock") }, "bad superblock"},
		"a verity device the kernel refuses": {func(f *fakeGuest) { f.failMount["map:root"] = errors.New("EINVAL") }, "EINVAL"},
		"an empty scratch disk":              {func(f *fakeGuest) { f.disks[1].Sectors = 0 }, "is empty"},
		"mke2fs failing":                     {func(f *fakeGuest) { f.failRun["/usr/sbin/mke2fs"] = errors.New("status 1") }, "make the file system"},
		"no list of writable state": {func(f *fakeGuest) {
			delete(f.files, newRoot+stateListDir+"/10-base.conf")
			delete(f.files, newRoot+stateListDir+"/50-session.conf")
		}, "lists no directory"},
		"a listed directory the image lacks": {func(f *fakeGuest) { delete(f.dirs, newRoot+"/root") }, "is no directory of the image"},
		"an empty launch key":                {func(f *fakeGuest) { f.files["/opkey/"+launchKeyFile] = nil }, "key is empty"},
		"no launch key on the volume":        {func(f *fakeGuest) { delete(f.files, "/opkey/"+launchKeyFile) }, launchKeyFile},
		"no way to bind the key":             {func(f *fakeGuest) { delete(f.files, rtmr3Path) }, "neither a writable RTMR[3]"},
		"RTMR[3] refusing the write":         {func(f *fakeGuest) { f.failMount["write:"+rtmr3Path] = errors.New("EINVAL") }, "extend RTMR[3]"},
		"/proc not mounting":                 {func(f *fakeGuest) { f.failMount["/proc"] = errors.New("ENODEV") }, "mount /proc"},
	}
	for name, c := range cases {
		f := tdxGuest()
		c.change(f)
		// A missing disk is waited for; the fake's clock runs with its sleeps.
		err := prepareRoot(f)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, c.want)
		}
		if _, wrote := f.writes[rtmr3Path]; wrote && c.want != "extend RTMR[3]" {
			t.Errorf("%s: RTMR[3] was extended", name)
		}
	}
}

// snpGuest is the same guest on SEV-SNP: no RTMR, a guest device, and a
// report whose HOST_DATA the launcher set.
func snpGuest(hostData []byte) *fakeGuest {
	f := tdxGuest()
	delete(f.files, rtmr3Path)
	f.files[sevGuest] = nil
	report := make([]byte, 1184)
	copy(report[192:], hostData)
	f.files[tsmReport+"/launch-key/outblob"] = report
	return f
}

func TestPrepareRootOnSNP(t *testing.T) {
	key := tdxGuest().files["/opkey/"+launchKeyFile]
	digest := sha256.Sum256(key)
	f := snpGuest(digest[:])
	if err := prepareRoot(f); err != nil {
		t.Fatal(err)
	}
	if got := f.writes[tsmReport+"/launch-key/inblob"]; len(got) != 64 {
		t.Fatalf("report data of %d bytes", len(got))
	}
	if f.mounted("/sys/kernel/config") == nil {
		t.Fatal("configfs not mounted")
	}

	// A launcher that bound another key, or none.
	for name, hostData := range map[string][]byte{"another key": bytes.Repeat([]byte{1}, 32), "no key": make([]byte, 32)} {
		err := prepareRoot(snpGuest(hostData))
		if err == nil || !strings.Contains(err.Error(), "HOST_DATA") {
			t.Errorf("%s: %v", name, err)
		}
	}

	short := snpGuest(digest[:])
	short.files[tsmReport+"/launch-key/outblob"] = make([]byte, 100)
	if err := prepareRoot(short); err == nil || !strings.Contains(err.Error(), "a report of 100 bytes") {
		t.Errorf("a short report: %v", err)
	}
}
