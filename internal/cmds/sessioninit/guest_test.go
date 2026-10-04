package sessioninit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

const testBootConfig = `{
  "hostname": "session",
  "steps": [["/usr/local/bin/c8s", "session-agent", "load"], ["/usr/sbin/nft", "-f", "/etc/c8s-session/firewall.nft"]],
  "service": ["/usr/local/bin/c8s", "session-agent", "run", "--platform=tdx"]
}`

func bootedGuest() *fakeGuest {
	f := newFakeGuest()
	f.files[bootConfigPath] = []byte(testBootConfig)
	f.files["/usr/lib/sysctl.d/50-hardening.conf"] = []byte("kernel.kptr_restrict = 2\n# comment\nkernel.dmesg_restrict=1\n-kernel.absent = 1\nnet.missing.key = 1\n")
	f.files["/etc/sysctl.d/50-c8s-session.conf"] = []byte("net.core.fb_tunnels_only_for_init_net = 2\n")
	f.sysctlErr["kernel/absent"] = errors.New("EINVAL")
	f.sysctlErr["net/missing/key"] = fs.ErrNotExist
	// The two steps end, an orphan is reaped, then the service ends.
	f.exits = [][2]int{{101, 0}, {102, 0}, {555, 9}, {103, 3}}
	return f
}

func TestRunGuest(t *testing.T) {
	f := bootedGuest()
	err := runGuest(f)
	if err == nil || !strings.Contains(err.Error(), "/usr/local/bin/c8s ended with status 3") {
		t.Fatalf("the guest ended with %v", err)
	}
	if f.root != newRoot {
		t.Fatalf("moved into %q", f.root)
	}
	for _, target := range []string{"/sys/fs/cgroup", "/dev/pts", "/dev/shm", "/tmp", "/sys/kernel/config"} {
		if f.mounted(target) == nil {
			t.Errorf("%s is not mounted", target)
		}
	}
	if f.hostname != "session" || !f.loopback || !f.noNewPriv || f.openFiles != openFiles {
		t.Fatalf("hostname %q loopback %v no-new-privileges %v open files %d", f.hostname, f.loopback, f.noNewPriv, f.openFiles)
	}
	wantSysctls := map[string]string{"kernel/kptr_restrict": "2", "kernel/dmesg_restrict": "1", "net/core/fb_tunnels_only_for_init_net": "2"}
	if !reflect.DeepEqual(f.sysctls, wantSysctls) {
		t.Fatalf("kernel settings %v", f.sysctls)
	}
	if !f.dirs[serviceCgroup] {
		t.Fatal("no service cgroup")
	}
	if got := string(f.writes["/sys/fs/cgroup/cgroup.subtree_control"]); !strings.HasPrefix(got, "+") {
		t.Fatalf("controllers: %q", got)
	}
	want := []started{
		{[]string{"/usr/local/bin/c8s", "session-agent", "load"}, "", 0},
		{[]string{"/usr/sbin/nft", "-f", "/etc/c8s-session/firewall.nft"}, "", 0},
		{[]string{"/usr/local/bin/c8s", "session-agent", "run", "--platform=tdx"}, serviceCgroup, serviceOOMScore},
	}
	if !reflect.DeepEqual(f.starts, want) {
		t.Fatalf("started %+v", f.starts)
	}
}

func TestRunGuestEndsOn(t *testing.T) {
	cases := map[string]struct {
		change func(f *fakeGuest)
		want   string
		starts int
	}{
		"a step that fails":             {func(f *fakeGuest) { f.exits = [][2]int{{101, 0}, {102, 1}} }, "nft -f /etc/c8s-session/firewall.nft ended with status 1", 2},
		"a step that does not start":    {func(f *fakeGuest) { f.startErr["/usr/sbin/nft"] = errors.New("ENOENT") }, "/usr/sbin/nft: ENOENT", 1},
		"a service that does not start": {func(f *fakeGuest) { f.startErr["/usr/local/bin/c8s"] = errors.New("ENOEXEC") }, "ENOEXEC", 0},
		"no boot configuration":         {func(f *fakeGuest) { delete(f.files, bootConfigPath) }, bootConfigPath, 0},
		"a boot configuration with an unknown member": {func(f *fakeGuest) {
			f.files[bootConfigPath] = []byte(`{"service":["/bin/a"],"extra":1}`)
		}, "boot configuration", 0},
		"a service named by a relative path": {func(f *fakeGuest) {
			f.files[bootConfigPath] = []byte(`{"service":["c8s"]}`)
		}, "names no absolute path", 0},
		"a kernel setting that does not take": {func(f *fakeGuest) { f.sysctlErr["kernel/kptr_restrict"] = errors.New("EPERM") }, "kernel settings: kernel/kptr_restrict", 0},
		"a sysctl file without a value":       {func(f *fakeGuest) { f.files["/etc/sysctl.d/99-bad.conf"] = []byte("kernel.panic\n") }, "no value", 0},
		"the move into the root failing":      {func(f *fakeGuest) { f.failMount["switch"] = errors.New("EBUSY") }, "move into the root", 0},
		"no cgroup file system":               {func(f *fakeGuest) { f.failMount["/sys/fs/cgroup"] = errors.New("ENODEV") }, "mount /sys/fs/cgroup", 0},
		"nothing left to wait for":            {func(f *fakeGuest) { f.exits = nil }, "wait for process", 1},
	}
	for name, c := range cases {
		f := bootedGuest()
		c.change(f)
		err := runGuest(f)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, c.want)
		}
		if len(f.starts) != c.starts {
			t.Errorf("%s: started %d programs, want %d", name, len(f.starts), c.starts)
		}
	}
}

func TestRunGuestWithoutConfigfs(t *testing.T) {
	f := bootedGuest()
	f.failMount["/sys/kernel/config"] = errors.New("ENODEV")
	if err := runGuest(f); err == nil || !strings.Contains(err.Error(), "ended with status 3") {
		t.Fatalf("a guest whose kernel has no configfs: %v", err)
	}
}

func TestReadGPT(t *testing.T) {
	disk := bootDiskImage("sha256")
	parts, err := readGPT(bytes.NewReader(disk))
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 3 {
		t.Fatalf("%d partitions", len(parts))
	}
	root, verity, ok := rootPartitions(parts)
	if !ok || root.Number != 2 || root.First != 100 || verity.Number != 3 || verity.First != 700 {
		t.Fatalf("root %+v verity %+v", root, verity)
	}
	if _, _, ok := rootPartitions(parts[:2]); ok {
		t.Fatal("a table without a verity partition has a root")
	}

	corrupt := func(change func(d []byte)) error {
		d := append([]byte(nil), disk...)
		change(d)
		_, err := readGPT(bytes.NewReader(d))
		return err
	}
	cases := map[string]func(d []byte){
		"no signature":              func(d []byte) { d[lbaSize] = 'X' },
		"a header that was changed": func(d []byte) { d[lbaSize+40]++ },
		"entries that were changed": func(d []byte) { d[2*lbaSize+300]++ },
	}
	for name, change := range cases {
		if err := corrupt(change); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := readGPT(bytes.NewReader(disk[:600])); err == nil {
		t.Error("a truncated disk: parsed")
	}

	// A table whose fields are checksummed but make no sense.
	resign := func(d []byte) {
		header := d[lbaSize : lbaSize+92]
		binary.LittleEndian.PutUint32(header[16:], 0)
		binary.LittleEndian.PutUint32(header[16:], crc32Of(header))
	}
	senseless := map[string]func(d []byte){
		"no entries":            func(d []byte) { binary.LittleEndian.PutUint32(d[lbaSize+80:], 0) },
		"entries of 100 bytes":  func(d []byte) { binary.LittleEndian.PutUint32(d[lbaSize+84:], 100) },
		"entries at sector 1":   func(d []byte) { binary.LittleEndian.PutUint64(d[lbaSize+72:], 1) },
		"a header of 512 bytes": func(d []byte) { binary.LittleEndian.PutUint32(d[lbaSize+12:], 512) },
	}
	for name, change := range senseless {
		if err := corrupt(func(d []byte) { change(d); resign(d) }); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	backwards := gptDisk(1000, []partition{{Number: 1, Type: rootPartitionType, First: 500, Last: 400}})
	if _, err := readGPT(bytes.NewReader(backwards)); err == nil {
		t.Error("a partition that ends before it starts: parsed")
	}
}

func TestGUIDEncoding(t *testing.T) {
	// The EFI system partition's type, as it sits in a table.
	want := []byte{0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}
	got := mustGUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("encoded % x", got)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a short GUID did not panic")
		}
	}()
	mustGUID("c12a7328")
}

func TestISOVolumeLabel(t *testing.T) {
	if got := isoVolumeLabel(bytes.NewReader(isoImage("opkeydata"))); got != "opkeydata" {
		t.Fatalf("label %q", got)
	}
	notISO := isoImage("opkeydata")
	notISO[isoDescriptorOffset+1] = 'X'
	if got := isoVolumeLabel(bytes.NewReader(notISO)); got != "" {
		t.Fatalf("label %q of a volume that is no ISO 9660", got)
	}
	if got := isoVolumeLabel(bytes.NewReader(make([]byte, 100))); got != "" {
		t.Fatalf("label %q of a short disk", got)
	}
}
