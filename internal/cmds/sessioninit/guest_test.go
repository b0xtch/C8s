package sessioninit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/fs"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/guestend"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

const testBootConfig = `{
  "hostname": "session",
  "steps": [["/usr/local/bin/c8s-session-guest", "session-agent", "load"], ["/usr/sbin/nft", "-f", "/etc/c8s-session/firewall.nft"]],
  "service": ["/usr/local/bin/c8s-session-guest", "session-agent", "run", "--platform=tdx"]
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
	if err == nil || !strings.Contains(err.Error(), "/usr/local/bin/c8s-session-guest ended with status 3") {
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
		{[]string{"/usr/local/bin/c8s-session-guest", "session-agent", "load"}, "", 0},
		{[]string{"/usr/sbin/nft", "-f", "/etc/c8s-session/firewall.nft"}, "", 0},
		{[]string{"/usr/local/bin/c8s-session-guest", "session-agent", "run", "--platform=tdx"}, serviceCgroup, serviceOOMScore},
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
		"a service that does not start": {func(f *fakeGuest) { f.startErr["/usr/local/bin/c8s-session-guest"] = errors.New("ENOEXEC") }, "ENOEXEC", 0},
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

// said runs a booted guest to its end as process 1 does, with a launcher
// that takes its last word, and returns the word the launcher was sent.
func said(t *testing.T, change func(*fakeGuest)) (*fakeGuest, *disclosure.End) {
	t.Helper()
	f := bootedGuest()
	f.files[guestend.HostConfigFile] = []byte(`{"end_port": 20007, "collateral_port": 20003}`)
	received := make(chan *disclosure.End, 1)
	f.launcher = func(uint32) (net.Conn, error) {
		guest, launcher := net.Pipe()
		go func() {
			end, _ := guestend.Receive(launcher, time.Second)
			received <- end
		}()
		return guest, nil
	}
	change(f)
	err := runGuest(f)
	sayLastWord(f, lastWord(err))
	select {
	case end := <-received:
		return f, end
	case <-time.After(100 * time.Millisecond):
		return f, nil
	}
}

// A guest whose service has ended tells its launcher how far it had come
// and why, on the port the host's file names: the reason the service exited
// with, when it is one of the service's own, and otherwise the status as it
// is, or the signal that killed it and whether the kernel sent it for memory.
func TestGuestSaysWhyItEnds(t *testing.T) {
	process := disclosure.EndStatus(disclosure.EndProcess)
	for name, tc := range map[string]struct {
		change func(*fakeGuest)
		want   disclosure.End
		status int
		signal int
	}{
		"its session's process ended": {func(f *fakeGuest) {
			f.exits[3][1] = process
			f.files[guestend.PhaseFile] = []byte("running\n")
		}, disclosure.End{Phase: "running", Code: disclosure.EndProcess}, -1, -1},
		"its service exited before it was ready": {func(*fakeGuest) {},
			disclosure.End{Phase: disclosure.EndedStarting, Code: disclosure.EndExited}, 3, -1},
		"its service exited while it waited for a bind": {func(f *fakeGuest) { f.files[guestend.PhaseFile] = []byte("ready") },
			disclosure.End{Phase: "ready", Code: disclosure.EndExited}, 3, -1},
		"its service was killed": {func(f *fakeGuest) {
			f.killed = map[int]int{103: 11}
			f.files[guestend.PhaseFile] = []byte("bound")
		}, disclosure.End{Phase: "bound", Code: disclosure.EndKilled}, -1, 11},
		"the kernel killed its service for memory": {func(f *fakeGuest) {
			f.killed = map[int]int{103: 9}
			f.files[guestend.PhaseFile] = []byte("running")
			f.files[serviceCgroup+"/memory.events.local"] = []byte("low 0\nhigh 0\nmax 0\noom 1\noom_kill 1\noom_group_kill 0\n")
		}, disclosure.End{Phase: "running", Code: disclosure.EndKilled, Memory: true}, -1, 9},
		"its service was killed, and not for memory": {func(f *fakeGuest) {
			f.killed = map[int]int{103: 9}
			f.files[serviceCgroup+"/memory.events.local"] = []byte("oom 0\noom_kill 0\n")
		}, disclosure.End{Phase: disclosure.EndedStarting, Code: disclosure.EndKilled}, -1, 9},
		"a step of its boot failed": {func(f *fakeGuest) { f.exits[1][1] = 4 },
			disclosure.End{Phase: disclosure.EndedBooting, Code: disclosure.EndBoot}, -1, -1},
	} {
		f, end := said(t, tc.change)
		if end == nil {
			t.Errorf("%s: its launcher was told nothing (the init logged %q)", name, f.logs)
			continue
		}
		if end.Phase != tc.want.Phase || end.Code != tc.want.Code || end.Memory != tc.want.Memory {
			t.Errorf("%s: its launcher was told %s", name, end)
		}
		if (tc.status >= 0) != (end.Status != nil) || end.Status != nil && *end.Status != tc.status {
			t.Errorf("%s: the word's status is %v, want %d", name, end.Status, tc.status)
		}
		if (tc.signal >= 0) != (end.Signal != nil) || end.Signal != nil && *end.Signal != tc.signal {
			t.Errorf("%s: the word's signal is %v, want %d", name, end.Signal, tc.signal)
		}
		if len(f.dialed) != 1 || f.dialed[0] != 20007 {
			t.Errorf("%s: the init dialed %v, and the host named port 20007", name, f.dialed)
		}
	}
}

// A guest that cannot say its word ends all the same: with no port named,
// with a host's file that is not staged, and with no launcher that listens.
func TestGuestEndsWithoutAWordItCannotSay(t *testing.T) {
	for name, change := range map[string]func(*fakeGuest){
		"the host named no port":  func(f *fakeGuest) { f.files[guestend.HostConfigFile] = []byte(`{"collateral_port": 20003}`) },
		"the host's file is gone": func(f *fakeGuest) { delete(f.files, guestend.HostConfigFile) },
		"no launcher listens":     func(f *fakeGuest) { f.launcher = nil },
		"the launcher takes none": func(f *fakeGuest) {
			f.launcher = func(uint32) (net.Conn, error) {
				guest, launcher := net.Pipe()
				t.Cleanup(func() { launcher.Close() })
				return guest, nil
			}
		},
	} {
		began := time.Now()
		f, end := said(t, change)
		if end != nil {
			t.Errorf("%s: a launcher was told %s", name, end)
		}
		if waited := time.Since(began); waited > 2*guestend.Wait {
			t.Errorf("%s: the guest's end waited %s", name, waited)
		}
		if !slices.ContainsFunc(f.logs, func(line string) bool { return strings.Contains(line, "no last word") }) {
			t.Errorf("%s: the init did not log that it said no word: %q", name, f.logs)
		}
	}
}
