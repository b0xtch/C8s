package sessioninit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/devmapper"
)

// memDisk is a disk held in memory.
type memDisk struct{ *bytes.Reader }

func (memDisk) Close() error { return nil }

// fakeDisk describes one disk of a fake guest.
type fakeDisk struct {
	blockDevice
	data []byte
}

type mountCall struct {
	source, target, fstype string
	flags                  uintptr
	data                   string
}

type mapping struct {
	name   string
	target devmapper.Target
	opts   devmapper.Options
}

type started struct {
	argv   []string
	cgroup string
	oom    int
}

// fakeGuest records what the init asks of the kernel and answers from what a
// test set up.
type fakeGuest struct {
	files    map[string][]byte
	dirs     map[string]bool
	disks    []fakeDisk
	mounts   []mountCall
	unmounts []string
	mappings []mapping
	ran      [][]string
	warmed   []string
	writes   map[string][]byte
	owners   [][2]string
	logs     []string
	slept    time.Duration
	// failMount fails a mount by target, failRun a helper by program.
	failMount map[string]error
	failRun   map[string]error
	// refuseFilesystem makes a mount of this type fail, for the root's
	// file system detection.
	refuseFilesystem map[string]bool
	// disksAfter hides the disks until this much sleep has passed.
	disksAfter time.Duration

	// The guest half.
	root      string
	hostname  string
	loopback  bool
	sysctls   map[string]string
	sysctlErr map[string]error
	noNewPriv bool
	openFiles uint64
	starts    []started
	// exits lists what Wait returns, in order: a process id and its status.
	exits    [][2]int
	nextPID  int
	startErr map[string]error
}

func newFakeGuest() *fakeGuest {
	return &fakeGuest{
		files: map[string][]byte{}, dirs: map[string]bool{}, writes: map[string][]byte{},
		failMount: map[string]error{}, failRun: map[string]error{}, refuseFilesystem: map[string]bool{},
		sysctls: map[string]string{}, sysctlErr: map[string]error{}, startErr: map[string]error{}, nextPID: 100,
	}
}

func (f *fakeGuest) Mount(source, target, fstype string, flags uintptr, data string) error {
	if err := f.failMount[target]; err != nil {
		return err
	}
	if f.refuseFilesystem[fstype] {
		return errors.New("wrong fs type")
	}
	f.mounts = append(f.mounts, mountCall{source, target, fstype, flags, data})
	return nil
}

func (f *fakeGuest) Unmount(target string) error {
	f.unmounts = append(f.unmounts, target)
	return nil
}

func (f *fakeGuest) MkdirAll(path string, _ os.FileMode) error {
	f.dirs[path] = true
	return nil
}

func (f *fakeGuest) ReadFile(path string, limit int64) ([]byte, error) {
	data, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("%s: %w", path, fs.ErrNotExist)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s holds more than %d bytes", path, limit)
	}
	return data, nil
}

func (f *fakeGuest) WriteFile(path string, data []byte, _ os.FileMode) error {
	if err := f.failMount["write:"+path]; err != nil {
		return err
	}
	f.writes[path] = append([]byte(nil), data...)
	f.files[path] = f.writes[path]
	return nil
}

func (f *fakeGuest) ReadDirFiles(dir string, _ int64) (map[string][]byte, error) {
	out := map[string][]byte{}
	for path, data := range f.files {
		if rest, ok := strings.CutPrefix(path, dir+"/"); ok && !strings.Contains(rest, "/") {
			out[rest] = data
		}
	}
	return out, nil
}

func (f *fakeGuest) IsDir(path string) bool { return f.dirs[path] }

func (f *fakeGuest) Exists(path string) bool {
	_, ok := f.files[path]
	return ok || f.dirs[path]
}

func (f *fakeGuest) CopyOwnerAndMode(from, to string) error {
	f.owners = append(f.owners, [2]string{from, to})
	return nil
}

func (f *fakeGuest) Disks() ([]blockDevice, error) {
	if f.slept < f.disksAfter {
		return nil, nil
	}
	out := make([]blockDevice, 0, len(f.disks))
	for _, d := range f.disks {
		out = append(out, d.blockDevice)
	}
	return out, nil
}

func (f *fakeGuest) OpenDisk(name string) (disk, error) {
	for _, d := range f.disks {
		if d.Name == name {
			return memDisk{bytes.NewReader(d.data)}, nil
		}
	}
	return nil, fs.ErrNotExist
}

func (f *fakeGuest) diskIndex(name string) uint32 {
	for i, d := range f.disks {
		if d.Name == name {
			return uint32(i)
		}
	}
	return 99
}

func (f *fakeGuest) PartitionDevice(name string, number int) (devmapper.Device, error) {
	return devmapper.Device{Major: 252, Minor: f.diskIndex(name)*16 + uint32(number)}, nil
}

func (f *fakeGuest) DiskDevice(name string) (devmapper.Device, error) {
	return devmapper.Device{Major: 252, Minor: f.diskIndex(name) * 16}, nil
}

func (f *fakeGuest) CreateMapping(name string, target devmapper.Target, opts devmapper.Options) (devmapper.Device, error) {
	if err := f.failMount["map:"+name]; err != nil {
		return devmapper.Device{}, err
	}
	f.mappings = append(f.mappings, mapping{name, target, opts})
	return devmapper.Device{Major: 253, Minor: uint32(len(f.mappings) - 1)}, nil
}

func (f *fakeGuest) RandomKey() ([]byte, error) { return bytes.Repeat([]byte{0x42}, 64), nil }

func (f *fakeGuest) RunIn(root string, argv []string) error {
	if err := f.failRun[argv[0]]; err != nil {
		return err
	}
	f.ran = append(f.ran, append([]string{root}, argv...))
	return nil
}

func (f *fakeGuest) ReadAhead(path string) { f.warmed = append(f.warmed, path) }

func (f *fakeGuest) Sleep(d time.Duration) { f.slept += d }

func (f *fakeGuest) Log(format string, args ...any) {
	f.logs = append(f.logs, fmt.Sprintf(format, args...))
}

func (f *fakeGuest) SwitchRoot(dir string) error {
	if err := f.failMount["switch"]; err != nil {
		return err
	}
	f.root = dir
	return nil
}

func (f *fakeGuest) SetHostname(name string) error { f.hostname = name; return nil }
func (f *fakeGuest) LoopbackUp() error             { f.loopback = true; return nil }

func (f *fakeGuest) WriteSysctl(key, value string) error {
	if err := f.sysctlErr[key]; err != nil {
		return err
	}
	f.sysctls[key] = value
	return nil
}

func (f *fakeGuest) NoNewPrivileges() error { f.noNewPriv = true; return nil }

func (f *fakeGuest) SetOpenFiles(limit uint64) error { f.openFiles = limit; return nil }

func (f *fakeGuest) Start(argv, _ []string, cgroup string, oom int) (int, error) {
	if err := f.startErr[argv[0]]; err != nil {
		return 0, err
	}
	f.starts = append(f.starts, started{argv, cgroup, oom})
	f.nextPID++
	return f.nextPID, nil
}

func (f *fakeGuest) Wait() (int, int, error) {
	if len(f.exits) == 0 {
		return 0, 0, errors.New("no child left")
	}
	next := f.exits[0]
	f.exits = f.exits[1:]
	return next[0], next[1], nil
}

func (f *fakeGuest) mounted(target string) *mountCall {
	for i := range f.mounts {
		if f.mounts[i].target == target {
			return &f.mounts[i]
		}
	}
	return nil
}

// gptDisk builds a disk with a valid partition table of these partitions.
func gptDisk(sectors int, parts []partition) []byte {
	disk := make([]byte, sectors*lbaSize)
	le := binary.LittleEndian
	entries := make([]byte, 128*128)
	for _, p := range parts {
		entry := entries[(p.Number-1)*128:]
		copy(entry, p.Type[:])
		entry[16] = byte(p.Number)
		le.PutUint64(entry[32:], p.First)
		le.PutUint64(entry[40:], p.Last)
	}
	copy(disk[2*lbaSize:], entries)
	header := disk[lbaSize : lbaSize+92]
	copy(header, "EFI PART")
	le.PutUint32(header[8:], 0x00010000)
	le.PutUint32(header[12:], 92)
	le.PutUint64(header[24:], 1)
	le.PutUint64(header[72:], 2)
	le.PutUint32(header[80:], 128)
	le.PutUint32(header[84:], 128)
	le.PutUint32(header[88:], crc32.ChecksumIEEE(entries))
	le.PutUint32(header[16:], crc32.ChecksumIEEE(header))
	return disk
}

// veritySuperblock is a superblock for a root of dataBlocks 4 KiB blocks.
func veritySuperblock(dataBlocks uint64, algorithm string) []byte {
	b := make([]byte, 512)
	copy(b, "verity\x00\x00")
	binary.LittleEndian.PutUint32(b[8:], 1)
	binary.LittleEndian.PutUint32(b[12:], 1)
	copy(b[32:], algorithm)
	binary.LittleEndian.PutUint32(b[64:], 4096)
	binary.LittleEndian.PutUint32(b[68:], 4096)
	binary.LittleEndian.PutUint64(b[72:], dataBlocks)
	binary.LittleEndian.PutUint16(b[80:], 32)
	copy(b[88:], bytes.Repeat([]byte{0xcd}, 32))
	return b
}

// bootDiskImage is a boot disk: an ESP, a root partition of 64 blocks and
// its verity tree.
func bootDiskImage(algorithm string) []byte {
	esp := mustGUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
	parts := []partition{
		{Number: 1, Type: esp, First: 40, Last: 99},
		{Number: 2, Type: rootPartitionType, First: 100, Last: 100 + 64*8 - 1},
		{Number: 3, Type: verityPartitionType, First: 700, Last: 799},
	}
	disk := gptDisk(1000, parts)
	copy(disk[700*lbaSize:], veritySuperblock(64, algorithm))
	return disk
}

// isoImage is a volume with this ISO 9660 label.
func isoImage(label string) []byte {
	disk := make([]byte, isoDescriptorOffset+2048)
	d := disk[isoDescriptorOffset:]
	d[0] = 1
	copy(d[1:], "CD001")
	copy(d[40:72], strings.Repeat(" ", 32))
	copy(d[40:], label)
	return disk
}

const testRootHash = "5f56b019a71bf0277c647b2e4aec8bb349b2a8cee40f1f9f28071991545450d7"

// tdxGuest is a guest as a launcher builds one on TDX: a boot disk, a
// scratch disk, a launch volume, and the image's files.
func tdxGuest() *fakeGuest {
	f := newFakeGuest()
	f.files["/proc/cmdline"] = []byte("roothash=" + testRootHash + " page_alloc.shuffle=1 no-kvmclock\n")
	f.disks = []fakeDisk{
		{blockDevice{Name: "vda", Sectors: 1000}, bootDiskImage("sha256")},
		{blockDevice{Name: "vdb", Serial: scratchSerial, Sectors: 8388608}, make([]byte, 4096)},
		{blockDevice{Name: "vdc", Sectors: 104}, isoImage(launchLabel)},
	}
	f.files[newRoot+stateListDir+"/10-base.conf"] = []byte("# writable state\nhome\nvar\n\nroot\n")
	f.files[newRoot+stateListDir+"/50-session.conf"] = []byte("var\netc/c8s-session/state\r\n")
	for _, dir := range []string{"home", "var", "root", "etc/c8s-session/state"} {
		f.dirs[newRoot+"/"+dir] = true
	}
	f.files[newRoot+bootConfigPath] = []byte(testBootConfig)
	f.files["/opkey/"+launchKeyFile] = []byte("-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n")
	f.files[rtmr3Path] = nil
	return f
}
