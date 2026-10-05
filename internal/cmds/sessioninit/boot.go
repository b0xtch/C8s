// Package sessioninit is the init of a session guest: process 1 from the
// initramfs to the guest's last moment. It opens the verity root the kernel
// command line names, makes the guest's encrypted state volume under a key
// of this boot, binds the launch key into the platform's evidence, and then
// runs what the root says a guest runs: the launch files' loader, the packet
// filter, and the agent. When the agent exits, the guest ends.
//
// It stands where an initrd script, systemd and their tools stood. A session
// guest runs one program for one session, and everything else that ran in it
// was something its host could try to reach.
package sessioninit

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/devmapper"
)

const (
	// newRoot is where the root file system is mounted before the init
	// moves into it.
	newRoot = "/sysroot"
	// stateDir holds the state volume while the overlays are made.
	stateDir = "/state"
	// scratchSerial is the serial of the disk the state volume is made on.
	// The launcher sets it, and a guest launched without such a disk keeps
	// its state in memory.
	scratchSerial = "confai-scratch"
	// launchLabel is the volume identifier of the launcher's ISO 9660 volume.
	launchLabel = "opkeydata"
	// launchKeyFile is the launch public key on that volume.
	launchKeyFile = "pubkey"
	maxLaunchKey  = 64 * 1024
	// launchKeyDir is where the key is staged for the agent, read-only.
	launchKeyDir  = "/run/confai"
	launchKeyName = "operator-pubkey"
	// stateListDir holds the image's lists of writable directories.
	stateListDir = "/usr/lib/confai/state.d"
	// bootConfigPath is the image's description of what a guest runs.
	bootConfigPath = "/etc/c8s-session/init.json"

	rtmr3Path = "/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384"
	sevGuest  = "/dev/sev-guest"
	tsmReport = "/sys/kernel/config/tsm/report"

	// diskWait is how long the init waits for the boot disk to appear.
	diskWait = 10 * time.Second
)

// disk is a block device the init reads from directly.
type disk interface {
	io.ReaderAt
	io.Closer
}

// blockDevice is one whole disk, as sysfs lists it.
type blockDevice struct {
	// Name is the kernel's name: vda.
	Name string
	// Serial is what the device reports as its serial, if anything.
	Serial string
	// Sectors is the disk's size in 512-byte sectors.
	Sectors uint64
}

// platform is everything the init asks of the kernel. The guest's is the
// real one; tests run the same steps against a recording one.
type platform interface {
	Mount(source, target, fstype string, flags uintptr, data string) error
	Unmount(target string) error
	MkdirAll(path string, mode os.FileMode) error
	ReadFile(path string, limit int64) ([]byte, error)
	WriteFile(path string, data []byte, mode os.FileMode) error
	// ReadDirFiles returns the regular files of a directory by name. A
	// directory that does not exist has none.
	ReadDirFiles(dir string, limit int64) (map[string][]byte, error)
	IsDir(path string) bool
	// CopyOwnerAndMode gives to the owner and mode of from.
	CopyOwnerAndMode(from, to string) error
	Disks() ([]blockDevice, error)
	OpenDisk(name string) (disk, error)
	// PartitionDevice returns the numbers of a disk's partition.
	PartitionDevice(diskName string, number int) (devmapper.Device, error)
	DiskDevice(diskName string) (devmapper.Device, error)
	CreateMapping(name string, target devmapper.Target, opts devmapper.Options) (devmapper.Device, error)
	RandomKey() ([]byte, error)
	// RunIn runs a program of the new root to its end, inside that root.
	RunIn(root string, argv []string) error
	// ReadAhead starts reading a file into memory and returns at once.
	ReadAhead(path string)
	Exists(path string) bool
	Sleep(d time.Duration)
	Log(format string, args ...any)
}

// prepareRoot does everything up to the move into the root: the verity root,
// the state volume and its overlays, and the launch key's binding. Any error
// is fatal to the guest: nothing here has a way to go on without it.
func prepareRoot(p platform) error {
	for _, m := range kernelMounts {
		if err := mountAt(p, m.source, m.target, m.fstype, m.flags, m.data); err != nil {
			return err
		}
	}
	cmdline, err := p.ReadFile("/proc/cmdline", 4096)
	if err != nil {
		return err
	}
	rootHash, err := rootHashFromCmdline(string(cmdline))
	if err != nil {
		return err
	}
	if err := openRoot(p, rootHash); err != nil {
		return fmt.Errorf("root file system: %w", err)
	}
	// What the guest runs next is read off the root while the state volume
	// is made: by the time the init starts a program, its pages are here.
	warm(p)
	// The root gets the same three: its tools run before the move, and
	// everything after it runs there.
	for _, m := range kernelMounts {
		if err := p.Mount(m.source, newRoot+m.target, m.fstype, m.flags, m.data); err != nil {
			return fmt.Errorf("mount %s: %w", newRoot+m.target, err)
		}
	}
	if err := openState(p); err != nil {
		return fmt.Errorf("state volume: %w", err)
	}
	if err := mountOverlays(p); err != nil {
		return fmt.Errorf("writable state: %w", err)
	}
	if err := p.Mount("tmpfs", newRoot+"/run", "tmpfs", msNoSuid|msNoDev|msStrictAtime, "mode=0755,size=20%,nr_inodes=800k"); err != nil {
		return fmt.Errorf("mount /run: %w", err)
	}
	if err := bindLaunchKey(p); err != nil {
		return fmt.Errorf("launch key: %w", err)
	}
	return nil
}

// kernelMounts are the kernel's own file systems, which the init needs
// before it can find a disk.
var kernelMounts = []struct {
	source, target, fstype string
	flags                  uintptr
	data                   string
}{
	{"proc", "/proc", "proc", msNoSuid | msNoDev | msNoExec, ""},
	{"sysfs", "/sys", "sysfs", msNoSuid | msNoDev | msNoExec, ""},
	{"devtmpfs", "/dev", "devtmpfs", msNoSuid, "mode=0755"},
}

// warm asks the kernel to read the programs the image's boot configuration
// names. It is a hint and nothing waits for it: a configuration that does
// not parse is refused later, by the code that acts on it.
func warm(p platform) {
	data, err := p.ReadFile(newRoot+bootConfigPath, maxBootConfig)
	if err != nil {
		return
	}
	cfg, err := parseBootConfig(data)
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, argv := range append(append([][]string{}, cfg.Steps...), cfg.Service) {
		if !seen[argv[0]] {
			seen[argv[0]] = true
			p.ReadAhead(newRoot + argv[0])
		}
	}
}

func mountAt(p platform, source, target, fstype string, flags uintptr, data string) error {
	if err := p.MkdirAll(target, 0o755); err != nil {
		return err
	}
	if err := p.Mount(source, target, fstype, flags, data); err != nil {
		return fmt.Errorf("mount %s: %w", target, err)
	}
	return nil
}

// rootFilesystems are the read-only file systems an image's root may be.
var rootFilesystems = []string{"erofs", "squashfs", "ext4"}

// openRoot finds the boot disk, opens its root partition through dm-verity
// under rootHash, and mounts it read-only.
func openRoot(p platform, rootHash []byte) error {
	var (
		name         string
		root, verity partition
	)
	// The disk's driver may still be probing when the init starts.
	for waited := time.Duration(0); ; waited += 10 * time.Millisecond {
		var err error
		name, root, verity, err = bootDisk(p)
		if err == nil {
			break
		}
		if waited >= diskWait {
			return err
		}
		p.Sleep(10 * time.Millisecond)
	}
	dataDev, err := p.PartitionDevice(name, root.Number)
	if err != nil {
		return err
	}
	hashDev, err := p.PartitionDevice(name, verity.Number)
	if err != nil {
		return err
	}
	d, err := p.OpenDisk(name)
	if err != nil {
		return err
	}
	header := make([]byte, 512)
	_, err = d.ReadAt(header, int64(verity.First)*lbaSize)
	_ = d.Close()
	if err != nil {
		return fmt.Errorf("verity superblock: %w", err)
	}
	sb, err := devmapper.ParseVeritySuperblock(header)
	if err != nil {
		return err
	}
	// The tree's digest is the root hash's: a tree of another length is not
	// this root's.
	if want := map[string]int{"sha256": 32, "sha384": 48, "sha512": 64}[sb.Algorithm]; want != len(rootHash) {
		return fmt.Errorf("the verity tree uses %s and the command line's root hash has %d bytes", sb.Algorithm, len(rootHash))
	}
	if have := (root.Last - root.First + 1) * lbaSize; sb.DataBlocks*uint64(sb.DataBlockSize) > have {
		return fmt.Errorf("the verity tree covers %d blocks of %d bytes and the root partition holds %d bytes", sb.DataBlocks, sb.DataBlockSize, have)
	}
	table, err := devmapper.VerityTable(sb, dataDev, hashDev, rootHash)
	if err != nil {
		return err
	}
	dev, err := p.CreateMapping("root", table, devmapper.Options{ReadOnly: true})
	if err != nil {
		return err
	}
	if err := p.MkdirAll(newRoot, 0o755); err != nil {
		return err
	}
	var mountErr error
	for _, fstype := range rootFilesystems {
		if mountErr = p.Mount(devmapper.NodePath(dev), newRoot, fstype, msReadOnly, ""); mountErr == nil {
			p.Log("root: %s on %s, verified against the command line's root hash", fstype, name)
			return nil
		}
	}
	return fmt.Errorf("mount: %w", mountErr)
}

// bootDisk returns the first disk that carries a root partition and its
// verity tree.
func bootDisk(p platform) (string, partition, partition, error) {
	disks, err := p.Disks()
	if err != nil {
		return "", partition{}, partition{}, err
	}
	for _, b := range disks {
		d, err := p.OpenDisk(b.Name)
		if err != nil {
			continue
		}
		parts, err := readGPT(d)
		_ = d.Close()
		if err != nil {
			continue
		}
		if root, verity, ok := rootPartitions(parts); ok {
			return b.Name, root, verity, nil
		}
	}
	return "", partition{}, partition{}, errors.New("no disk carries a root partition and its verity tree")
}

// openState mounts the guest's writable state at stateDir: an ext4 file
// system on the scratch disk, encrypted under a key made here and kept
// nowhere else, or memory when the guest has no such disk. The key is new
// every boot, so what an earlier guest wrote to the disk is noise to this one.
func openState(p platform) error {
	if err := p.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	disks, err := p.Disks()
	if err != nil {
		return err
	}
	for _, b := range disks {
		if b.Serial != scratchSerial {
			continue
		}
		if b.Sectors == 0 {
			return fmt.Errorf("%s is empty", b.Name)
		}
		dev, err := p.DiskDevice(b.Name)
		if err != nil {
			return err
		}
		key, err := p.RandomKey()
		if err != nil {
			return err
		}
		table, err := devmapper.CryptTable(dev, b.Sectors, key, devmapper.CryptOptions{})
		for i := range key {
			key[i] = 0
		}
		if err != nil {
			return err
		}
		mapped, err := p.CreateMapping("scratch", table, devmapper.Options{Secure: true})
		// The table's parameter string held the key in hex.
		table.Params = ""
		if err != nil {
			return err
		}
		node := devmapper.NodePath(mapped)
		// No journal: this file system lives for one boot under a key that
		// dies with it, so there is never anything to recover, and a journal
		// is the larger part of making and mounting it. The inode tables are
		// written as they are first used: every block reads as noise until
		// it is written under this key, so zeroing them first says nothing.
		if err := p.RunIn(newRoot, []string{"/usr/sbin/mke2fs", "-q", "-t", "ext4", "-O", "^has_journal,^resize_inode", "-E", "lazy_itable_init=1,nodiscard", node}); err != nil {
			return fmt.Errorf("make the file system: %w", err)
		}
		if err := p.Mount(node, stateDir, "ext4", msNoSuid|msNoDev, ""); err != nil {
			return fmt.Errorf("mount: %w", err)
		}
		p.Log("state: encrypted under a key of this boot, on %s", b.Name)
		return nil
	}
	p.Log("state: no scratch disk, kept in memory")
	return p.Mount("tmpfs", stateDir, "tmpfs", msNoSuid|msNoDev, "size=2G")
}

// mountOverlays gives each directory the image lists a writable layer on the
// state volume. The rest of the root stays read-only.
func mountOverlays(p platform) error {
	files, err := p.ReadDirFiles(newRoot+stateListDir, 64*1024)
	if err != nil {
		return err
	}
	lists := map[string][]byte{}
	for name, data := range files {
		if strings.HasSuffix(name, ".conf") {
			lists[name] = data
		}
	}
	dirs, err := stateDirs(lists)
	if err != nil {
		return err
	}
	for i, dir := range dirs {
		lower := newRoot + "/" + dir
		if !p.IsDir(lower) {
			return fmt.Errorf("%s is listed for writable state and is no directory of the image", dir)
		}
		upper := fmt.Sprintf("%s/%d/upper", stateDir, i+1)
		work := fmt.Sprintf("%s/%d/work", stateDir, i+1)
		for _, d := range []string{upper, work} {
			if err := p.MkdirAll(d, 0o755); err != nil {
				return err
			}
		}
		// The merged directory takes the upper one's owner and mode.
		if err := p.CopyOwnerAndMode(lower, upper); err != nil {
			return err
		}
		if err := p.Mount("overlay", lower, "overlay", 0, "lowerdir="+lower+",upperdir="+upper+",workdir="+work); err != nil {
			return fmt.Errorf("overlay on %s: %w", dir, err)
		}
	}
	p.Log("state: writable %s", strings.Join(dirs, " "))
	return nil
}

// bindLaunchKey ties the launch key the host handed in to this guest's
// evidence, before anything of the root runs. On TDX its SHA-384 digest is
// extended into RTMR[3]. On SEV-SNP the launcher committed its SHA-256
// digest as HOST_DATA when it launched the guest, and the guest's own report
// must say so. The key is staged for the agent exactly as it was bound.
//
// A guest launched with no launch volume boots unbound. A guest that has the
// volume and cannot bind the key does not boot: its host would otherwise
// choose whether the key counts.
func bindLaunchKey(p platform) error {
	disks, err := p.Disks()
	if err != nil {
		return err
	}
	var volume string
	for _, b := range disks {
		d, err := p.OpenDisk(b.Name)
		if err != nil {
			continue
		}
		label := isoVolumeLabel(d)
		_ = d.Close()
		if label == launchLabel {
			volume = b.Name
			break
		}
	}
	if volume == "" {
		p.Log("launch key: no launch volume, the guest boots unbound")
		return nil
	}
	const mountPoint = "/opkey"
	// No symlinks: the volume is its host's, and a link named like the key
	// would have this process read a file of the guest's in its place.
	if err := mountAt(p, "/dev/"+volume, mountPoint, "iso9660", msReadOnly|msNoSuid|msNoDev|msNoExec|msNoSymFollow, ""); err != nil {
		return err
	}
	key, err := p.ReadFile(mountPoint+"/"+launchKeyFile, maxLaunchKey)
	_ = p.Unmount(mountPoint)
	if err != nil {
		return err
	}
	if len(key) == 0 {
		return errors.New("the launch volume's key is empty")
	}
	staged := newRoot + launchKeyDir
	if err := p.MkdirAll(staged, 0o755); err != nil {
		return err
	}
	if err := p.WriteFile(staged+"/"+launchKeyName, key, 0o644); err != nil {
		return err
	}
	// Read-only from here on: the agent checks the binding again, and nothing
	// in the guest has a reason to replace the file.
	if err := p.Mount(staged, staged, "", msBind, ""); err != nil {
		return fmt.Errorf("bind %s: %w", launchKeyDir, err)
	}
	if err := p.Mount("", staged, "", msBind|msRemount|msReadOnly, ""); err != nil {
		return fmt.Errorf("make %s read-only: %w", launchKeyDir, err)
	}
	if bound, err := bindSimulated(p, key); bound || err != nil {
		return err
	}
	switch {
	case p.Exists(rtmr3Path):
		digest := sha512.Sum384(key)
		// The node takes one write of exactly a digest.
		if err := p.WriteFile(rtmr3Path, digest[:], 0); err != nil {
			return fmt.Errorf("extend RTMR[3]: %w", err)
		}
		p.Log("launch key: its digest is extended into RTMR[3]")
	case p.Exists(sevGuest):
		want := sha256.Sum256(key)
		hostData, err := snpHostData(p)
		if err != nil {
			return err
		}
		if !bytes.Equal(hostData, want[:]) {
			return fmt.Errorf("the guest's report carries HOST_DATA %x and the staged key's digest is %x: the launcher bound another key, or none", hostData, want)
		}
		p.Log("launch key: its digest is this guest's HOST_DATA")
	default:
		return errors.New("this guest has neither a writable RTMR[3] nor an SEV-SNP guest device to bind the key with")
	}
	return nil
}

// snpHostData asks the platform for this guest's attestation report and
// returns its HOST_DATA field: 32 bytes at offset 192 in every report version.
func snpHostData(p platform) ([]byte, error) {
	// Before the move into the root, the kernel's configfs is not mounted.
	if err := mountAt(p, "configfs", "/sys/kernel/config", "configfs", 0, ""); err != nil {
		return nil, err
	}
	entry := tsmReport + "/launch-key"
	if err := p.MkdirAll(entry, 0o700); err != nil {
		return nil, fmt.Errorf("ask for a report: %w", err)
	}
	// HOST_DATA is fixed at launch, so the report's freshness says nothing here.
	if err := p.WriteFile(entry+"/inblob", make([]byte, 64), 0); err != nil {
		return nil, fmt.Errorf("ask for a report: %w", err)
	}
	report, err := p.ReadFile(entry+"/outblob", 16*1024)
	if err != nil {
		return nil, fmt.Errorf("read the report: %w", err)
	}
	if len(report) < 224 {
		return nil, fmt.Errorf("a report of %d bytes", len(report))
	}
	return report[192:224], nil
}
