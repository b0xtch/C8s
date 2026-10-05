//go:build linux

package sessionagent

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/containerd/v2/contrib/seccomp"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sandboxinit"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/imagestore"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const (
	// sandboxID names the one container of a guest, to crun and in the cgroup tree.
	sandboxID    = "sandbox"
	cgroupRoot   = "/sys/fs/cgroup"
	startTimeout = 30 * time.Second
	stopTimeout  = 10 * time.Second
	// awaitRunningEvery is how often a starting sandbox is looked at. A
	// look reads three small files of the kernel's.
	awaitRunningEvery = 200 * time.Microsecond
	// crunFailed is crun's own exit status: the command it was given never ran.
	crunFailed = 255
)

// ImageRunnerConfig places the sandbox container in the guest. Every value
// comes from the measured image's units.
type ImageRunnerConfig struct {
	// StateDir holds the pulled blobs and the unpacked root filesystem. It is
	// on the encrypted scratch volume: the image's files are tenant data.
	StateDir string
	// RunDir holds the runtime bundle, crun's state and per-command files.
	RunDir string
	// CredentialDir is bound read-only into the container at the same path.
	CredentialDir string
	// CgroupParent is the agent's delegated cgroup v2 directory. The container
	// gets a child of it, and every command a child of that.
	CgroupParent string
	// PidsLimit caps the tasks of the sandbox and its commands together.
	PidsLimit int64
	// Crun is the runtime binary.
	Crun string
	// SandboxInit is the program a container runs until its session's bind
	// says what the sandbox's process is: internal/cmds/sandboxinit. The
	// container is made around it ahead of the bind, and it then becomes
	// that process.
	SandboxInit string
	Pull        imagestore.PullLimits
	Unpack      imagestore.UnpackLimits
	// Images is the host's image store, or nil. What it holds of an image is
	// read from it, checked like a registry's answer, and the registry is
	// asked for the rest.
	Images *imagestore.Store
	// PlainHTTP marks the registries reached without TLS.
	PlainHTTP func(host string) bool
	// ColdCommands has every command started by the runtime when it is
	// asked for, and none ahead of its command: see warmCommand.
	ColdCommands bool
	Logger       *slog.Logger
}

// ImageRunner runs the launch document's OCI image as one crun container in a
// user namespace, and commands inside it. A document with no sandbox goes to
// the bare runner instead.
type ImageRunner struct {
	cfg  ImageRunnerConfig
	bare Runner

	mu       sync.Mutex
	prepared *preparedSandbox
	started  bool
	exited   chan struct{}
	exitErr  error
	// made is the container made over the first image unpacked ahead, before
	// any bind named an image. A Prepare takes it, for its sandbox or to end
	// it.
	made *madeSandbox
	// net is the sandbox's namespaces and its proxy, made once, from when
	// the runner is. A caller waits for them.
	net func() (*sandboxNet, error)
	// ahead are the images being unpacked before any sandbox is named, by
	// digest. stopAhead ends the unpacking and aheadDone is closed when it
	// has ended. All three are nil when nothing is unpacked ahead.
	ahead     map[string]*prestagedImage
	stopAhead context.CancelFunc
	aheadDone chan struct{}
}

// prestagedImage is an image unpacked before any sandbox was named.
type prestagedImage struct {
	ref string
	// done is closed when the unpack has ended, one way or the other.
	done   chan struct{}
	err    error
	config ocispec.ImageConfig
	rootfs string
}

type preparedSandbox struct {
	process *specs.Process
	rootfs  string
	// egress is the document's allowlist, nil when it sets none.
	egress *session.Egress
	// made is the sandbox's container, whose init waits to become process.
	made *madeSandbox
}

// madeSandbox is a container whose process is not the image's yet. Its
// namespaces, mounts and limits are in place, and its first process is the
// sandbox init, which waits for the agent to say what to become. Nothing of
// the image has run.
type madeSandbox struct {
	// digest names the image whose tree is the container's root.
	digest string
	rootfs string
	// control is the agent's end of the socket pair the init reads.
	control *os.File
	pidPath string
	// cgroupsPath is the container's cgroup, as the kernel names it.
	cgroupsPath string
	logPath     string
	// exited is closed when the container's runtime has ended, and exitErr
	// then says how.
	exited  chan struct{}
	exitErr error
	// warm holds the one process that was started ahead for whichever
	// command comes next: see warmCommand. A command that takes it says so
	// on warmTaken, and the next is started. stopWarm ends the starting of
	// them, and warmDone is closed when it has ended. All four are nil for a
	// container whose commands the runtime starts as they come.
	warm      chan *warmCommand
	warmTaken chan struct{}
	stopWarm  context.CancelFunc
	warmDone  chan struct{}
	// warmUsed counts the commands that ran as a process started ahead.
	warmUsed atomic.Int64
}

// NewImageRunner returns the runner of a guest image that carries crun.
func NewImageRunner(cfg ImageRunnerConfig, bare Runner) (*ImageRunner, error) {
	if bare == nil {
		return nil, errors.New("image runner needs a bare runner for guests without a sandbox")
	}
	if cfg.StateDir == "" || cfg.RunDir == "" || cfg.CredentialDir == "" || cfg.Crun == "" || cfg.SandboxInit == "" {
		return nil, errors.New("image runner needs a state directory, a run directory, a credential directory, crun and the sandbox's init")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	r := &ImageRunner{cfg: cfg, bare: bare, exited: make(chan struct{})}
	r.net = sync.OnceValues(newSandboxNet)
	// Ahead of any sandbox: a bind then finds them made.
	go func() {
		if _, err := r.net(); err != nil {
			cfg.Logger.Error("make the sandbox's namespaces", "error", err)
		}
	}()
	return r, nil
}

func (r *ImageRunner) sandbox() (*preparedSandbox, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.prepared, r.started
}

// CredentialOwner is the image's user as the guest sees it: its id inside the
// container, shifted into the range the container's user namespace maps.
func (r *ImageRunner) CredentialOwner() (int, int) {
	w, _ := r.sandbox()
	if w == nil {
		return r.bare.CredentialOwner()
	}
	return imagestore.IDBase + int(w.process.User.UID), imagestore.IDBase + int(w.process.User.GID)
}

// stateDir makes the directory the sandbox's files live under. The
// container's root reaches its root filesystem through it.
func (r *ImageRunner) stateDir() error {
	// MkdirAll leaves the mode of one that already exists.
	if err := os.MkdirAll(r.cfg.StateDir, 0o711); err != nil {
		return err
	}
	return os.Chmod(r.cfg.StateDir, 0o711)
}

func (r *ImageRunner) aheadDir() string { return filepath.Join(r.cfg.StateDir, "prestaged") }

// Prestage unpacks images from the host's image store, one after another in
// the background, so that a Prepare which names one of them finds its tree
// ready. It asks no registry: a guest that belongs to nobody yet has no
// business on a network. Every blob is checked against its digest before it
// is read as anything, starting from the digest in the reference.
func (r *ImageRunner) Prestage(ctx context.Context, images []string) <-chan struct{} {
	r.mu.Lock()
	if r.ahead != nil || r.prepared != nil {
		r.mu.Unlock()
		return closed
	}
	ctx, r.stopAhead = context.WithCancel(ctx)
	r.ahead, r.aheadDone = map[string]*prestagedImage{}, make(chan struct{})
	var order []*prestagedImage
	for _, ref := range images {
		digest, err := (&session.Sandbox{Image: ref}).Digest()
		if err != nil || r.ahead[digest] != nil {
			continue
		}
		entry := &prestagedImage{ref: ref, done: make(chan struct{}), rootfs: filepath.Join(r.aheadDir(), strings.TrimPrefix(digest, "sha256:"), "rootfs")}
		r.ahead[digest] = entry
		order = append(order, entry)
	}
	done := r.aheadDone
	r.mu.Unlock()
	go func() {
		defer close(done)
		for i, entry := range order {
			began := time.Now()
			entry.err = r.unpackAhead(ctx, entry)
			if entry.err == nil && i == 0 {
				// The first image listed is the one a pool's sessions are
				// expected to name: its container is made now, so that a
				// bind which names it only has a process to start.
				r.makeAhead(ctx, entry)
			}
			close(entry.done)
			if entry.err != nil {
				r.cfg.Logger.Warn("image not unpacked ahead", "image", entry.ref, "error", entry.err)
				continue
			}
			r.cfg.Logger.Info("image unpacked ahead", "image", entry.ref, "seconds", time.Since(began).Seconds())
		}
	}()
	return done
}

// makeAhead makes the sandbox's container over an image unpacked ahead. A
// failure leaves the image's tree where the unpack put it, for a Prepare to
// take the usual way.
func (r *ImageRunner) makeAhead(ctx context.Context, entry *prestagedImage) {
	if ctx.Err() != nil {
		return
	}
	began := time.Now()
	digest, err := (&session.Sandbox{Image: entry.ref}).Digest()
	if err != nil {
		return
	}
	process, err := sandboxProcess(entry.config, &session.Sandbox{Image: entry.ref}, r.cfg.CredentialDir)
	if err != nil {
		// The image names a user the sandbox cannot run as.
		r.cfg.Logger.Info("no container made ahead", "image", entry.ref, "reason", err)
		return
	}
	rootfs := filepath.Join(r.cfg.StateDir, "rootfs")
	if err := os.Rename(entry.rootfs, rootfs); err != nil {
		r.cfg.Logger.Warn("no container made ahead", "image", entry.ref, "error", err)
		return
	}
	made, err := r.mountAndMake(ctx, digest, rootfs, process)
	if err != nil {
		r.cfg.Logger.Warn("no container made ahead", "image", entry.ref, "error", err)
		// Back where a Prepare looks for it.
		if err := os.Rename(rootfs, entry.rootfs); err != nil {
			entry.err = fmt.Errorf("the image's tree was lost to a container that could not be made: %w", err)
		}
		return
	}
	// The tree is the container's now: what held it is empty.
	_ = os.Remove(filepath.Dir(entry.rootfs))
	r.mu.Lock()
	r.made = made
	r.mu.Unlock()
	r.cfg.Logger.Info("container made ahead", "image", entry.ref, "seconds", time.Since(began).Seconds())
}

// unpackAhead reads one image from the host's store and unpacks it beside
// where a sandbox's tree goes. A failure leaves nothing.
func (r *ImageRunner) unpackAhead(ctx context.Context, entry *prestagedImage) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Dir(entry.rootfs)
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	if err := r.stateDir(); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	store := filepath.Join(dir, "store")
	defer os.RemoveAll(store)
	puller := &imagestore.Puller{StoreDir: store, Limits: r.cfg.Pull, Images: r.cfg.Images, ImagesOnly: true}
	img, err := puller.Pull(ctx, entry.ref)
	if err != nil {
		return err
	}
	unpacker, err := imagestore.NewUnpacker(entry.rootfs, r.cfg.Unpack)
	if err != nil {
		return err
	}
	if err := img.Unpack(ctx, unpacker); err != nil {
		return err
	}
	if _, err := unpacker.Finish(); err != nil {
		return err
	}
	entry.config = img.Config.Config
	return nil
}

// takeAhead ends the unpacking ahead and returns the tree of w's image, if
// it was unpacked. An unpack of that image still under way is waited for:
// it is further along than a pull that starts now.
func (r *ImageRunner) takeAhead(ctx context.Context, w *session.Sandbox) *prestagedImage {
	r.mu.Lock()
	ahead, stop, done := r.ahead, r.stopAhead, r.aheadDone
	r.ahead, r.stopAhead, r.aheadDone = nil, nil, nil
	r.mu.Unlock()
	if ahead == nil {
		return nil
	}
	digest, _ := w.Digest()
	entry := ahead[digest]
	if entry != nil {
		select {
		case <-entry.done:
		case <-ctx.Done():
		}
	}
	stop()
	// Past this nothing writes under the directory any more.
	<-done
	if entry == nil || entry.err != nil || ctx.Err() != nil {
		return nil
	}
	return entry
}

// Prepare readies the sandbox the bind names: its image in place, and its
// container made, with the sandbox init as its process. A bind that names
// the image whose container was made ahead finds all of that done. For any
// other, the image is taken from what was unpacked ahead, or pulled and
// verified against the digest the bind pins, and its container is made now.
// Nothing of the image runs.
func (r *ImageRunner) Prepare(ctx context.Context, w *session.Sandbox, egress *session.Egress) error {
	if prepared, _ := r.sandbox(); prepared != nil {
		return errors.New("a sandbox is already prepared")
	}
	// Without it a command could not be killed together with what it spawned.
	if r.cfg.CgroupParent == "" {
		return errors.New("this guest has no delegated cgroup to contain a sandbox in")
	}
	if err := r.stateDir(); err != nil {
		return err
	}
	digest, err := w.Digest()
	if err != nil {
		return err
	}
	store, rootfs := filepath.Join(r.cfg.StateDir, "store"), filepath.Join(r.cfg.StateDir, "rootfs")
	began := time.Now()
	// Ends the unpacking ahead, and with it the making of a container: from
	// here r.made does not change under this call.
	ahead := r.takeAhead(ctx, w)
	r.mu.Lock()
	made := r.made
	r.made = nil
	r.mu.Unlock()
	var process *specs.Process
	switch {
	case made != nil && made.digest == digest && ahead != nil:
		process, err = sandboxProcess(ahead.config, w, r.cfg.CredentialDir)
		recordStep(ctx, stepPrestaged, time.Since(began))
	default:
		if made != nil {
			// Made over another image than the bind names.
			r.unmake(made)
			made = nil
		}
		if ahead != nil {
			if process, err = sandboxProcess(ahead.config, w, r.cfg.CredentialDir); err == nil {
				err = os.Rename(ahead.rootfs, rootfs)
			}
			recordStep(ctx, stepPrestaged, time.Since(began))
		} else {
			process, err = r.fetch(ctx, w, store, rootfs)
			// The blobs are spent either way; the scratch volume keeps only a
			// tree that is about to run.
			began = time.Now()
			if rmErr := os.RemoveAll(store); err == nil {
				err = rmErr
			}
			recordStep(ctx, stepClear, time.Since(began))
		}
		if err == nil {
			if made, err = r.mountAndMake(ctx, digest, rootfs, process); err != nil {
				err = fmt.Errorf("make the sandbox's container: %w", err)
			}
		}
		if err != nil {
			_ = os.RemoveAll(rootfs)
		}
	}
	// What was unpacked ahead and is not this sandbox's is nobody's. It goes
	// while the sandbox starts: no sandbox waits for it.
	go func() { _ = os.RemoveAll(r.aheadDir()) }()
	if err != nil {
		if made != nil {
			r.unmake(made)
		}
		return err
	}
	r.mu.Lock()
	r.prepared = &preparedSandbox{process: process, rootfs: rootfs, egress: egress, made: made}
	r.mu.Unlock()
	// The sandbox's end is its container's from here.
	go func() {
		<-made.exited
		r.mu.Lock()
		r.exitErr = made.exitErr
		r.mu.Unlock()
		close(r.exited)
	}()
	return nil
}

// fetch pulls the image into store, unpacks it at rootfs and returns the
// process its config and the launch document describe.
func (r *ImageRunner) fetch(ctx context.Context, w *session.Sandbox, store, rootfs string) (*specs.Process, error) {
	began := time.Now()
	puller := &imagestore.Puller{StoreDir: store, Limits: r.cfg.Pull, PlainHTTP: r.cfg.PlainHTTP, Images: r.cfg.Images}
	img, err := pullWaiting(ctx, puller, w.Image, r.cfg.Logger)
	if err != nil {
		return nil, err
	}
	// Before the unpack: a config the runner cannot honour needs no files.
	process, err := sandboxProcess(img.Config.Config, w, r.cfg.CredentialDir)
	if err != nil {
		return nil, err
	}
	unpacker, err := imagestore.NewUnpacker(rootfs, r.cfg.Unpack)
	if err != nil {
		return nil, err
	}
	unpacking := time.Now()
	if err := img.Unpack(ctx, unpacker); err != nil {
		return nil, fmt.Errorf("unpack image: %w", err)
	}
	owning := time.Now()
	recordStep(ctx, stepUnpack, owning.Sub(unpacking))
	stats, err := unpacker.Finish()
	if err != nil {
		return nil, fmt.Errorf("unpack image: %w", err)
	}
	recordStep(ctx, stepOwn, time.Since(owning))
	r.cfg.Logger.Info("sandbox image unpacked", "digest", img.Digest, "entries", stats.Entries, "bytes", stats.Bytes,
		"skipped_devices", stats.SkippedDevices, "seconds", time.Since(began).Seconds())
	return process, nil
}

// mountRootfs puts the unpacked tree behind a mount of its own that honours no
// device node and no setuid bit. The scratch volume under it honours both. The
// flags are locked for the container: its user namespace does not own the mount.
func mountRootfs(rootfs string) error {
	if err := unix.Mount(rootfs, rootfs, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind root filesystem: %w", err)
	}
	if err := unix.Mount("", rootfs, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_NODEV|unix.MS_NOSUID, ""); err != nil {
		_ = unix.Unmount(rootfs, unix.MNT_DETACH)
		return fmt.Errorf("restrict root filesystem mount: %w", err)
	}
	return nil
}

func (r *ImageRunner) cgroupDir() string { return filepath.Join(r.cfg.CgroupParent, sandboxID) }

// crun is one invocation of the runtime. It gets none of the agent's
// environment: the container's comes from its config alone.
func (r *ImageRunner) crun(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, r.cfg.Crun, append([]string{"--root", filepath.Join(r.cfg.RunDir, "crun"), "--cgroup-manager=cgroupfs"}, args...)...)
	cmd.Env = []string{"PATH=" + defaultSandboxPath}
	return cmd
}

// mountAndMake puts the tree at rootfs behind its mount and makes the
// sandbox's container over it. On failure the tree is unmounted and stays.
func (r *ImageRunner) mountAndMake(ctx context.Context, digest, rootfs string, image *specs.Process) (*madeSandbox, error) {
	if err := mountRootfs(rootfs); err != nil {
		return nil, err
	}
	made, err := r.makeSandbox(ctx, digest, rootfs, image)
	if err != nil {
		_ = unix.Unmount(rootfs, unix.MNT_DETACH)
		return nil, err
	}
	return made, nil
}

// makeSandbox makes the sandbox's container under a crun that stays in the
// foreground: the agent is its parent, so the sandbox's end is the end of a
// child. The container's process is the sandbox init, run as the user and
// under the limits of image's process, from a descriptor the runtime
// preserves: the container holds no file of it. It returns once the init
// runs, and waits there for Start.
func (r *ImageRunner) makeSandbox(ctx context.Context, digest, rootfs string, image *specs.Process) (_ *madeSandbox, err error) {
	cgroupsPath, ok := strings.CutPrefix(r.cgroupDir(), cgroupRoot)
	if !ok || cgroupsPath == "" {
		return nil, fmt.Errorf("delegated cgroup %s is not under %s", r.cfg.CgroupParent, cgroupRoot)
	}
	// Beside the credential directory, where the container's user can reach
	// it: the run directory is the agent's alone.
	mounts := sandboxMounts{CredentialDir: r.cfg.CredentialDir, ResolvConf: filepath.Join(filepath.Dir(r.cfg.CredentialDir), "sandbox-resolv.conf")}
	if err := os.MkdirAll(r.cfg.CredentialDir, 0o700); err != nil {
		return nil, err
	}
	if err := fileutil.WriteAtomic(mounts.ResolvConf, []byte(sandboxResolvConf), 0o644); err != nil {
		return nil, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = sandboxID
	}
	if err := os.MkdirAll(r.cfg.RunDir, 0o700); err != nil {
		return nil, err
	}
	sandboxNet, err := r.net()
	if err != nil {
		return nil, fmt.Errorf("the sandbox's namespaces: %w", err)
	}
	// The image's user, capabilities and limits, and nothing else of the
	// image yet: its command, environment and directory come with Start.
	init := *image
	init.Args = []string{fmt.Sprintf("/proc/self/fd/%d", sandboxinit.ProgramFD)}
	init.Env = []string{"PATH=" + defaultSandboxPath}
	init.Cwd = "/"
	spec := sandboxSpec(&init, rootfs, hostname, cgroupsPath, r.cfg.PidsLimit, mounts, sandboxNet.paths())
	// containerd's default profile, for the capabilities the sandbox holds:
	// what a container gets anywhere else. Capabilities and the user namespace
	// already gate most of what it refuses; this narrows the kernel surface
	// behind them, and crun applies it to every command too.
	spec.Linux.Seccomp = seccomp.DefaultProfile(spec)
	config, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	bundle := filepath.Join(r.cfg.RunDir, "bundle")
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		return nil, err
	}
	if err := fileutil.WriteAtomic(filepath.Join(bundle, "config.json"), config, 0o600); err != nil {
		return nil, err
	}
	// crun's own errors go to this file. The sandbox's output is tenant data
	// and goes nowhere: the container's stdio is /dev/null.
	made := &madeSandbox{
		digest: digest, rootfs: rootfs, cgroupsPath: cgroupsPath, exited: make(chan struct{}),
		logPath: filepath.Join(r.cfg.RunDir, "crun-run.log"), pidPath: filepath.Join(r.cfg.RunDir, "sandbox.pid"),
	}
	if err := os.Remove(made.pidPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	program, err := os.Open(r.cfg.SandboxInit)
	if err != nil {
		return nil, fmt.Errorf("the sandbox's init: %w", err)
	}
	defer program.Close()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("the sandbox init's control socket: %w", err)
	}
	made.control = os.NewFile(uintptr(pair[0]), "sandbox-init-control")
	theirs := os.NewFile(uintptr(pair[1]), "sandbox-init")
	defer theirs.Close()
	// Not under ctx: the sandbox outlives the admission that made it.
	cmd := r.crun(context.Background(), "--log", "file:"+made.logPath, "run", "--bundle", bundle, "--pid-file", made.pidPath,
		"--preserve-fds", "2", sandboxID)
	// Descriptors 3 and 4 of the runtime, and so of the container's process.
	cmd.ExtraFiles = []*os.File{program, theirs}
	if err := cmd.Start(); err != nil {
		_ = made.control.Close()
		return nil, fmt.Errorf("start crun: %w", err)
	}
	go func() {
		err := cmd.Wait()
		var status *exec.ExitError
		if errors.As(err, &status) {
			err = fmt.Errorf("sandbox exited with status %d", exitStatus(status.ProcessState))
		}
		made.exitErr = err
		close(made.exited)
	}()
	if err := r.await(ctx, made, sandboxNet, true, nil, nil); err != nil {
		if reason := readTrimmed(made.logPath); reason != "" {
			err = fmt.Errorf("%w: %s", err, reason)
		}
		r.endContainer(made)
		return nil, err
	}
	if !r.cfg.ColdCommands {
		// The user, capabilities and limits of a command are the image's,
		// which no bind changes: a command's process can wait for its
		// command from now on.
		keeping, stop := context.WithCancel(context.Background())
		made.warm, made.warmTaken = make(chan *warmCommand, 1), make(chan struct{}, 1)
		made.stopWarm, made.warmDone = stop, make(chan struct{})
		go r.keepWarm(keeping, made, image)
	}
	return made, nil
}

// endContainer ends a made container and waits for its runtime to go. Its
// init ends by itself when the agent's end of its socket closes, and the
// cgroup's kill switch reaches whatever else is in it.
func (r *ImageRunner) endContainer(made *madeSandbox) {
	if made.stopWarm != nil {
		made.stopWarm()
		<-made.warmDone
	}
	_ = made.control.Close()
	if err := os.WriteFile(filepath.Join(r.cgroupDir(), "cgroup.kill"), []byte("1"), 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		r.cfg.Logger.Warn("end the sandbox's container", "error", err)
	}
	select {
	case <-made.exited:
	case <-time.After(stopTimeout):
		r.cfg.Logger.Warn("the sandbox's container was still there after it was killed", "after", stopTimeout.String())
	}
	// What the runtime keeps of a container that ended under it.
	_ = r.crun(context.Background(), "delete", "--force", sandboxID).Run()
}

// unmake ends a container that no sandbox will use, and removes the tree it
// was made over.
func (r *ImageRunner) unmake(made *madeSandbox) {
	r.endContainer(made)
	if err := unix.Unmount(made.rootfs, unix.MNT_DETACH); err != nil {
		r.cfg.Logger.Warn("unmount the root filesystem of a container that was not used", "error", err)
	}
	_ = os.RemoveAll(made.rootfs)
}

// Start tells the container's init what the bind decided. With no process of
// the session's, the init stays as the sandbox's first process and reaps what
// commands leave. With the image's command, the init becomes that process, in
// the container that was made for it.
func (r *ImageRunner) Start(ctx context.Context, credentialDir string) error {
	w, started := r.sandbox()
	switch {
	case w == nil:
		return errors.New("no sandbox prepared")
	case started:
		return errors.New("the sandbox was already started")
	case credentialDir != r.cfg.CredentialDir:
		return errors.New("the sandbox was prepared for another credential directory")
	}
	sandboxNet, err := r.net()
	if err != nil {
		return fmt.Errorf("the sandbox's namespaces: %w", err)
	}
	began := time.Now()
	sandboxNet.serve(w.egress)
	stays := len(w.process.Args) == 0
	told := sandboxinit.Process{Stay: true}
	if !stays {
		told = sandboxinit.Process{Argv: w.process.Args, Env: w.process.Env, Cwd: w.process.Cwd}
	}
	message, err := json.Marshal(told)
	if err != nil {
		return err
	}
	control := w.made.control
	// With the message goes one end of a pipe, which the init keeps closed
	// at its exec: the other end reads the pipe's end the moment the init
	// has become the sandbox's process, or is gone.
	became, theirs, err := os.Pipe()
	if err != nil {
		return err
	}
	err = sendWith(control, message, theirs)
	_ = theirs.Close()
	if err != nil {
		_ = became.Close()
		return fmt.Errorf("tell the sandbox's init its process: %w", err)
	}
	execed := make(chan struct{})
	go func() {
		defer became.Close()
		var none [1]byte
		_, _ = became.Read(none[:])
		close(execed)
	}()
	// The message ends where the agent stops writing.
	if err := unix.Shutdown(int(control.Fd()), unix.SHUT_WR); err != nil {
		return fmt.Errorf("tell the sandbox's init its process: %w", err)
	}
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	sent := time.Since(began)
	// The init says why when it could not become the process, or stay.
	var refused chan string
	answered := make(chan time.Duration, 1)
	if stays {
		// An init that stays says so and lets the pipe go. Its end of the
		// socket need not close then: the runtime may hold it too. So what
		// it has said by the pipe's end is read without waiting for more.
		select {
		case <-execed:
			answered <- time.Since(began)
		case <-w.made.exited:
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(startTimeout):
			return fmt.Errorf("the sandbox's init had not answered after %s", startTimeout)
		}
		said := make([]byte, sandboxinit.MaxAnswer)
		n, _, err := unix.Recvfrom(int(control.Fd()), said, unix.MSG_DONTWAIT)
		if err != nil {
			n = 0
		}
		if taken, reason := sandboxinit.ParseAnswer(said[:n]); !taken {
			return fmt.Errorf("the sandbox's init does not stay: %s", cmp.Or(reason, "it ended without a word"))
		}
	} else {
		refused = make(chan string, 1)
		go func() {
			_, reason := sandboxinit.ReadAnswer(control)
			answered <- time.Since(began)
			refused <- reason
		}()
	}
	if err := r.await(ctx, w.made, sandboxNet, stays, refused, execed); err != nil {
		if reason := readTrimmed(w.made.logPath); reason != "" {
			err = fmt.Errorf("%w: %s", err, reason)
		}
		return err
	}
	lasted := time.Since(began)
	// When the init's end of the socket closed, if it has by now: at its
	// exec or once it stays, unless something else still holds that end.
	var closed time.Duration
	select {
	case closed = <-answered:
	default:
	}
	r.cfg.Logger.Info("sandbox started", "took_us", lasted.Microseconds(), "told_us", sent.Microseconds(), "closed_us", closed.Microseconds(), "init_stays", stays)
	return nil
}

// await returns once the container's first process is the program that is
// waited for: the sandbox init, when the container is made, and after Start
// whatever the init became. The runtime writes the container's first process
// to its pid file when the container is made, and until that process has
// become the init its executable is the runtime's. The process is taken for
// the container's only if it is in the container's cgroup, whatever the file
// says, and it must run in the namespaces the agent made for it. refused,
// when set, delivers what the init says if it could not become the process.
// The process is looked at every so often, and at once when soon is closed:
// that is when the init has become something else, or is gone.
func (r *ImageRunner) await(ctx context.Context, made *madeSandbox, namespaces *sandboxNet, init bool, refused <-chan string, soon <-chan struct{}) error {
	runtime, err := os.Stat(r.cfg.Crun)
	if err != nil {
		return err
	}
	program, err := os.Stat(r.cfg.SandboxInit)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(startTimeout)
	for {
		select {
		case <-made.exited:
			reason := made.exitErr
			if reason == nil {
				reason = errors.New("sandbox exited with status 0")
			}
			// The init says why before it goes.
			if refused != nil {
				select {
				case said := <-refused:
					if said != "" {
						reason = fmt.Errorf("%w: %s", reason, said)
					}
				case <-time.After(100 * time.Millisecond):
				}
			}
			return fmt.Errorf("the sandbox ended before it was running: %w", reason)
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if pid, err := strconv.Atoi(readTrimmed(made.pidPath)); err == nil && pid > 1 {
			proc := filepath.Join("/proc", strconv.Itoa(pid))
			// A file of the kernel's, a line long, which reports no size.
			if cgroup, err := os.ReadFile(filepath.Join(proc, "cgroup")); err == nil && strings.TrimSpace(string(cgroup)) == "0::"+made.cgroupsPath {
				if exe, err := os.Stat(filepath.Join(proc, "exe")); err == nil && !os.SameFile(exe, runtime) && os.SameFile(exe, program) == init {
					return namespaces.holds(proc)
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the sandbox was not running after %s", startTimeout)
		}
		select {
		case <-soon:
			// Once: from here the process is looked at every so often again.
			soon = nil
		case <-time.After(awaitRunningEvery):
		}
	}
}

// sendWith writes message to the init's control socket and passes it one
// descriptor with the first of its bytes.
func sendWith(control *os.File, message []byte, pass *os.File) error {
	n, err := unix.SendmsgN(int(control.Fd()), message, unix.UnixRights(int(pass.Fd())), nil, 0)
	runtime.KeepAlive(pass)
	if err != nil {
		return err
	}
	_, err = control.Write(message[n:])
	return err
}

// Wait returns when the container's main process has ended. A guest waits
// from before it has a sandbox, so this does not ask whether one is prepared.
func (r *ImageRunner) Wait(ctx context.Context) error {
	select {
	case <-r.exited:
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.exitErr
	case <-ctx.Done():
		return nil
	}
}

// Exec runs one command inside the container, as the sandbox's user and
// under its limits. crun and everything the command spawns start in a cgroup
// of their own below the container's, so killing that cgroup is exact.
func (r *ImageRunner) Exec(ctx context.Context, req *session.ExecRequest) (*session.ExecResponse, error) {
	w, started := r.sandbox()
	if w == nil {
		return r.bare.Exec(ctx, req)
	}
	if !started {
		return nil, errors.New("the sandbox is not running")
	}
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = session.DefaultExecLimit * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// A process that was started for whichever command comes next, if one
	// waits. Otherwise the runtime starts this command's.
	if warm := w.made.takeWarm(); warm != nil {
		if resp, started := r.execWarm(ctx, warm, w.process, req); started {
			w.made.warmUsed.Add(1)
			return resp, nil
		}
		// It ended before it took the command, which started nothing.
	}

	dir := filepath.Join(r.cfg.RunDir, "exec-"+req.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	process, err := json.Marshal(execProcess(w.process, req))
	if err != nil {
		return nil, err
	}
	processPath, logPath := filepath.Join(dir, "process.json"), filepath.Join(dir, "crun.log")
	if err := os.WriteFile(processPath, process, 0o600); err != nil {
		return nil, err
	}
	group, err := newProcessGroup(r.cgroupDir(), req.ID)
	if err != nil {
		return nil, err
	}
	defer group.close()

	cmd := r.crun(ctx, "--log", "file:"+logPath, "exec", "--process", processPath, "--cgroup", filepath.Base(group.dir), sandboxID)
	cmd.Stdin = bytes.NewReader(req.Stdin)
	stdout, stderr := &cappedBuffer{limit: session.MaxExecOutput}, &cappedBuffer{limit: session.MaxExecOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = group.sysProcAttr(-1, -1)
	cmd.Cancel = func() error { return group.kill(cmd.Process) }
	cmd.WaitDelay = waitDelay

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start crun: %w", err)
	}
	group.started(cmd.Process)
	waitErr := cmd.Wait()
	// Stragglers that outlived the command must not outlive its result.
	_ = group.kill(cmd.Process)
	if cmd.ProcessState == nil {
		return nil, fmt.Errorf("wait for command: %w", waitErr)
	}
	resp := &session.ExecResponse{
		ExitCode: exitStatus(cmd.ProcessState),
		Stdout:   stdout.bytes(), Stderr: stderr.bytes(),
		StdoutTruncated: stdout.truncated(), StderrTruncated: stderr.truncated(),
		DurationMillis: time.Since(start).Milliseconds(),
		TimedOut:       errors.Is(ctx.Err(), context.DeadlineExceeded),
	}
	// crun logs only its own failures, so a logged failure means the command
	// never started. As with a bare command that is a result, with the status
	// a shell would give, and crun has already said why on stderr.
	if reason := readTrimmed(logPath); resp.ExitCode == crunFailed && reason != "" {
		resp.ExitCode = exitNotExecutable
		if strings.Contains(reason, "No such file or directory") {
			resp.ExitCode = exitNotFound
		}
	}
	return resp, nil
}

// warmCommand is a command's process started ahead of its command: the
// sandbox init, started by the runtime in the sandbox's container and in a
// cgroup of its own, waiting to be told what to become. The runtime's part of
// starting a command is done before the command comes, and what is left is
// one message and one exec.
//
// Tenant code runs beside the waiting init under the same user. The init is
// undumpable until its exec, so that code cannot attach to it or open its
// socket to the agent, and the agent reads a bounded answer from it.
type warmCommand struct {
	cmd   *exec.Cmd
	group *processGroup
	// dir holds the runtime's description of the process and its log.
	dir     string
	logPath string
	// control is the agent's end of the socket pair the init reads.
	control        *os.File
	stdin          io.WriteCloser
	stdout, stderr *cappedBuffer
	// done is closed when the runtime has ended, and with it the process.
	done chan struct{}
}

// keepWarm keeps one command's process waiting in made's container for as
// long as the container lives, and starts the next when one is taken.
func (r *ImageRunner) keepWarm(ctx context.Context, made *madeSandbox, image *specs.Process) {
	defer close(made.warmDone)
	for n := 0; ; n++ {
		warm, err := r.startWarm(image, n)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-made.exited:
				return
			default:
			}
			r.cfg.Logger.Warn("a command's process was not started ahead", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-made.exited:
				return
			case <-time.After(time.Second):
			}
			continue
		}
		// Room for one, and nothing else is ever in it.
		made.warm <- warm
		select {
		case <-made.warmTaken:
		case <-ctx.Done():
		case <-made.exited:
		}
		if ctx.Err() != nil || ended(made.exited) {
			// The one that waits, unless a command took it just now.
			select {
			case left := <-made.warm:
				r.endWarm(left)
			default:
			}
			return
		}
	}
}

func ended(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// startWarm starts the sandbox init in the sandbox's container, as a command
// is started: by the runtime, in a cgroup of its own below the container's,
// as the image's user and under its limits.
func (r *ImageRunner) startWarm(image *specs.Process, n int) (_ *warmCommand, err error) {
	id := fmt.Sprintf("ahead-%d", n)
	warm := &warmCommand{dir: filepath.Join(r.cfg.RunDir, "exec-"+id), done: make(chan struct{})}
	if err := os.MkdirAll(warm.dir, 0o700); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if warm.control != nil {
				_ = warm.control.Close()
			}
			if warm.group != nil {
				warm.group.close()
			}
			_ = os.RemoveAll(warm.dir)
		}
	}()
	init := *image
	init.Args = []string{fmt.Sprintf("/proc/self/fd/%d", sandboxinit.ProgramFD)}
	init.Env = []string{"PATH=" + defaultSandboxPath}
	init.Cwd = "/"
	process, err := json.Marshal(&init)
	if err != nil {
		return nil, err
	}
	processPath := filepath.Join(warm.dir, "process.json")
	warm.logPath = filepath.Join(warm.dir, "crun.log")
	if err := os.WriteFile(processPath, process, 0o600); err != nil {
		return nil, err
	}
	if warm.group, err = newProcessGroup(r.cgroupDir(), id); err != nil {
		return nil, err
	}
	program, err := os.Open(r.cfg.SandboxInit)
	if err != nil {
		return nil, fmt.Errorf("the sandbox's init: %w", err)
	}
	defer program.Close()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("the init's control socket: %w", err)
	}
	warm.control = os.NewFile(uintptr(pair[0]), "command-init-control")
	theirs := os.NewFile(uintptr(pair[1]), "command-init")
	defer theirs.Close()
	// Not under a context: the process waits for a command that has not
	// come, and that command's limit is what ends it.
	cmd := r.crun(context.Background(), "--log", "file:"+warm.logPath, "exec", "--process", processPath,
		"--cgroup", filepath.Base(warm.group.dir), "--preserve-fds", "2", sandboxID)
	cmd.ExtraFiles = []*os.File{program, theirs}
	warm.stdout, warm.stderr = &cappedBuffer{limit: session.MaxExecOutput}, &cappedBuffer{limit: session.MaxExecOutput}
	cmd.Stdout, cmd.Stderr = warm.stdout, warm.stderr
	if warm.stdin, err = cmd.StdinPipe(); err != nil {
		return nil, err
	}
	cmd.SysProcAttr = warm.group.sysProcAttr(-1, -1)
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start crun: %w", err)
	}
	warm.group.started(cmd.Process)
	warm.cmd = cmd
	go func() {
		_ = cmd.Wait()
		close(warm.done)
	}()
	return warm, nil
}

// endWarm ends a command's process that no command took, or whose command
// is over, and removes what was made for it.
func (r *ImageRunner) endWarm(warm *warmCommand) {
	_ = warm.control.Close()
	_ = warm.stdin.Close()
	_ = warm.group.kill(warm.cmd.Process)
	select {
	case <-warm.done:
	case <-time.After(stopTimeout):
		r.cfg.Logger.Warn("a command's process was still there after it was killed", "after", stopTimeout.String())
	}
	warm.group.close()
	_ = os.RemoveAll(warm.dir)
}

// takeWarm returns a command's process that waits for its command, or nil
// when none does: the next one is still being started, or the container
// starts none ahead.
func (m *madeSandbox) takeWarm() *warmCommand {
	if m.warm == nil {
		return nil
	}
	select {
	case warm := <-m.warm:
		select {
		case m.warmTaken <- struct{}{}:
		default:
		}
		return warm
	default:
		return nil
	}
}

// execWarm runs one command as a process that was started ahead: it tells
// the init what to become and waits for the runtime to end, as Exec does for
// a command the runtime starts. started is false when the process ended
// before it took the command: nothing ran, and the caller starts the command
// another way.
func (r *ImageRunner) execWarm(ctx context.Context, warm *warmCommand, main *specs.Process, req *session.ExecRequest) (_ *session.ExecResponse, started bool) {
	defer r.endWarm(warm)
	start := time.Now()
	p := execProcess(main, req)
	message, err := json.Marshal(sandboxinit.Process{Argv: p.Args, Env: p.Env, Cwd: p.Cwd})
	if err != nil {
		return nil, false
	}
	if _, err := warm.control.Write(message); err != nil {
		return nil, false
	}
	// The message ends where the agent stops writing.
	if err := unix.Shutdown(int(warm.control.Fd()), unix.SHUT_WR); err != nil {
		return nil, false
	}
	type answer struct {
		taken  bool
		reason string
	}
	said := make(chan answer, 1)
	go func() {
		taken, reason := sandboxinit.ReadAnswer(warm.control)
		said <- answer{taken, reason}
	}()
	go func() {
		_, _ = warm.stdin.Write(req.Stdin)
		_ = warm.stdin.Close()
	}()
	select {
	case <-warm.done:
	case <-ctx.Done():
		_ = warm.group.kill(warm.cmd.Process)
		<-warm.done
	}
	// Stragglers that outlived the command must not outlive its result.
	_ = warm.group.kill(warm.cmd.Process)
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	var init answer
	select {
	case init = <-said:
	case <-time.After(waitDelay):
	}
	if !init.taken && init.reason == "" && !timedOut && ctx.Err() == nil {
		return nil, false
	}
	resp := &session.ExecResponse{
		ExitCode: exitStatus(warm.cmd.ProcessState),
		Stdout:   warm.stdout.bytes(), Stderr: warm.stderr.bytes(),
		StdoutTruncated: warm.stdout.truncated(), StderrTruncated: warm.stderr.truncated(),
		DurationMillis: time.Since(start).Milliseconds(),
		TimedOut:       timedOut,
	}
	// A reason from the init means the command never started. That is a
	// result, with the status a shell would give and the reason where the
	// command's own errors go.
	if init.reason != "" && resp.ExitCode == sandboxinit.FailureStatus {
		resp.ExitCode = exitNotExecutable
		if lower := strings.ToLower(init.reason); strings.Contains(lower, "command not found") || strings.Contains(lower, "no such file or directory") {
			resp.ExitCode = exitNotFound
		}
		if !resp.StderrTruncated {
			resp.Stderr = append(resp.Stderr, []byte(init.reason+"\n")...)
		}
	}
	return resp, true
}

// Dial connects to a port on the loopback of the sandbox's network
// namespace, from inside it.
func (r *ImageRunner) Dial(ctx context.Context, port int) (net.Conn, error) {
	if _, started := r.sandbox(); !started {
		return r.bare.Dial(ctx, port)
	}
	sandboxNet, err := r.net()
	if err != nil {
		return nil, err
	}
	return sandboxNet.dial(ctx, port)
}

// Close ends the sandbox and releases its root filesystem. A guest never
// needs it: it powers off with the agent.
func (r *ImageRunner) Close() error {
	r.mu.Lock()
	stop, done := r.stopAhead, r.aheadDone
	r.mu.Unlock()
	if stop != nil {
		stop()
		<-done
	}
	w, _ := r.sandbox()
	r.mu.Lock()
	made := r.made
	r.made = nil
	r.mu.Unlock()
	// The namespaces go last, and whether a sandbox came or not.
	defer func() {
		if sandboxNet, err := r.net(); err == nil {
			_ = sandboxNet.Close()
		}
	}()
	if made != nil {
		// Made ahead, and no bind came for it.
		r.unmake(made)
	}
	if w == nil {
		return nil
	}
	// Reaches the container and every command in the cgroups below it,
	// whether its process is the image's yet or still the init.
	r.endContainer(w.made)
	select {
	case <-w.made.exited:
	default:
		return fmt.Errorf("the sandbox was still running %s after it was killed", stopTimeout)
	}
	if err := unix.Unmount(w.rootfs, unix.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount root filesystem: %w", err)
	}
	return nil
}

func readTrimmed(path string) string {
	data, err := session.ReadBounded(path, 64<<10)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
