//go:build linux

package sessionagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/contrib/seccomp"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

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
	Crun   string
	Pull   imagestore.PullLimits
	Unpack imagestore.UnpackLimits
	// Images is the host's image store, or nil. What it holds of an image is
	// read from it, checked like a registry's answer, and the registry is
	// asked for the rest.
	Images *imagestore.Store
	// PlainHTTP marks the registries reached without TLS.
	PlainHTTP func(host string) bool
	Logger    *slog.Logger
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
}

// NewImageRunner returns the runner of a guest image that carries crun.
func NewImageRunner(cfg ImageRunnerConfig, bare Runner) (*ImageRunner, error) {
	if bare == nil {
		return nil, errors.New("image runner needs a bare runner for guests without a sandbox")
	}
	if cfg.StateDir == "" || cfg.RunDir == "" || cfg.CredentialDir == "" || cfg.Crun == "" {
		return nil, errors.New("image runner needs a state directory, a run directory, a credential directory and crun")
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
		for _, entry := range order {
			began := time.Now()
			entry.err = r.unpackAhead(ctx, entry)
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

// Prepare pulls the image, verifies it against the digest the launch document
// pins, and unpacks it, or takes the tree that was unpacked ahead. Nothing of
// the image runs.
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
	store, rootfs := filepath.Join(r.cfg.StateDir, "store"), filepath.Join(r.cfg.StateDir, "rootfs")
	began := time.Now()
	var process *specs.Process
	var err error
	if ahead := r.takeAhead(ctx, w); ahead != nil {
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
	// What was unpacked ahead and is not this sandbox's is nobody's. It goes
	// while the sandbox starts: no sandbox waits for it.
	go func() { _ = os.RemoveAll(r.aheadDir()) }()
	if err == nil {
		err = mountRootfs(rootfs)
	}
	if err != nil {
		_ = os.RemoveAll(rootfs)
		return err
	}
	r.mu.Lock()
	r.prepared = &preparedSandbox{process: process, rootfs: rootfs, egress: egress}
	r.mu.Unlock()
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

// Start runs the container under a crun that stays in the foreground: the
// agent is its parent, so the sandbox's end is the end of a child.
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
	cgroupsPath, ok := strings.CutPrefix(r.cgroupDir(), cgroupRoot)
	if !ok || cgroupsPath == "" {
		return fmt.Errorf("delegated cgroup %s is not under %s", r.cfg.CgroupParent, cgroupRoot)
	}
	// Beside the credential directory, where the container's user can reach
	// it: the run directory is the agent's alone.
	mounts := sandboxMounts{CredentialDir: credentialDir, ResolvConf: filepath.Join(filepath.Dir(credentialDir), "sandbox-resolv.conf")}
	if err := fileutil.WriteAtomic(mounts.ResolvConf, []byte(sandboxResolvConf), 0o644); err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = sandboxID
	}
	if err := os.MkdirAll(r.cfg.RunDir, 0o700); err != nil {
		return err
	}
	sandboxNet, err := r.net()
	if err != nil {
		return fmt.Errorf("the sandbox's namespaces: %w", err)
	}
	spec := sandboxSpec(w.process, w.rootfs, hostname, cgroupsPath, r.cfg.PidsLimit, mounts, sandboxNet.paths())
	// containerd's default profile, for the capabilities the sandbox holds:
	// what a container gets anywhere else. Capabilities and the user namespace
	// already gate most of what it refuses; this narrows the kernel surface
	// behind them, and crun applies it to every command too.
	spec.Linux.Seccomp = seccomp.DefaultProfile(spec)
	config, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	bundle := filepath.Join(r.cfg.RunDir, "bundle")
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		return err
	}
	if err := fileutil.WriteAtomic(filepath.Join(bundle, "config.json"), config, 0o600); err != nil {
		return err
	}
	// crun's own errors go to this file. The sandbox's output is tenant data
	// and goes nowhere: the container's stdio is /dev/null.
	logPath := filepath.Join(r.cfg.RunDir, "crun-run.log")
	pidPath := filepath.Join(r.cfg.RunDir, "sandbox.pid")
	if err := os.Remove(pidPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	sandboxNet.serve(w.egress)
	// Not under ctx: the sandbox outlives the admission that started it.
	cmd := r.crun(context.Background(), "--log", "file:"+logPath, "run", "--bundle", bundle, "--pid-file", pidPath, sandboxID)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start crun: %w", err)
	}
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	go func() {
		err := cmd.Wait()
		var status *exec.ExitError
		if errors.As(err, &status) {
			err = fmt.Errorf("sandbox exited with status %d", exitStatus(status.ProcessState))
		}
		r.mu.Lock()
		r.exitErr = err
		r.mu.Unlock()
		close(r.exited)
	}()
	if err := r.awaitRunning(ctx, pidPath, cgroupsPath, sandboxNet); err != nil {
		if reason := readTrimmed(logPath); reason != "" {
			err = fmt.Errorf("%w: %s", err, reason)
		}
		return err
	}
	r.cfg.Logger.Info("sandbox started")
	return nil
}

// awaitRunning returns once the image's own program runs. The runtime writes
// the container's first process to pidPath when the container is made, and
// that process then becomes the image's command: until it has, its
// executable is the runtime's. The process is taken for the container's only
// if it is in the container's cgroup, whatever the file says, and it must run
// in the namespaces the agent made for it.
func (r *ImageRunner) awaitRunning(ctx context.Context, pidPath, cgroupsPath string, namespaces *sandboxNet) error {
	runtime, err := os.Stat(r.cfg.Crun)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(startTimeout)
	for {
		select {
		case <-r.exited:
			return fmt.Errorf("the sandbox ended before it was running: %w", r.exitError())
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if pid, err := strconv.Atoi(readTrimmed(pidPath)); err == nil && pid > 1 {
			proc := filepath.Join("/proc", strconv.Itoa(pid))
			// A file of the kernel's, a line long, which reports no size.
			if cgroup, err := os.ReadFile(filepath.Join(proc, "cgroup")); err == nil && strings.TrimSpace(string(cgroup)) == "0::"+cgroupsPath {
				if exe, err := os.Stat(filepath.Join(proc, "exe")); err == nil && !os.SameFile(exe, runtime) {
					return namespaces.holds(proc)
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the sandbox was not running after %s", startTimeout)
		}
		time.Sleep(awaitRunningEvery)
	}
}

func (r *ImageRunner) exitError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.exitErr == nil {
		return errors.New("sandbox exited with status 0")
	}
	return r.exitErr
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
	w, started := r.sandbox()
	// The namespaces go last, and whether a sandbox came or not.
	defer func() {
		if sandboxNet, err := r.net(); err == nil {
			_ = sandboxNet.Close()
		}
	}()
	if w == nil {
		return nil
	}
	if started {
		// Reaches the container and every command in the cgroups below it.
		if err := os.WriteFile(filepath.Join(r.cgroupDir(), "cgroup.kill"), []byte("1"), 0); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-r.exited:
		case <-time.After(stopTimeout):
			return fmt.Errorf("the sandbox was still running %s after it was killed", stopTimeout)
		}
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
