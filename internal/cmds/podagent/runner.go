package podagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

// RunnerConfig places commands in the guest: who they run as and where.
type RunnerConfig struct {
	// UID and GID are the unprivileged identity commands run as; -1 keeps the
	// agent's own, which only tests do.
	UID, GID int
	// Home is the default working directory, on the encrypted scratch volume.
	Home string
	// CredentialDir is exported to commands as C8S_CREDENTIALS_DIR.
	CredentialDir string
	// CgroupParent, when set, is a delegated cgroup v2 directory. Each command
	// gets its own child cgroup, killed whole when the command ends.
	CgroupParent string
}

// ProcessRunner runs commands directly in the guest as an unprivileged user.
// It is the worker with no container image: the measured guest userland is
// the environment.
type ProcessRunner struct {
	cfg RunnerConfig
}

// NewProcessRunner returns the runner for a guest without a workload image.
func NewProcessRunner(cfg RunnerConfig) (*ProcessRunner, error) {
	if cfg.Home == "" {
		return nil, errors.New("runner home directory is required")
	}
	return &ProcessRunner{cfg: cfg}, nil
}

func (r *ProcessRunner) CredentialOwner() (int, int) { return r.cfg.UID, r.cfg.GID }

// Prepare refuses a workload image: this runner has no container runtime, and
// running the document's image "some other way" would run something the
// document did not name.
func (r *ProcessRunner) Prepare(context.Context, *podcvm.Workload) error {
	return errors.New("this guest image cannot run a workload image")
}

func (r *ProcessRunner) Start(context.Context, string) error {
	return errors.New("no workload prepared")
}

const (
	// Exit statuses for a command that never ran, as shells report them.
	exitNotExecutable = 126
	exitNotFound      = 127
	// waitDelay bounds how long output pipes held open by a killed command's
	// descendants can delay its result.
	waitDelay = 5 * time.Second
)

func (r *ProcessRunner) Exec(ctx context.Context, req *podcvm.ExecRequest) (*podcvm.ExecResponse, error) {
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = podcvm.DefaultExecLimit * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	group, err := newProcessGroup(r.cfg.CgroupParent, req.ID)
	if err != nil {
		return nil, err
	}
	defer group.close()

	cmd := exec.CommandContext(ctx, req.Argv[0], req.Argv[1:]...)
	cmd.Dir = r.cfg.Home
	if req.Cwd != "" {
		cmd.Dir = req.Cwd
	}
	cmd.Env = r.environ(req.Env)
	cmd.Stdin = bytes.NewReader(req.Stdin)
	stdout, stderr := &cappedBuffer{limit: podcvm.MaxExecOutput}, &cappedBuffer{limit: podcvm.MaxExecOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = group.sysProcAttr(r.cfg.UID, r.cfg.GID)
	// Cancellation kills the command together with everything it spawned.
	cmd.Cancel = func() error { return group.kill(cmd.Process) }
	cmd.WaitDelay = waitDelay

	start := time.Now()
	runErr := cmd.Run()
	// Stragglers that outlived the command must not outlive its result.
	_ = group.kill(cmd.Process)
	resp := &podcvm.ExecResponse{
		Stdout: stdout.bytes(), Stderr: stderr.bytes(),
		StdoutTruncated: stdout.truncated(), StderrTruncated: stderr.truncated(),
		DurationMillis: time.Since(start).Milliseconds(),
	}
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
	case errors.As(runErr, &exitErr):
		resp.ExitCode = exitErr.ExitCode()
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			resp.ExitCode = 128 + int(status.Signal())
		}
	case cmd.ProcessState == nil:
		// The command never started. That is an outcome of this request, so it
		// is reported as a result with the status a shell would give.
		resp.ExitCode = exitNotExecutable
		if errors.Is(runErr, exec.ErrNotFound) || errors.Is(runErr, fs.ErrNotExist) {
			resp.ExitCode = exitNotFound
		}
		resp.Stderr = []byte(runErr.Error() + "\n")
	default:
		return nil, fmt.Errorf("run command: %w", runErr)
	}
	resp.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	return resp, nil
}

// environ is a fixed baseline plus the request's variables. Nothing is
// inherited from the agent's own environment.
func (r *ProcessRunner) environ(extra map[string]string) []string {
	env := map[string]string{
		"PATH":                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME":                r.cfg.Home,
		"LANG":                "C.UTF-8",
		"C8S_CREDENTIALS_DIR": r.cfg.CredentialDir,
	}
	for k, v := range extra {
		env[k] = v
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// cappedBuffer keeps the first limit bytes and discards the rest, so a noisy
// command can neither block on a full pipe nor exhaust agent memory.
type cappedBuffer struct {
	mu    sync.Mutex
	buf   []byte
	limit int
	cut   bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.limit - len(b.buf); room >= len(p) {
		b.buf = append(b.buf, p...)
	} else {
		b.buf = append(b.buf, p[:room]...)
		b.cut = true
	}
	return len(p), nil
}

func (b *cappedBuffer) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf == nil {
		return []byte{}
	}
	return b.buf
}

func (b *cappedBuffer) truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cut
}
