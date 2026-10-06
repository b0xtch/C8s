//go:build linux

package sessionagent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// execPidsMax caps one command's processes and threads, so a fork bomb
	// cannot take the tasks the agent itself needs. Eight commands run at once.
	execPidsMax = "1024"
	// execOOMScoreAdj puts tenant commands ahead of every guest service.
	execOOMScoreAdj = "500"
)

// processGroup contains one command and everything it spawns. With a delegated
// cgroup the containment is exact: cgroup.kill reaches every descendant, even
// one that left the process group or session.
type processGroup struct {
	dir string
	fd  *os.File
}

func newProcessGroup(parent, id string) (*processGroup, error) {
	if parent == "" {
		return &processGroup{}, nil
	}
	dir := filepath.Join(parent, "exec-"+id)
	if err := os.Mkdir(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create command cgroup: %w", err)
	}
	// Best effort: the file exists only where the pids controller is delegated.
	_ = os.WriteFile(filepath.Join(dir, "pids.max"), []byte(execPidsMax), 0)
	fd, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		_ = os.Remove(dir)
		return nil, fmt.Errorf("open command cgroup: %w", err)
	}
	return &processGroup{dir: dir, fd: fd}, nil
}

func (g *processGroup) sysProcAttr(uid, gid int) *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{Setpgid: true}
	if uid >= 0 && gid >= 0 {
		// An empty Groups list drops the agent's supplementary groups.
		attr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	}
	if g.fd != nil {
		attr.UseCgroupFD, attr.CgroupFD = true, int(g.fd.Fd())
	}
	return attr
}

// started undoes what the command inherited from the agent's unit: the agent is
// protected from the OOM killer, and a tenant command must be the first thing
// the kernel takes when the guest runs out of memory.
func (g *processGroup) started(p *os.Process) {
	_ = os.WriteFile(fmt.Sprintf("/proc/%d/oom_score_adj", p.Pid), []byte(execOOMScoreAdj), 0)
}

// kill ends the command and everything it spawned. With a cgroup it is ended
// by the cgroup alone, which names its processes by no number: once a
// command has been waited for, its number can name another process, and in
// the agent's namespace that could be one of the agent's own. Without one,
// p leads the process group that is killed, and must not have been waited
// for yet: see wait.
func (g *processGroup) kill(p *os.Process) error {
	if g.dir != "" {
		// The kernel's own file, written and never made: a cgroup that is
		// gone has none, and holds nothing to end.
		f, err := os.OpenFile(filepath.Join(g.dir, "cgroup.kill"), os.O_WRONLY, 0)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteString("1")
		return err
	}
	if p != nil {
		// Negative pid: the whole process group the command leads.
		if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	return nil
}

// wait waits for a command that was started in the group, and ends what
// outlived it: stragglers must not outlive a command's result. Without a
// cgroup they are the command's process group, which is killed once the
// command has ended and before it is waited for: until then the command
// keeps its number, and so its group's, from every other process.
func (g *processGroup) wait(cmd *exec.Cmd) error {
	if g.dir == "" {
		var info unix.Siginfo
		for {
			if err := unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil); !errors.Is(err, unix.EINTR) {
				break
			}
		}
		_ = g.kill(cmd.Process)
		return cmd.Wait()
	}
	err := cmd.Wait()
	_ = g.kill(nil)
	return err
}

// closeWait bounds how long close tries to empty a command's cgroup.
const closeWait = 2 * time.Second

// close removes the command's cgroup, which the kernel allows once it holds
// no process. A cgroup that is gone holds none: a container's runtime
// removes the cgroups below the container's when the container ends. One
// that still holds a process is killed again and tried again, for a bounded
// time: whoever was handed the cgroup's file of processes can put more in
// after a kill, until the cgroup is removed. A cgroup that does not empty
// in that time is left to end with its sandbox, and nothing waits on it.
func (g *processGroup) close() {
	if g.dir == "" {
		return
	}
	g.fd.Close()
	pause := time.Millisecond
	for deadline := time.Now().Add(closeWait); ; time.Sleep(pause) {
		if err := os.Remove(g.dir); err == nil || errors.Is(err, os.ErrNotExist) || time.Now().After(deadline) {
			return
		}
		_ = g.kill(nil)
		pause = min(2*pause, 10*time.Millisecond)
	}
}

// agentWeight is the agent's weight on a processor against its siblings in
// the service's cgroup, the sandbox and the commands, which keep the
// kernel's 100. The session's code has every processor of the guest, the
// agent's among them, and code that keeps its busy threads to the agent's
// then takes a hundredth of it where it would take half.
const agentWeight = "10000"

// DelegatedCgroup prepares this service's own cgroup for per-command children.
// cgroup v2 forbids processes in a cgroup that has controller-enabled children,
// so the agent first moves itself into a leaf, which it weighs above the
// children to come. It returns "" when the service was not started with a
// delegated cgroup v2 subtree.
func DelegatedCgroup() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	rel, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "0::")
	if !ok || strings.Contains(rel, "\n") {
		return "", nil
	}
	base := filepath.Join("/sys/fs/cgroup", rel)
	leaf := filepath.Join(base, "agent")
	if err := os.Mkdir(leaf, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return "", nil
	}
	if err := os.WriteFile(filepath.Join(leaf, "cgroup.procs"), []byte("0"), 0); err != nil {
		return "", fmt.Errorf("move agent into its leaf cgroup: %w", err)
	}
	if err := weigh(base, leaf); err != nil {
		return "", err
	}
	// Best effort: without the pids controller a command is still contained
	// and killed whole, only its task count is unbounded.
	_ = os.WriteFile(filepath.Join(base, "cgroup.subtree_control"), []byte("+pids"), 0)
	return base, nil
}

// weigh gives the cgroup at leaf the agent's weight among the children of
// base, whose processor time the kernel then shares out by weight.
func weigh(base, leaf string) error {
	if err := os.WriteFile(filepath.Join(base, "cgroup.subtree_control"), []byte("+cpu"), 0); err != nil {
		return fmt.Errorf("share the service's processor time by weight: %w", err)
	}
	if err := os.WriteFile(filepath.Join(leaf, "cpu.weight"), []byte(agentWeight), 0); err != nil {
		return fmt.Errorf("weigh the agent above its sandbox: %w", err)
	}
	return nil
}
