//go:build linux

package podagent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
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

func (g *processGroup) kill(p *os.Process) error {
	var errs []error
	if g.dir != "" {
		if err := os.WriteFile(filepath.Join(g.dir, "cgroup.kill"), []byte("1"), 0); err != nil {
			errs = append(errs, err)
		}
	}
	if p != nil {
		// Negative pid: the whole process group the command leads.
		if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// close removes the command's cgroup once the kernel has reaped its tasks.
func (g *processGroup) close() {
	if g.dir == "" {
		return
	}
	g.fd.Close()
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		events, _ := os.ReadFile(filepath.Join(g.dir, "cgroup.events"))
		if strings.Contains(string(events), "populated 0") || time.Now().After(deadline) {
			break
		}
	}
	_ = os.Remove(g.dir)
}

// DelegatedCgroup prepares this service's own cgroup for per-command children.
// cgroup v2 forbids processes in a cgroup that has controller-enabled children,
// so the agent first moves itself into a leaf. It returns "" when the service
// was not started with a delegated cgroup v2 subtree.
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
	return base, nil
}
