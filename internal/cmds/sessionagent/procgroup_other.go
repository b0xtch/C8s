//go:build !linux

package sessionagent

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// processGroup off Linux is a plain process group; only tests run here.
type processGroup struct{}

func newProcessGroup(string, string) (*processGroup, error) { return &processGroup{}, nil }

func (g *processGroup) sysProcAttr(uid, gid int) *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{Setpgid: true}
	if uid >= 0 && gid >= 0 {
		attr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	}
	return attr
}

func (g *processGroup) started(*os.Process) {}

func (g *processGroup) kill(p *os.Process) error {
	if p == nil {
		return nil
	}
	if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

// wait waits for a command that was started in the group, and ends what
// outlived it.
func (g *processGroup) wait(cmd *exec.Cmd) error {
	err := cmd.Wait()
	_ = g.kill(cmd.Process)
	return err
}

func (g *processGroup) close() {}
