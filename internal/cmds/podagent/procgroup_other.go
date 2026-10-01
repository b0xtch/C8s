//go:build !linux

package podagent

import (
	"errors"
	"os"
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

func (g *processGroup) close() {}
