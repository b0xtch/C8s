//go:build linux

package sandboxinit

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// spawn is the sandbox's spawner. The runtime starts it once, in the
// sandbox's container, as the image's user and under the container's limits,
// and whatever it starts inherits all of that: a process for a command then
// costs a fork and an exec where the runtime's own start costs a program
// that reads the container's state, joins its namespaces and loads its
// filters each time.
//
// ControlFD is a socket of packets here. Each packet from the agent is a
// request and carries SpawnRequest descriptors: the control socket of the
// process to start, its standard input, output and error, and the file of
// the kernel's that puts a process in the cgroup the agent made for this
// one. The spawner starts this program again with the first four, as the
// runtime would have, and writes the new process's number to the fifth: the
// process is in its cgroup before the agent hears of it, and the agent moves
// nothing by a number, which in its own namespace could name another process
// by then. The kernel reads the number in this namespace, where the process
// keeps it until this spawner has reaped it, and lets the write put only
// this sandbox's processes there, and only in that one cgroup. The spawner
// answers with a packet: Spawned and the request's number, with a descriptor
// for the new process, by which the agent knows it and learns of its end; or
// SpawnFailed, the number and why. It reaps what it started and says nothing
// of how any of it ended: the kernel tells the agent that, through the
// descriptor. It returns when the agent closes the socket.
//
// It says nothing of its own to the agent but these, and reads nothing from
// it but descriptors: no command passes through it.
func spawn() int {
	self := fmt.Sprintf("/proc/self/fd/%d", ProgramFD)
	// Held by a start from its fork until the process's number is written
	// to its cgroup's file, and by the reaper for each wait: no process is
	// reaped, and so none gives its number up, in between.
	var mu sync.Mutex
	say := func(text string, descriptors ...int) {
		var rights []byte
		if len(descriptors) > 0 {
			rights = unix.UnixRights(descriptors...)
		}
		for {
			if err := unix.Sendmsg(ControlFD, []byte(text), rights, nil, 0); !errors.Is(err, unix.EINTR) {
				return
			}
		}
	}

	ended := make(chan os.Signal, 1)
	signal.Notify(ended, unix.SIGCHLD)
	go func() {
		for range ended {
			for {
				mu.Lock()
				pid, err := unix.Wait4(-1, nil, unix.WNOHANG, nil)
				mu.Unlock()
				if errors.Is(err, unix.EINTR) {
					continue
				}
				if pid <= 0 || err != nil {
					break
				}
			}
		}
	}()

	packet, control := make([]byte, MaxSpawnPacket), make([]byte, unix.CmsgSpace(4*8))
	for n := 0; ; {
		size, controlled, _, _, err := unix.Recvmsg(ControlFD, packet, control, unix.MSG_CMSG_CLOEXEC)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || size == 0 {
			// The agent closed its end: the sandbox is ending.
			return 0
		}
		passed := passedIn(control[:controlled])
		if len(passed) != SpawnRequest {
			say(fmt.Sprintf("%s %d a request carries %d descriptors, and this one %d", SpawnFailed, n, SpawnRequest, len(passed)))
		} else {
			mu.Lock()
			var process int
			pid, err := syscall.ForkExec(self, []string{self}, &syscall.ProcAttr{
				Dir: "/", Env: []string{"PATH=" + defaultPath},
				// Where the runtime puts them: the standard three, this
				// program's file, the process's own control socket.
				Files: []uintptr{uintptr(passed[1]), uintptr(passed[2]), uintptr(passed[3]), ProgramFD, uintptr(passed[0])},
				Sys:   &syscall.SysProcAttr{Setsid: true, PidFD: &process},
			})
			if err == nil {
				// Its number is its own for as long as this lock is held:
				// only the reaper above gives a number up, under the lock.
				if err = writeAll(passed[4], strconv.Itoa(pid)); err != nil {
					err = fmt.Errorf("put the process in its cgroup: %w", err)
					_ = unix.Kill(pid, unix.SIGKILL)
					_ = unix.Close(process)
				}
			}
			mu.Unlock()
			if err != nil {
				say(fmt.Sprintf("%s %d %v", SpawnFailed, n, err))
			} else {
				say(fmt.Sprintf("%s %d", Spawned, n), process)
				_ = unix.Close(process)
			}
		}
		for _, fd := range passed {
			_ = unix.Close(fd)
		}
		n++
	}
}

// writeAll writes text to a descriptor in one write, again if interrupted.
func writeAll(fd int, text string) error {
	for {
		if _, err := unix.Write(fd, []byte(text)); !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// passedIn is every descriptor in one packet's control data.
func passedIn(control []byte) []int {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return nil
	}
	var passed []int
	for i := range messages {
		if fds, err := unix.ParseUnixRights(&messages[i]); err == nil {
			passed = append(passed, fds...)
		}
	}
	return passed
}
