//go:build linux

package coresched

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// sleeper is a program that stays until it is killed.
func sleeper(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return cmd
}

// Two programs started apart have a cookie each, and not the same one. A
// program one of them starts has its starter's. No thread of the program
// that started them has any.
func TestProgramsStartedApartShareNoCore(t *testing.T) {
	one, two := sleeper(t), sleeper(t)
	apart, err := Start(one, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !apart {
		t.Skip("this machine's cores have one hardware thread each: there is nothing to keep apart")
	}
	if also, err := Start(two, nil); err != nil || !also {
		t.Fatalf("the second program: apart %v, %v", also, err)
	}
	first, err := Cookie(one.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Cookie(two.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if first == 0 || second == 0 || first == second {
		t.Fatalf("the two programs' cookies: %#x and %#x", first, second)
	}
	// What a program started apart starts is of its kind: here a shell's
	// child, found by its parent.
	shell := exec.Command("sh", "-c", "sleep 300 & wait")
	t.Cleanup(func() {
		if shell.Process != nil {
			_ = unix.Kill(-shell.Process.Pid, unix.SIGKILL)
			_ = shell.Wait()
		}
	})
	shell.SysProcAttr = &unix.SysProcAttr{Setpgid: true}
	if _, err := Start(shell, nil); err != nil {
		t.Fatal(err)
	}
	own, err := Cookie(shell.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	var child int
	for range 200 {
		data, _ := os.ReadFile("/proc/" + strconv.Itoa(shell.Process.Pid) + "/task/" + strconv.Itoa(shell.Process.Pid) + "/children")
		if fields := strings.Fields(string(data)); len(fields) > 0 {
			child, _ = strconv.Atoi(fields[0])
			break
		}
		unix.Nanosleep(&unix.Timespec{Nsec: 5e6}, nil)
	}
	if child == 0 {
		t.Skip("this kernel does not list a process's children")
	}
	if inherited, err := Cookie(child); err != nil || inherited != own || own == first || own == second {
		t.Fatalf("a program started apart has cookie %#x and its child %#x (%v)", own, inherited, err)
	}
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		tid, _ := strconv.Atoi(task.Name())
		// A thread that ended since the listing has none to ask for.
		if value, err := Cookie(tid); err == nil && value != 0 {
			t.Errorf("thread %d of the program that started them has cookie %#x", tid, value)
		}
	}
	// So a program started the plain way afterwards has none: no start
	// hands the last one's cookie on.
	for range 8 {
		plain := sleeper(t)
		if err := plain.Start(); err != nil {
			t.Fatal(err)
		}
		if value, err := Cookie(plain.Process.Pid); err != nil || value != 0 {
			t.Fatalf("a program started the plain way has cookie %#x (%v)", value, err)
		}
	}
}

// What place does to the starting thread, the program starts with, and a
// place that fails starts nothing.
func TestProgramStartsWhereItsThreadWasPlaced(t *testing.T) {
	var was unix.CPUSet
	if err := unix.SchedGetaffinity(0, &was); err != nil {
		t.Fatal(err)
	}
	var first int
	for cpu := range 1024 {
		if was.IsSet(cpu) {
			first = cpu
			break
		}
	}
	cmd := sleeper(t)
	if _, err := Start(cmd, func() error {
		var one unix.CPUSet
		one.Set(first)
		return unix.SchedSetaffinity(0, &one)
	}); err != nil {
		t.Fatal(err)
	}
	var has unix.CPUSet
	if err := unix.SchedGetaffinity(cmd.Process.Pid, &has); err != nil {
		t.Fatal(err)
	}
	if has.Count() != 1 || !has.IsSet(first) {
		t.Fatalf("the program may run on %d CPUs, and its thread was placed on CPU %d alone", has.Count(), first)
	}
	// The caller's own threads are where they were.
	var now unix.CPUSet
	if err := unix.SchedGetaffinity(0, &now); err != nil || now != was {
		t.Fatalf("the caller's thread was moved: %v", err)
	}
	refused := errors.New("no place")
	never := exec.Command("sleep", "300")
	if _, err := Start(never, func() error { return refused }); !errors.Is(err, refused) || never.Process != nil {
		t.Fatalf("a place that fails: %v, started %v", err, never.Process != nil)
	}
}
