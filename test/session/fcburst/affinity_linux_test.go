package main

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// allowed is the CPUs a process started now may run on, as the kernel
// lists them.
func allowed(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("grep", "Cpus_allowed_list", "/proc/self/status").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, list, _ := strings.Cut(strings.TrimSpace(string(out)), ":")
	return strings.TrimSpace(list)
}

// A VMM is started by a thread that keeps to the VMMs' CPUs, and so keeps to
// them itself. What the same goroutine starts afterwards is where this
// program runs again.
func TestPinnedThreadStartsItsChildOnTheNamedCPUs(t *testing.T) {
	var mine unix.CPUSet
	if err := unix.SchedGetaffinity(0, &mine); err != nil {
		t.Fatal(err)
	}
	if mine.Count() < 2 {
		t.Skip("this process may run on one CPU alone")
	}
	one := -1
	for cpu := 0; one < 0; cpu++ {
		if mine.IsSet(cpu) {
			one = cpu
		}
	}
	before := allowed(t)
	pin, err := affinity(strconv.Itoa(one))
	if err != nil {
		t.Fatal(err)
	}
	restore, err := pin()
	if err != nil {
		t.Fatal(err)
	}
	during := allowed(t)
	restore()
	if during != strconv.Itoa(one) {
		t.Fatalf("a child of the pinned thread may run on CPUs %s, want %d alone", during, one)
	}
	if after := allowed(t); after != before {
		t.Fatalf("after the VMM was started, a child may run on CPUs %s, and before on %s", after, before)
	}
}
