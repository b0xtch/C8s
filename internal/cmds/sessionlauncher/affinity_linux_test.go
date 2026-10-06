//go:build linux

package sessionlauncher

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// allowedCPUs lists the CPUs the calling thread may run on.
func allowedCPUs(t *testing.T) []int {
	t.Helper()
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		t.Fatal(err)
	}
	var cpus []int
	for cpu := 0; len(cpus) < set.Count(); cpu++ {
		if set.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	return cpus
}

// readCPUs reads what a process said of its own allowed CPUs.
func readCPUs(t *testing.T, status string) []int {
	t.Helper()
	_, list, ok := strings.Cut(status, "Cpus_allowed_list:")
	if !ok {
		t.Fatalf("no allowed CPUs in %q", status)
	}
	cpus, err := parseCPUList(strings.TrimSpace(list))
	if err != nil {
		t.Fatal(err)
	}
	return cpus
}

// A process started away from a CPU may not run on it, nor may a process it
// starts in turn. The thread that started it may again.
func TestStartOnKeepsTheProcessOffTheCPUs(t *testing.T) {
	allowed := allowedCPUs(t)
	if len(allowed) < 2 {
		t.Skip("one CPU: a process cannot be kept off it")
	}
	start := func(avoid []int) (off, child, grandchild []int) {
		t.Helper()
		var out bytes.Buffer
		cmd := exec.Command("sh", "-c", "grep Cpus_allowed_list: /proc/self/status; echo --; sh -c 'grep Cpus_allowed_list: /proc/self/status'")
		cmd.Stdout = &out
		off, err := startOn(cmd, nil, avoid)
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
		own, descendant, _ := strings.Cut(out.String(), "--")
		if after := allowedCPUs(t); !slices.Equal(after, allowed) {
			t.Fatalf("after a start away from %v the caller may run on %v, was %v", avoid, after, allowed)
		}
		return off, readCPUs(t, own), readCPUs(t, descendant)
	}

	// One CPU the caller has, and one it never had.
	never := allowed[len(allowed)-1] + 1
	off, child, grandchild := start([]int{allowed[0], never})
	if !slices.Equal(off, allowed[:1]) || !slices.Equal(child, allowed[1:]) || !slices.Equal(grandchild, allowed[1:]) {
		t.Fatalf("away from %d and %d: kept off %v, the process on %v, its child on %v; want %v", allowed[0], never, off, child, grandchild, allowed[1:])
	}
	// Nothing to stay away from, and nowhere else to go.
	for name, avoid := range map[string][]int{"none": nil, "one it never had": {never}, "all it has": allowed} {
		if off, child, _ := start(avoid); len(off) != 0 || !slices.Equal(child, allowed) {
			t.Fatalf("%s: kept off %v, the process on %v; want %v", name, off, child, allowed)
		}
	}
}

// A process started on CPUs of its own may run on those and no other, and
// so may a process it starts in turn, while the thread that started it stays
// where it was. A CPU to stay away from is left out of them, unless that
// would leave none.
func TestStartOnKeepsTheProcessToItsCPUs(t *testing.T) {
	allowed := allowedCPUs(t)
	if len(allowed) < 3 {
		t.Skip("fewer than three CPUs: a process cannot be kept to some of them and off one of those")
	}
	start := func(keep, avoid []int) (off, child, grandchild []int) {
		t.Helper()
		var out bytes.Buffer
		cmd := exec.Command("sh", "-c", "grep Cpus_allowed_list: /proc/self/status; echo --; sh -c 'grep Cpus_allowed_list: /proc/self/status'")
		cmd.Stdout = &out
		off, err := startOn(cmd, keep, avoid)
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
		own, descendant, _ := strings.Cut(out.String(), "--")
		if after := allowedCPUs(t); !slices.Equal(after, allowed) {
			t.Fatalf("after a start on %v the caller may run on %v, was %v", keep, after, allowed)
		}
		return off, readCPUs(t, own), readCPUs(t, descendant)
	}
	keep := allowed[1:]
	if off, child, grandchild := start(keep, nil); len(off) != 0 || !slices.Equal(child, keep) || !slices.Equal(grandchild, keep) {
		t.Fatalf("on %v: kept off %v, the process on %v, its child on %v", keep, off, child, grandchild)
	}
	// Away from one of its own, and from one that was never among them.
	if off, child, _ := start(keep, []int{allowed[0], keep[0]}); !slices.Equal(off, keep[:1]) || !slices.Equal(child, keep[1:]) {
		t.Fatalf("on %v away from %d and %d: kept off %v, the process on %v", keep, allowed[0], keep[0], off, child)
	}
	// Away from all it was to keep to, it keeps to them.
	if off, child, _ := start(keep[:1], keep[:1]); len(off) != 0 || !slices.Equal(child, keep[:1]) {
		t.Fatalf("on %v away from the same: kept off %v, the process on %v", keep[:1], off, child)
	}
	// CPUs the machine does not have are no place to start anything.
	cmd := exec.Command("true")
	if _, err := startOn(cmd, []int{maxCPUs - 1}, nil); err == nil {
		_ = cmd.Wait()
		t.Fatal("a process was started on a CPU no machine has")
	}
}

// Run starts the VMM on the CPUs it is told to keep the VMM to, and stays
// where it was itself. A list that is none is refused before anything is
// started.
func TestRunKeepsTheVMMToItsCPUs(t *testing.T) {
	allowed := allowedCPUs(t)
	if len(allowed) < 2 {
		t.Skip("one CPU: a VMM cannot be kept to fewer than its launcher has")
	}
	real := sysfsRoot
	t.Cleanup(func() { sysfsRoot = real })
	sysfsRoot = t.TempDir()
	qemu, record := fakeQEMU(t, `grep Cpus_allowed_list: /proc/self/status > "$record/cpus"; exec sleep 30`)
	cfg := launchConfig(t, qemu)
	cfg.AvoidFirstCPU = false
	cfg.VMMCPUs = strconv.Itoa(allowed[1])
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var said bytes.Buffer
	go func() { done <- Run(ctx, cfg, slog.New(slog.NewJSONHandler(&said, nil))) }()
	waitFor(t, filepath.Join(record, "cpus"), done)
	status, err := os.ReadFile(filepath.Join(record, "cpus"))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := readCPUs(t, string(status)); !slices.Equal(got, allowed[1:2]) {
		t.Fatalf("the VMM may run on %v, want %v", got, allowed[1:2])
	}
	if after := allowedCPUs(t); !slices.Equal(after, allowed) {
		t.Fatalf("the launcher may run on %v after it started its VMM, was %v", after, allowed)
	}
	if want := fmt.Sprintf(`"msg":"the VMM keeps to CPUs of its own","cpus":"%d"`, allowed[1]); !strings.Contains(said.String(), want) {
		t.Fatalf("the launcher did not say where its VMM runs:\n%s", said.String())
	}

	for _, list := range []string{"3-1", "x", "1,1", "2-"} {
		qemu, record := fakeQEMU(t, "exec sleep 30")
		cfg := launchConfig(t, qemu)
		cfg.VMMCPUs = list
		if err := Run(context.Background(), cfg, quiet); err == nil || !strings.Contains(err.Error(), "--vmm-cpus") {
			t.Fatalf("CPUs %q: Run = %v", list, err)
		}
		if _, err := os.Stat(filepath.Join(record, "args")); err == nil {
			t.Fatalf("CPUs %q: the VMM was started", list)
		}
	}
}

// Only a TDX guest's VMM is kept off a CPU, and only by a launcher that was
// not told otherwise.
func TestAvoidCPUs(t *testing.T) {
	real := sysfsRoot
	t.Cleanup(func() { sysfsRoot = real })
	sysfsRoot = fakeSysfs(t, "0-3", map[int]string{0: "0", 1: "0", 2: "1", 3: "1"})
	for name, tc := range map[string]struct {
		cfg  Config
		want []int
	}{
		"tdx":            {Config{Platform: "tdx", AvoidFirstCPU: true}, []int{0, 2}},
		"snp":            {Config{Platform: "snp", AvoidFirstCPU: true}, nil},
		"told otherwise": {Config{Platform: "tdx"}, nil},
	} {
		if got, err := tc.cfg.avoidCPUs(); err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, %v; want %v", name, got, err, tc.want)
		}
	}
}

// Run keeps a TDX guest's VMM off the first CPU of each package. A launcher
// told to leave the VMM where it is runs it on every CPU the launcher has.
func TestRunKeepsTheVMMOffTheFirstCPUOfEachPackage(t *testing.T) {
	allowed := allowedCPUs(t)
	if len(allowed) < 2 {
		t.Skip("one CPU: a process cannot be kept off it")
	}
	// A machine of one package, whose CPUs are the launcher's own.
	online := make([]string, len(allowed))
	packages := map[int]string{}
	for i, cpu := range allowed {
		online[i], packages[cpu] = strconv.Itoa(cpu), "0"
	}
	real := sysfsRoot
	t.Cleanup(func() { sysfsRoot = real })

	for name, tc := range map[string]struct {
		change func(*Config)
		sysfs  string
		want   []int
	}{
		"a TDX guest":          {nil, fakeSysfs(t, strings.Join(online, ","), packages), allowed[1:]},
		"told otherwise":       {func(c *Config) { c.AvoidFirstCPU = false }, t.TempDir(), allowed},
		"a first CPU not ours": {nil, fakeSysfs(t, strconv.Itoa(allowed[len(allowed)-1]+1), map[int]string{allowed[len(allowed)-1] + 1: "0"}), allowed},
	} {
		t.Run(name, func(t *testing.T) {
			qemu, record := fakeQEMU(t, `grep Cpus_allowed_list: /proc/self/status > "$record/cpus"; exec sleep 30`)
			cfg := launchConfig(t, qemu)
			cfg.AvoidFirstCPU = true
			if tc.change != nil {
				tc.change(&cfg)
			}
			sysfsRoot = tc.sysfs
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			var said bytes.Buffer
			go func() { done <- Run(ctx, cfg, slog.New(slog.NewJSONHandler(&said, nil))) }()
			waitFor(t, filepath.Join(record, "cpus"), done)
			status, err := os.ReadFile(filepath.Join(record, "cpus"))
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatalf("Run: %v", err)
			}
			if got := readCPUs(t, string(status)); !slices.Equal(got, tc.want) {
				t.Fatalf("the VMM may run on %v, want %v", got, tc.want)
			}
			// It says which CPUs it kept the VMM off, when it kept it off any.
			const msg = `"msg":"the VMM is kept off the first CPU of each package"`
			line := fmt.Sprintf(`%s,"cpus":[%d]`, msg, allowed[0])
			if kept := len(tc.want) < len(allowed); strings.Contains(said.String(), line) != kept || strings.Contains(said.String(), msg) != kept {
				t.Fatalf("kept off a CPU: %v; the launcher said:\n%s", kept, said.String())
			}
		})
	}

	// A machine the launcher cannot read is not guessed at.
	t.Run("no sysfs", func(t *testing.T) {
		qemu, record := fakeQEMU(t, "exec sleep 30")
		cfg := launchConfig(t, qemu)
		cfg.AvoidFirstCPU = true
		sysfsRoot = t.TempDir()
		if err := Run(context.Background(), cfg, quiet); err == nil || !strings.Contains(err.Error(), "--avoid-first-cpu") {
			t.Fatalf("Run = %v", err)
		}
		if _, err := os.Stat(filepath.Join(record, "args")); err == nil {
			t.Fatal("the VMM was started")
		}
	})
}
