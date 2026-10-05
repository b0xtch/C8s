//go:build linux

package sessiond

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// fakeLauncher is a launcher that writes down what it was asked to run and
// then stays, as a launcher stays for the life of its guest.
func fakeLauncher(t *testing.T) (path, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	path = filepath.Join(dir, "launcher")
	script := "#!/bin/sh\necho \"$@\" > " + argsFile + "\nexec sleep 300\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, argsFile
}

func userRunner(t *testing.T, self string) (*QEMURunner, Spec) {
	t.Helper()
	cfg := &Config{
		StateDir: "/state",
		Network:  Network{Mode: NetworkUser, FirstPort: 39000},
		VMM:      VMM{QuoteSocket: "/run/qgs.socket", Confine: "64055"},
	}
	pool := &Pool{ImageDir: "/images/session", LaunchDir: "/bundle/opkeydata", ImageStore: "/store/images.store", platform: "tdx"}
	spec := Spec{ID: "td-test", Dir: t.TempDir(), Slot: 3, Pool: pool, Class: Class{VCPUs: 4, Memory: "16G", Scratch: "8G"}}
	return &QEMURunner{cfg: cfg, log: slog.New(slog.NewTextHandler(io.Discard, nil)), self: self}, spec
}

func gone(t *testing.T, inst Instance, what string) {
	t.Helper()
	select {
	case <-inst.Done():
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: its process is still there", what)
	}
}

// A TD's launcher is started with the pool's and the class's settings, runs
// in a session of its own, is found again by a later daemon, and is ended on
// the daemon's word.
func TestRunnerStartsAdoptsAndStops(t *testing.T) {
	self, argsFile := fakeLauncher(t)
	runner, spec := userRunner(t, self)
	inst, err := runner.Start(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inst.Stop)
	if inst.Address() != "127.0.0.1:39003" {
		t.Fatalf("the TD of slot 3 is reached at %s", inst.Address())
	}
	handle := inst.Handle()
	if handle.PID <= 0 || handle.Start == 0 {
		t.Fatalf("the launcher's handle is %+v", handle)
	}
	var args string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if data, err := os.ReadFile(argsFile); err == nil && len(data) > 0 {
			args = strings.TrimSpace(string(data))
			break
		}
	}
	want := "session-launcher run --platform tdx --image-dir /images/session --launch-dir /bundle/opkeydata" +
		" --work-dir " + filepath.Join(spec.Dir, workDir) + " --name td-test --vcpus 4 --memory 16G --vsock-cid auto" +
		" --collateral-cache /state/collateral" +
		" --quote-socket /run/qgs.socket --confine 64055 --scratch 8G --image-store /store/images.store" +
		" --network user --port 127.0.0.1:39003:8443"
	if args != want {
		t.Fatalf("the launcher was started with\n %s\nwant\n %s", args, want)
	}
	// The launcher leads a session of its own: it outlives the daemon.
	if sid, err := unix.Getsid(handle.PID); err != nil || sid != handle.PID {
		t.Fatalf("the launcher's session is %d, %v", sid, err)
	}

	// A later daemon finds it by its handle, and not by a handle that names
	// another process of the same id.
	adopted, err := runner.Adopt(spec, handle)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if adopted.Address() != inst.Address() {
		t.Fatalf("the adopted TD is reached at %s", adopted.Address())
	}
	if _, err := runner.Adopt(spec, Handle{PID: handle.PID, Start: handle.Start + 1}); err == nil {
		t.Fatal("a handle of another start time was adopted")
	}
	if _, err := runner.Adopt(spec, Handle{PID: handle.PID}); err == nil {
		t.Fatal("a handle with no start time was adopted")
	}
	select {
	case <-adopted.Done():
		t.Fatal("the adopted TD is taken for gone while it runs")
	case <-time.After(2 * gonePoll):
	}

	adopted.Stop()
	gone(t, adopted, "the adopted TD after its stop")
	gone(t, inst, "the TD after its stop")
	// Stopping what is gone is nothing.
	inst.Stop()
	adopted.Stop()
	if _, err := runner.Adopt(spec, handle); err == nil {
		t.Fatal("a launcher that is gone was adopted")
	}
}

// A launcher that takes no notice of its stop is killed with its group once
// its grace is over. Here it ignores the signal for good, so the test runs
// the group kill itself.
func TestRunnerWaitsForTheWholeGroup(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "launcher")
	// A launcher whose child, the VMM, outlives it.
	script := "#!/bin/sh\nsleep 300 &\necho $! > " + filepath.Join(dir, "child") + "\nwait\n"
	if err := os.WriteFile(self, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	runner, spec := userRunner(t, self)
	inst, err := runner.Start(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	var child string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if data, err := os.ReadFile(filepath.Join(dir, "child")); err == nil && len(data) > 1 {
			child = strings.TrimSpace(string(data))
			break
		}
	}
	if child == "" {
		t.Fatal("the launcher started no child")
	}
	// The shell dies of the signal and leaves its child behind.
	inst.Stop()
	select {
	case <-inst.Done():
		t.Fatal("the TD is taken for gone while its VMM runs")
	case <-time.After(4 * gonePoll):
	}
	if _, err := os.Stat("/proc/" + child); err != nil {
		t.Fatalf("the child is gone already: %v", err)
	}
	if err := syscall.Kill(-inst.Handle().PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	gone(t, inst, "the TD once its group was killed")
}

func TestProcessStart(t *testing.T) {
	own, err := processStart(os.Getpid())
	if err != nil || own == 0 {
		t.Fatalf("this process's start: %d, %v", own, err)
	}
	if again, err := processStart(os.Getpid()); err != nil || again != own {
		t.Fatalf("this process's start read twice: %d and %d, %v", own, again, err)
	}
	if _, err := processStart(1 << 30); err == nil {
		t.Fatal("a process that is not there has a start time")
	}
}

// The host asks a guest's end of its tap for its Ethernet address every few
// milliseconds until it answers, where the kernel would ask once a second: a
// guest is reached as it comes up.
func TestTapAsksForItsGuestOften(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make a tap")
	}
	const slot = 3
	host, _, err := slotAddresses(netip.MustParsePrefix("10.99.7.0/24"), slot)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		// A network namespace of this test's own. The thread that enters it
		// never leaves, and ends with this goroutine.
		runtime.LockOSThread()
		done <- func() error {
			if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
				return fmt.Errorf("a network namespace: %w", err)
			}
			tap, vhost, err := (&QEMURunner{}).tap(slot, host)
			if err != nil {
				return err
			}
			defer tap.Close()
			if vhost != nil {
				defer vhost.Close()
			}
			link, err := netlink.LinkByName(tapName(slot))
			if err != nil {
				return err
			}
			addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
			if err != nil || len(addrs) != 1 || !addrs[0].IP.Equal(net.IP(host.AsSlice())) {
				return fmt.Errorf("the host's end has addresses %v, %v", addrs, err)
			}
			every, err := os.ReadFile("/proc/sys/net/ipv4/neigh/" + tapName(slot) + "/retrans_time_ms")
			if err != nil || strings.TrimSpace(string(every)) != tapAskEvery {
				return fmt.Errorf("the guest's end is asked every %q ms, %v: want %s", every, err, tapAskEvery)
			}
			return nil
		}()
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
