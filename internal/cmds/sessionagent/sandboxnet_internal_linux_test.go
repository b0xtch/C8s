//go:build linux

package sessionagent

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A sandbox's namespace is made with a loopback and nothing else. Anything
// more is a way out that the proxy's rules do not cover, such as the tunnel
// device a kernel with a tunnel driver adds to every new namespace.
func TestOnlyLoopback(t *testing.T) {
	lo := net.Interface{Index: 1, Name: "lo", Flags: net.FlagLoopback}
	if err := onlyLoopback([]net.Interface{lo}); err != nil {
		t.Errorf("a namespace with its loopback alone: %v", err)
	}
	if err := onlyLoopback(nil); err != nil {
		t.Errorf("a namespace with no interface: %v", err)
	}
	sit := net.Interface{Index: 2, Name: "sit0"}
	eth := net.Interface{Index: 3, Name: "eth0", Flags: net.FlagUp | net.FlagBroadcast}
	err := onlyLoopback([]net.Interface{lo, sit, eth})
	if err == nil || !strings.Contains(err.Error(), "sit0, eth0") {
		t.Errorf("a namespace with a tunnel and an ethernet device: %v, want a refusal naming both", err)
	}
}

// The agent makes the sandbox's namespaces and then has the kernel make no
// user namespace again. A process is the sandbox's only if it runs in both.
func TestSandboxNamespacesAreTheLast(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make a user namespace with a mapped id range")
	}
	// TestMain pointed the limit at a file of the test binary's.
	if userNamespaceLimit == "/proc/sys/user/max_user_namespaces" {
		t.Fatal("this test would close the machine it runs on to user namespaces")
	}
	if err := os.WriteFile(userNamespaceLimit, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := newSandboxNet()
	if err != nil {
		t.Skipf("no namespaces here: %v", err)
	}
	defer n.Close()
	if got, err := os.ReadFile(userNamespaceLimit); err != nil || string(got) != "0" {
		t.Fatalf("the limit on user namespaces is %q after the sandbox's was made, %v", got, err)
	}

	// This process is in neither.
	if err := n.holds("/proc/self"); err == nil || !strings.Contains(err.Error(), "user namespace") {
		t.Fatalf("the test's own process: %v", err)
	}
	nsenter, err := exec.LookPath("nsenter")
	if err != nil {
		t.Skip("needs nsenter to start a process in the namespaces")
	}
	at := n.paths()
	inside := func(args ...string) *exec.Cmd {
		t.Helper()
		cmd := exec.Command(nsenter, append(args, "sleep", "30")...)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		// nsenter becomes sleep once it has entered.
		proc := fmt.Sprintf("/proc/%d", cmd.Process.Pid)
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			if comm, _ := os.ReadFile(proc + "/comm"); strings.TrimSpace(string(comm)) == "sleep" {
				return cmd
			}
			if time.Now().After(deadline) {
				t.Fatalf("nsenter %v did not become sleep", args)
			}
		}
	}
	both := inside("--user="+at.User, "--net="+at.Network, "--preserve-credentials")
	if err := n.holds(fmt.Sprintf("/proc/%d", both.Process.Pid)); err != nil {
		t.Fatalf("a process in both namespaces: %v", err)
	}
	userOnly := inside("--user="+at.User, "--preserve-credentials")
	if err := n.holds(fmt.Sprintf("/proc/%d", userOnly.Process.Pid)); err == nil || !strings.Contains(err.Error(), "net namespace") {
		t.Fatalf("a process in the user namespace alone: %v", err)
	}
	netOnly := inside("--net=" + at.Network)
	if err := n.holds(fmt.Sprintf("/proc/%d", netOnly.Process.Pid)); err == nil || !strings.Contains(err.Error(), "user namespace") {
		t.Fatalf("a process in the network namespace alone: %v", err)
	}
	if err := n.holds("/proc/0"); err == nil {
		t.Fatal("a process that does not exist is held")
	}
}

// A guest whose limit cannot be set gets no sandbox namespaces: what they
// promise depends on it.
func TestSandboxNamespacesNeedTheLimit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make a user namespace with a mapped id range")
	}
	defer func(path string) { userNamespaceLimit = path }(userNamespaceLimit)
	userNamespaceLimit = filepath.Join(t.TempDir(), "absent", "max_user_namespaces")
	if n, err := newSandboxNet(); err == nil {
		_ = n.Close()
		t.Fatal("namespaces were made in a guest that stays open to more")
	}
}
