//go:build linux

package sessionagent

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A command's cgroup that is gone before the command's group is closed, as
// when its container ended under it, holds no task to wait for: a guest
// whose sandbox ended would otherwise wait out the whole bound before it
// ends.
func TestProcessGroupClosesAtOnceOverACgroupThatIsGone(t *testing.T) {
	g := &processGroup{dir: filepath.Join(t.TempDir(), "exec-gone")}
	began := time.Now()
	g.close()
	if took := time.Since(began); took > 500*time.Millisecond {
		t.Errorf("closing a group whose cgroup is gone took %s", took)
	}
}

// One that is there is tried until the kernel lets it go, which is once it
// holds nothing, and no longer than the bound. A file in a directory stands
// for a process in a cgroup here: neither can be removed around it.
func TestProcessGroupWaitsForACgroupToEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "exec-there")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(dir, "a-process")
	if err := os.WriteFile(inside, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	const held = 150 * time.Millisecond
	emptied := time.AfterFunc(held, func() { _ = os.Remove(inside) })
	defer emptied.Stop()
	g := &processGroup{dir: dir}
	began := time.Now()
	g.close()
	if took := time.Since(began); took < held || took > held+time.Second {
		t.Errorf("closing a group whose cgroup emptied after %s took %s", held, took)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the cgroup is still there after it emptied: %v", err)
	}
	// Killing it made nothing in it: the kernel's file is written where
	// there is one, and a directory that is no cgroup is left as it is.
	other := filepath.Join(t.TempDir(), "exec-plain")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := (&processGroup{dir: other}).kill(nil); err != nil {
		t.Fatal(err)
	}
	if left, err := os.ReadDir(other); err != nil || len(left) != 0 {
		t.Errorf("a kill left %v in a directory that is no cgroup, %v", left, err)
	}
}

// One that does not empty is left when the bound is up: nothing waits on it.
func TestProcessGroupLeavesACgroupThatDoesNotEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "exec-kept-full")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a-process"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	g := &processGroup{dir: dir}
	began := time.Now()
	g.close()
	if took := time.Since(began); took < closeWait || took > closeWait+time.Second {
		t.Errorf("closing a group whose cgroup never emptied took %s, and the bound is %s", took, closeWait)
	}
}

// The agent's cgroup is weighed above what runs beside it: a cgroup made
// beside it, as the sandbox's is, keeps the kernel's own weight.
func TestAgentOutweighsWhatRunsBesideIt(t *testing.T) {
	parent, err := os.MkdirTemp(cgroupRoot, "c8s-test-weight-")
	if err != nil {
		t.Skipf("no cgroup of the test's own: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(parent) })
	if has, _ := os.ReadFile(filepath.Join(parent, "cgroup.controllers")); !slices.Contains(strings.Fields(string(has)), "cpu") {
		t.Skip("the test's cgroup has no cpu controller to hand on")
	}
	leaf, beside := filepath.Join(parent, "agent"), filepath.Join(parent, "sandbox")
	for _, dir := range []string{leaf, beside} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(dir) })
	}
	if err := weigh(parent, leaf); err != nil {
		t.Fatal(err)
	}
	for dir, want := range map[string]string{leaf: agentWeight, beside: "100"} {
		got, err := os.ReadFile(filepath.Join(dir, "cpu.weight"))
		if err != nil {
			t.Fatal(err)
		}
		if weight := strings.TrimSpace(string(got)); weight != want {
			t.Errorf("%s weighs %s, and should weigh %s", filepath.Base(dir), weight, want)
		}
	}
}

// commandGroups makes cgroups as the agent makes a command's, under one of
// the test's own, which takes the guest's root.
func commandGroups(t *testing.T, ids ...string) []*processGroup {
	t.Helper()
	parent, err := os.MkdirTemp(cgroupRoot, "c8s-test-group-")
	if err != nil {
		t.Skipf("no cgroup of the test's own: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(parent) })
	groups := make([]*processGroup, 0, len(ids))
	for _, id := range ids {
		group, err := newProcessGroup(parent, id)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = group.kill(nil)
			group.close()
		})
		groups = append(groups, group)
	}
	return groups
}

// A command's cgroup is emptied of what is put in it after its kill, as a
// process that was handed the cgroup's file could go on doing: close kills again
// until the kernel lets the cgroup go, and from then on the file puts
// nothing anywhere.
func TestGroupIsEmptiedOfWhatIsPutInAfterItsKill(t *testing.T) {
	group := commandGroups(t, "refilled")[0]
	procs, err := os.OpenFile(filepath.Join(group.dir, "cgroup.procs"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer procs.Close()
	var mu sync.Mutex
	var inside, outside []*exec.Cmd
	add := func() {
		cmd := exec.Command("sleep", "30")
		if err := cmd.Start(); err != nil {
			return
		}
		_, err := procs.WriteString(strconv.Itoa(cmd.Process.Pid))
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			inside = append(inside, cmd)
		} else {
			outside = append(outside, cmd)
		}
	}
	add()
	if err := group.kill(nil); err != nil {
		t.Fatal(err)
	}
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		for range 8 {
			add()
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	began := time.Now()
	group.close()
	took := time.Since(began)
	close(stop)
	<-stopped
	if _, err := os.Stat(group.dir); !os.IsNotExist(err) {
		t.Errorf("the cgroup is still there %s after it was closed: %v", took, err)
	}
	if took > closeWait {
		t.Errorf("closing the cgroup took %s, and its bound is %s", took, closeWait)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(inside) == 0 {
		t.Fatal("no process was put in the cgroup")
	}
	for _, cmd := range inside {
		ended := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(ended)
		}()
		select {
		case <-ended:
		case <-time.After(10 * time.Second):
			t.Errorf("process %d was put in the cgroup and outlived it", cmd.Process.Pid)
		}
	}
	// Those the removed cgroup did not take are the test's own to end.
	for _, cmd := range outside {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}
