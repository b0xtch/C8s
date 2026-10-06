//go:build linux

package sessionagent

import (
	"os"
	"path/filepath"
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

// One that is there is waited for until the kernel says it holds no task,
// and removed then.
func TestProcessGroupWaitsForACgroupToEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "exec-there")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, "cgroup.events")
	if err := os.WriteFile(events, []byte("populated 1\nfrozen 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const held = 150 * time.Millisecond
	emptied := time.AfterFunc(held, func() {
		_ = os.WriteFile(events, []byte("populated 0\nfrozen 0\n"), 0o644)
	})
	defer emptied.Stop()
	g := &processGroup{dir: dir}
	began := time.Now()
	g.close()
	if took := time.Since(began); took < held || took > held+time.Second {
		t.Errorf("closing a group whose cgroup emptied after %s took %s", held, took)
	}
}
