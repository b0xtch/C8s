//go:build linux

package sessionagent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// TestImageRulesetPassesTheGuard loads the image's rules with the real nft,
// in a network namespace of its own, and holds the guard to what the kernel
// then lists: the check a guest makes before it serves.
func TestImageRulesetPassesTheGuard(t *testing.T) {
	if _, err := os.Stat(loadedRuleset); errors.Is(err, fs.ErrNotExist) {
		t.Skip("needs the guest image profile: run from a checkout")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to make a network namespace")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("needs ip to make a network namespace")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("needs nft to load the rules")
	}
	ns := fmt.Sprintf("c8s-filter-%d", os.Getpid())
	if out, err := exec.Command(ip, "netns", "add", ns).CombinedOutput(); err != nil {
		t.Fatalf("make a network namespace: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command(ip, "netns", "del", ns).Run() })
	if out, err := exec.Command(ip, "netns", "exec", ns, nft, "-f", loadedRuleset).CombinedOutput(); err != nil {
		t.Fatalf("load the image's rules: %v: %s", err, out)
	}
	inside := filepath.Join(t.TempDir(), "nft")
	script := fmt.Sprintf("#!/bin/sh\nexec %s netns exec %s %s \"$@\"\n", ip, ns, nft)
	if err := os.WriteFile(inside, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := (RulesetGuard{Nft: inside, Expected: expectedRuleset}).Check(context.Background()); err != nil {
		t.Fatalf("the rules the image loads are not the ones its guard expects: %v", err)
	}
}

// The kernel's count of a namespace's filter moves with every change that
// takes effect and with nothing else, which is what a guest's repeated check
// leans on: the image's rules pass once, by their listing, and are listed
// again only after something changed them, even if it put them back.
func TestRulesetWatchFollowsTheKernelsCount(t *testing.T) {
	if _, err := os.Stat(loadedRuleset); errors.Is(err, fs.ErrNotExist) {
		t.Skip("needs the guest image profile: run from a checkout")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to make a network namespace")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("needs nft to load the rules")
	}
	// A network namespace for this thread alone, which ends with it: the
	// thread is never unlocked. What it starts runs in the namespace too.
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			t.Errorf("a network namespace of its own: %v", err)
			return
		}
		run := func(args ...string) bool {
			out, err := exec.Command(nft, args...).CombinedOutput()
			if err != nil {
				t.Errorf("nft %v: %v: %s", args, err, out)
			}
			return err == nil
		}
		empty, err := rulesetGeneration()
		if err != nil {
			t.Errorf("the count of an empty filter: %v", err)
			return
		}
		if again, err := rulesetGeneration(); err != nil || again != empty {
			t.Errorf("the count moved with nothing changed: %d then %d (%v)", empty, again, err)
			return
		}
		if !run("-f", loadedRuleset) {
			return
		}
		loaded, err := rulesetGeneration()
		if err != nil || loaded == empty {
			t.Errorf("the count did not move when the rules were loaded: %d then %d (%v)", empty, loaded, err)
			return
		}

		dir := t.TempDir()
		counted := filepath.Join(dir, "nft")
		script := fmt.Sprintf("#!/bin/sh\necho x >> %s\nexec %s \"$@\"\n", filepath.Join(dir, "asked"), nft)
		if err := os.WriteFile(counted, []byte(script), 0o755); err != nil {
			t.Error(err)
			return
		}
		listed := func() int {
			data, _ := os.ReadFile(filepath.Join(dir, "asked"))
			return len(data) / 2
		}
		watch := &RulesetWatch{Guard: RulesetGuard{Nft: counted, Expected: expectedRuleset}, Generation: rulesetGeneration}
		for i := range 3 {
			if err := watch.Check(context.Background()); err != nil {
				t.Errorf("check %d of the image's rules: %v", i+1, err)
				return
			}
		}
		if listed() != 1 {
			t.Errorf("three checks of an unchanged filter listed it %d times, want 1", listed())
			return
		}
		// A listing changes nothing.
		if !run("list", "ruleset") {
			return
		}
		if now, err := rulesetGeneration(); err != nil || now != loaded {
			t.Errorf("the count moved when the filter was listed: %d then %d (%v)", loaded, now, err)
			return
		}
		// A table more is another filter, and the next check sees it.
		if !run("add", "table", "inet", "stranger") {
			return
		}
		if err := watch.Check(context.Background()); err == nil {
			t.Error("a filter with a table more passed")
			return
		}
		// Put back as it was, it passes again, by a listing.
		if !run("delete", "table", "inet", "stranger") {
			return
		}
		before := listed()
		for range 2 {
			if err := watch.Check(context.Background()); err != nil {
				t.Errorf("the image's rules after a change that was undone: %v", err)
				return
			}
		}
		if listed() != before+1 {
			t.Errorf("two checks after a change that was undone listed the filter %d times, want 1", listed()-before)
		}
	}()
	<-done
}
