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
	"testing"
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
