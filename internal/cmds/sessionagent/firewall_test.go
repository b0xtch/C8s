package sessionagent

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The image's own expected listing, as it ships on the measured root.
const expectedRuleset = "../../../session-guest-image/c8s-session/mkosi.extra/etc/c8s-session/firewall.json"

// fakeNft is an nft that prints a fixed listing when asked for the ruleset.
func fakeNft(t *testing.T, listing string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "listing.json"), []byte(listing), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "nft")
	script := "#!/bin/sh\n[ \"$1 $2 $3\" = \"-j list ruleset\" ] || exit 64\ncat " + filepath.Join(dir, "listing.json") + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

type nftItem = map[string]map[string]any

// asKernelLists returns the image's rules the way a kernel reports them: a
// version stamp in front and a handle of its own choosing on every object.
// mutate may change the rules first.
func asKernelLists(t *testing.T, mutate func([]nftItem) []nftItem) string {
	t.Helper()
	data, err := os.ReadFile(expectedRuleset)
	if err != nil {
		t.Fatal(err)
	}
	var listing struct {
		Nftables []nftItem `json:"nftables"`
	}
	if err := json.Unmarshal(data, &listing); err != nil {
		t.Fatal(err)
	}
	items := listing.Nftables
	if mutate != nil {
		items = mutate(items)
	}
	out := []any{map[string]any{"metainfo": map[string]any{"version": "9.9.9", "release_name": "x", "json_schema_version": 1}}}
	for i, item := range items {
		for _, object := range item {
			object["handle"] = 40 + i
		}
		out = append(out, item)
	}
	rendered, err := json.Marshal(map[string]any{"nftables": out})
	if err != nil {
		t.Fatal(err)
	}
	return string(rendered)
}

func TestRulesetGuard(t *testing.T) {
	if _, err := os.Stat(expectedRuleset); errors.Is(err, fs.ErrNotExist) {
		t.Skip("needs the guest image profile: run from a checkout")
	}
	check := func(listing string) error {
		return RulesetGuard{Nft: fakeNft(t, listing), Expected: expectedRuleset}.Check(context.Background())
	}
	if err := check(asKernelLists(t, nil)); err != nil {
		t.Fatalf("the image's own rules, as a kernel lists them: %v", err)
	}
	for name, mutate := range map[string]func([]nftItem) []nftItem{
		"flushed": func([]nftItem) []nftItem { return nil },
		"the distribution's skeleton": func([]nftItem) []nftItem {
			return []nftItem{
				{"table": {"family": "inet", "name": "filter"}},
				{"chain": {"family": "inet", "table": "filter", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
			}
		},
		"input policy accept": func(items []nftItem) []nftItem {
			for _, item := range items {
				if chain, ok := item["chain"]; ok && chain["name"] == "input" {
					chain["policy"] = "accept"
				}
			}
			return items
		},
		"another port open": func(items []nftItem) []nftItem {
			return append(items, nftItem{"rule": {"family": "inet", "table": "c8s_session", "chain": "input", "expr": []any{map[string]any{"accept": nil}}}})
		},
		"the rule that keeps the sandbox off the agent is gone": func(items []nftItem) []nftItem {
			last := items[len(items)-1]["rule"]
			if last == nil || last["chain"] != "output" {
				t.Fatal("fixture: the last rule is not the output chain's")
			}
			return items[:len(items)-1]
		},
		"rules in another order": func(items []nftItem) []nftItem {
			n := len(items)
			items[n-2], items[n-3] = items[n-3], items[n-2]
			return items
		},
		"a table besides the image's": func(items []nftItem) []nftItem {
			return append([]nftItem{{"table": {"family": "ip", "name": "nat"}}}, items...)
		},
	} {
		if err := check(asKernelLists(t, mutate)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := check("nft: command failed"); err == nil {
		t.Error("output that is no listing passed the check")
	}
	// An nft that cannot be run is a failure, and so is a missing expectation.
	if err := (RulesetGuard{Nft: filepath.Join(t.TempDir(), "absent"), Expected: expectedRuleset}).Check(context.Background()); err == nil {
		t.Error("a missing nft passed the check")
	}
	if err := (RulesetGuard{Nft: fakeNft(t, asKernelLists(t, nil)), Expected: filepath.Join(t.TempDir(), "absent")}).Check(context.Background()); err == nil {
		t.Error("a missing expectation passed the check")
	}
}

// The rules the image loads, beside the listing the guard holds them to.
const loadedRuleset = "../../../session-guest-image/c8s-session/mkosi.extra/etc/c8s-session/firewall.nft"

// The guard compares a kernel's listing with a file, and the image loads its
// rules from another: a guest whose two files name different tables refuses
// to serve. This runs where no nft does.
func TestExpectedRulesetNamesTheLoadedTable(t *testing.T) {
	rules, err := os.ReadFile(loadedRuleset)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("needs the guest image profile: run from a checkout")
	}
	if err != nil {
		t.Fatal(err)
	}
	declared := regexp.MustCompile(`(?m)^table (\S+) (\S+) \{`).FindAllSubmatch(rules, -1)
	if len(declared) != 1 {
		t.Fatalf("the image's rules declare %d tables, want one", len(declared))
	}
	data, err := os.ReadFile(expectedRuleset)
	if err != nil {
		t.Fatal(err)
	}
	var listing struct {
		Nftables []nftItem `json:"nftables"`
	}
	if err := json.Unmarshal(data, &listing); err != nil {
		t.Fatal(err)
	}
	family, name := string(declared[0][1]), string(declared[0][2])
	for i, item := range listing.Nftables {
		for kind, object := range item {
			table := object["table"]
			if kind == "table" {
				table = object["name"]
			}
			if object["family"] != family || table != name {
				t.Errorf("item %d of the expected listing (%s) is in %v %v, and the image loads %s %s", i, kind, object["family"], table, family, name)
			}
		}
	}
}
