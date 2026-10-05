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

// countingNft is an nft that lists listing and counts how often it is asked.
func countingNft(t *testing.T, listing func() string) (path string, asked func() int) {
	t.Helper()
	dir := t.TempDir()
	count := filepath.Join(dir, "asked")
	out := filepath.Join(dir, "listing")
	path = filepath.Join(dir, "nft")
	script := "#!/bin/sh\necho x >> " + count + "\ncat " + out + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func() {
		if err := os.WriteFile(out, []byte(listing()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write()
	return path, func() int {
		write()
		data, err := os.ReadFile(count)
		if err != nil {
			return 0
		}
		return len(data) / 2
	}
}

// A guest lists its packet filter once and from then on asks the kernel only
// whether anything changed it. While the kernel's count of changes stands
// where it stood around a listing that passed, a check lists nothing. A count
// that moved has the filter listed again, and so does one that moved while
// the filter was being listed, a count that cannot be read, and a listing
// that did not pass.
func TestRulesetWatchListsAgainOnlyWhenTheFilterChanged(t *testing.T) {
	if _, err := os.Stat(expectedRuleset); errors.Is(err, fs.ErrNotExist) {
		t.Skip("needs the guest image profile: run from a checkout")
	}
	ctx := context.Background()
	listing := asKernelLists(t, nil)
	nft, asked := countingNft(t, func() string { return listing })
	generation, failing := uint32(7), false
	var moving func()
	watch := &RulesetWatch{
		Guard: RulesetGuard{Nft: nft, Expected: expectedRuleset},
		Generation: func() (uint32, error) {
			if failing {
				return 0, errors.New("no netlink")
			}
			now := generation
			if moving != nil {
				moving()
			}
			return now, nil
		},
	}
	check := func(what string, want int) {
		t.Helper()
		if err := watch.Check(ctx); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if got := asked(); got != want {
			t.Fatalf("%s: the filter was listed %d times, want %d", what, got, want)
		}
	}
	check("the first check", 1)
	check("a check with nothing changed", 1)
	check("another", 1)

	// A change that takes effect, whatever it leaves behind.
	generation++
	check("a check after a change that was undone", 2)
	check("a check with nothing changed since", 2)

	// A change while the filter is listed: that listing stands for nothing.
	generation++
	moving = func() { generation++; moving = nil }
	check("a check while the filter changes", 3)
	check("the check after it", 4)
	check("a check with nothing changed since", 4)

	// A kernel that does not say: the filter is listed every time.
	failing = true
	check("a check with no count", 5)
	check("another", 6)
	failing = false
	check("a check once the count is back", 7)
	check("a check with nothing changed since", 7)

	// A filter that is not the image's is refused, and nothing is held for
	// the count it was listed under.
	generation++
	listing = asKernelLists(t, func(items []nftItem) []nftItem { return items[:len(items)-1] })
	asked()
	if err := watch.Check(ctx); err == nil {
		t.Fatal("a filter with a rule gone passed")
	}
	if err := watch.Check(ctx); err == nil {
		t.Fatal("the same filter passed the second time, under the count it was refused under")
	}
	listing = asKernelLists(t, nil)
	if got := asked(); got != 9 {
		t.Fatalf("a refused filter was listed %d times in two checks, want 2", got-7)
	}
	check("the image's filter again, under the same count", 10)
	check("a check with nothing changed since", 10)

	// With no count to ask for, every check lists.
	plain := &RulesetWatch{Guard: RulesetGuard{Nft: nft, Expected: expectedRuleset}}
	for range 2 {
		if err := plain.Check(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := asked(); got != 12 {
		t.Fatalf("a watch with no count listed %d times in two checks", got-10)
	}
}
