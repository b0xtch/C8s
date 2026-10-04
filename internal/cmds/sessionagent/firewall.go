package sessionagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// RulesetGuard compares the packet filter the kernel holds with the one the
// image was built to load. The filter is what keeps the guest's ports to the
// agent's one from outside, and off a command that runs in the guest's own
// network namespace. The guest's init loads it; this is the check that
// nothing replaced it since.
type RulesetGuard struct {
	// Nft is the nft binary.
	Nft string
	// Expected is the listing `nft -j list ruleset` gives for the image's
	// rules, on the measured root.
	Expected string
}

// Check fails unless the ruleset in force is the expected one.
func (g RulesetGuard) Check(ctx context.Context) error {
	want, err := session.ReadBounded(g.Expected, 1<<20)
	if err != nil {
		return fmt.Errorf("expected packet filter: %w", err)
	}
	live, err := exec.CommandContext(ctx, g.Nft, "-j", "list", "ruleset").Output()
	if err != nil {
		return fmt.Errorf("list the packet filter in force: %w", err)
	}
	wantForm, err := normalizeRuleset(want)
	if err != nil {
		return fmt.Errorf("expected packet filter: %w", err)
	}
	liveForm, err := normalizeRuleset(live)
	if err != nil {
		return fmt.Errorf("packet filter in force: %w", err)
	}
	if !bytes.Equal(wantForm, liveForm) {
		// Neither is secret, and the difference is the whole diagnosis.
		return fmt.Errorf("the packet filter in force is not the one this image loads: have %s, want %s", liveForm, wantForm)
	}
	return nil
}

// normalizeRuleset renders an nft JSON listing in one fixed form, without what
// differs between two loads of the same rules: the handles the kernel hands
// out and the tool's own version stamp.
func normalizeRuleset(data []byte) ([]byte, error) {
	var listing struct {
		Nftables []any `json:"nftables"`
	}
	if err := json.Unmarshal(data, &listing); err != nil {
		return nil, err
	}
	if len(listing.Nftables) == 0 {
		return nil, errors.New("not an nft listing")
	}
	kept := make([]any, 0, len(listing.Nftables))
	for _, item := range listing.Nftables {
		if object, ok := item.(map[string]any); ok {
			if _, stamp := object["metainfo"]; stamp {
				continue
			}
		}
		kept = append(kept, withoutHandles(item))
	}
	// encoding/json writes object members in sorted order.
	return json.Marshal(kept)
}

func withoutHandles(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, value := range v {
			if key != "handle" {
				out[key] = withoutHandles(value)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, value := range v {
			out[i] = withoutHandles(value)
		}
		return out
	default:
		return v
	}
}
