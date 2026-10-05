//go:build c8s_simtee

package sessioncli

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/simtee"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// run runs one command of the session tree to its end.
func run(ctx context.Context, args ...string) (string, error) {
	cmd := NewCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(ctx)
	return out.String(), err
}

// simulatedQuote is evidence of a guest launched from the authority in dir,
// as a guest puts it in an envelope.
func simulatedQuote(t *testing.T, dir string, reportData []byte) teetypes.AttestationEvidence {
	t.Helper()
	authority, err := simtee.LoadDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	hardware, err := authority.NewHardware(sha512.Sum384([]byte("firmware")), sha512.Sum384([]byte("kernel")), sha512.Sum384([]byte("boot")), "a shape")
	if err != nil {
		t.Fatal(err)
	}
	machine, err := hardware.Boot()
	if err != nil {
		t.Fatal(err)
	}
	var bound [64]byte
	copy(bound[:], reportData)
	quote, err := machine.Quote([48]byte{}, bound)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"quote": base64.StdEncoding.EncodeToString(quote)})
	if err != nil {
		t.Fatal(err)
	}
	return teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: body}
}

// 'simtee new' makes an authority, 'simtee vendor' serves its documents and
// says where in the directory, and a command given the directory judges a
// guest of that authority under it: with no word from Intel's service, and
// with nothing kept among Intel's documents. A command given no directory
// judges as any build's does, and refuses that guest.
func TestCommandsJudgeUnderTheSimulatedAuthorityTheyAreGiven(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "authority")
	out, err := run(context.Background(), "simtee", "new", "--out", dir)
	if err != nil || !strings.Contains(out, "protects nothing") {
		t.Fatalf("simtee new: %v\n%s", err, out)
	}
	if _, err := run(context.Background(), "simtee", "new", "--out", dir); err == nil {
		t.Fatal("an authority was made over another")
	}
	// Before anybody serves its documents, a command says so and judges
	// nothing.
	reportData := []byte("what the guest binds")
	env := simulatedQuote(t, dir, reportData)
	cache := t.TempDir()
	judging := &trust{collateralCache: cache, simulated: simulatedTrust{dir: dir}}
	var verdict *session.VerificationError
	if _, err := judging.engine().VerifyEvidence(context.Background(), env, reportData); err == nil || errors.As(err, &verdict) ||
		!strings.Contains(err.Error(), "--simulated-tee") || !strings.Contains(err.Error(), "nobody serves its documents") {
		t.Fatalf("a command whose authority nobody serves: %v", err)
	}

	ctx, stop := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		_, err := run(ctx, "simtee", "vendor", "--dir", dir)
		served <- err
	}()
	address := filepath.Join(dir, simtee.VendorFile)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(address); err == nil {
			break
		}
		select {
		case err := <-served:
			t.Fatalf("simtee vendor ended: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("simtee vendor wrote no address")
		}
	}
	res, err := judging.engine().VerifyEvidence(context.Background(), env, reportData)
	if err != nil {
		t.Fatalf("a guest of the authority, judged under it: %v", err)
	}
	if finding := session.CollateralOf(res); finding == nil || !finding.UpToDate() || finding.Stapled {
		t.Fatalf("finding %+v", finding)
	}
	if _, err := judging.engine().VerifyEvidence(context.Background(), env, []byte("another binding")); !errors.As(err, &verdict) {
		t.Fatalf("another binding than the quote's: %v", err)
	}
	// What the command kept is the authority's own, apart from Intel's.
	entries, err := os.ReadDir(cache)
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "simulated-") {
		t.Fatalf("the command's cache holds %v (%v)", entries, err)
	}
	// With no directory the command is any build's: Intel's root, and no
	// simulated guest.
	shipped := &trust{collateralCache: t.TempDir(), ownCollateral: true}
	if shipped.simulated.engine(session.EngineOptions{}) != nil {
		t.Fatal("a command that was given no directory has a simulated engine")
	}
	offline, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if res, err := shipped.engine().VerifyEvidence(offline, env, reportData); err == nil || res != nil {
		t.Fatalf("a command that was given no directory took a simulated guest: %+v", res)
	}

	stop()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("simtee vendor, stopped: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("simtee vendor did not end")
	}
	if _, err := os.Stat(address); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("simtee vendor left its address behind: %v", err)
	}
	// A directory that holds no authority is served by nobody.
	if _, err := run(context.Background(), "simtee", "vendor", "--dir", t.TempDir()); err == nil {
		t.Fatal("a directory that holds no authority was served")
	}
}

// Every command that judges evidence takes the directory, and says what the
// option is. No other command has it.
func TestEveryJudgingCommandTakesTheSimulatedAuthority(t *testing.T) {
	judging := 0
	var walk func(cmd *cobra.Command)
	walk = func(cmd *cobra.Command) {
		for _, child := range cmd.Commands() {
			walk(child)
		}
		judges := cmd.Flags().Lookup("collateral-cache") != nil
		flag := cmd.Flags().Lookup("simulated-tee")
		switch {
		case judges && flag == nil:
			t.Errorf("%s judges evidence and takes no --simulated-tee", cmd.CommandPath())
		case !judges && flag != nil:
			t.Errorf("%s judges no evidence and takes --simulated-tee", cmd.CommandPath())
		case judges:
			judging++
			if flag.DefValue != "" || !strings.Contains(flag.Usage, "DEVELOPMENT ONLY") || !strings.Contains(flag.Usage, "in place of Intel's root, never beside it") {
				t.Errorf("%s: --simulated-tee does not say what it is: %q", cmd.CommandPath(), flag.Usage)
			}
		}
	}
	walk(NewCmd())
	if judging < 6 {
		t.Fatalf("%d commands judge evidence: the walk found too few", judging)
	}
	var s simulatedTrust
	set := pflag.NewFlagSet("command", pflag.ContinueOnError)
	s.flags(set)
	if err := set.Parse([]string{"--simulated-tee", "/authority"}); err != nil || s.dir != "/authority" {
		t.Fatalf("--simulated-tee /authority: %v, %q", err, s.dir)
	}
}

// A verdict a command prints under a simulated authority says, before every
// other gap, that it proves nothing about the guest's hardware. A command
// that was given no directory says no such thing.
func TestVerdictUnderASimulatedAuthoritySaysWhatItDoesNotProve(t *testing.T) {
	b := unbound(t, sessionsim.NewGuest(t, nil))
	bind(t, b)
	for _, simulated := range []bool{true, false} {
		flags := driving(b)
		if simulated {
			// The engine is the test's own: only what the command says of
			// its verdict is under test.
			flags.simulated.dir = "/authority"
		}
		var stdout, stderr bytes.Buffer
		if code := runVerify(context.Background(), flags, true, &stdout, &stderr); code != ExitOK {
			t.Fatalf("verify: exit %d: %s%s", code, stdout.String(), stderr.String())
		}
		var v verdict
		if err := json.Unmarshal(stdout.Bytes(), &v); err != nil || !v.Verified {
			t.Fatalf("verdict %+v, %v", v, err)
		}
		said := len(v.NotProven) > 0 && strings.Contains(v.NotProven[0], "its TEE is simulated in software")
		if said != simulated {
			t.Fatalf("simulated %v, and the verdict's gaps are %q", simulated, v.NotProven)
		}
		stdout.Reset()
		if code := runVerify(context.Background(), flags, false, &stdout, &stderr); code != ExitOK {
			t.Fatalf("verify: exit %d", code)
		}
		if strings.Contains(stdout.String(), "NOT PROVEN    anything about the guest's hardware") != simulated {
			t.Fatalf("simulated %v, and the command printed:\n%s", simulated, stdout.String())
		}
	}
}
