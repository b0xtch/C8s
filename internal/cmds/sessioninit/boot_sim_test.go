//go:build c8s_simtee

package sessioninit

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/simtee"
)

// simGuest is the guest a launcher builds with no TEE: the same disks and
// files, and neither a register nor a guest device.
func simGuest() *fakeGuest {
	f := tdxGuest()
	delete(f.files, rtmr3Path)
	return f
}

// The init of a simulation build keeps RTMR[3] in a file in memory, where
// its agent looks for it, holding what a TDX module's would hold after the
// launch key: the value a verifier seeds a guest's chain with.
func TestPrepareRootOnASimulatedTEE(t *testing.T) {
	if simRegisterPath != simtee.RegisterPath {
		t.Fatalf("the init makes the register at %s and the agent reads it at %s", simRegisterPath, simtee.RegisterPath)
	}
	f := simGuest()
	if err := prepareRoot(f); err != nil {
		t.Fatal(err)
	}
	key := f.files["/opkey/"+launchKeyFile]
	if !bytes.Equal(f.writes[newRoot+launchKeyDir+"/"+launchKeyName], key) {
		t.Fatal("the staged key is not the volume's")
	}
	want := runtimemeasure.Seed(key)
	if got := f.writes[newRoot+simRegisterPath]; !bytes.Equal(got, want[:]) {
		t.Fatalf("the simulated register holds %x, and a TDX module's would hold %x", got, want)
	}
	if !f.dirs[newRoot+"/run/c8s-simtee"] {
		t.Fatal("the register's directory was not made")
	}
	var said bool
	for _, line := range f.logs {
		said = said || strings.Contains(line, "simulated and protects nothing")
	}
	if !said {
		t.Fatalf("the init did not say that this guest's TEE is simulated: %q", f.logs)
	}
}

// A simulation build boots in no guest that has a TEE: it would keep a
// register of its own beside the hardware's.
func TestSimulationBuildBootsInNoTEE(t *testing.T) {
	for name, device := range map[string]string{
		"a trust domain's register": rtmr3Path, "a trust domain's device": tdxDevice, "an SEV-SNP guest's device": sevGuest,
	} {
		f := simGuest()
		f.files[device] = nil
		err := prepareRoot(f)
		if err == nil || !strings.Contains(err.Error(), "a simulation build runs in none") {
			t.Errorf("%s: %v", name, err)
		}
		if _, wrote := f.writes[newRoot+simRegisterPath]; wrote {
			t.Errorf("%s: a simulated register was made", name)
		}
		if _, wrote := f.writes[rtmr3Path]; wrote {
			t.Errorf("%s: the hardware's register was extended", name)
		}
	}
}

// A guest launched with no launch volume has no key to extend, and no
// hardware file either: its init makes no register, and its agent finds
// none.
func TestSimulatedGuestWithoutALaunchVolumeHasNoRegister(t *testing.T) {
	f := simGuest()
	f.disks = f.disks[:2]
	if err := prepareRoot(f); err != nil {
		t.Fatal(err)
	}
	if _, wrote := f.writes[newRoot+simRegisterPath]; wrote {
		t.Fatal("a register was made for a guest with no launch key")
	}
}

// A register the init cannot make stops the guest.
func TestSimulatedRegisterThatCannotBeMadeStopsTheGuest(t *testing.T) {
	f := simGuest()
	f.failMount["write:"+newRoot+simRegisterPath] = errors.New("ENOSPC")
	if err := prepareRoot(f); err == nil || !strings.Contains(err.Error(), "simulated RTMR[3]") {
		t.Fatalf("a register that could not be written: %v", err)
	}
}
