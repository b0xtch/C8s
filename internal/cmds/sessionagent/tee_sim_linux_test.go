//go:build linux && c8s_simtee

package sessionagent

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/simtee"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// simGuest is a guest as a simulation build's launcher and init leave it:
// the hardware file its load step staged, and the register its init made
// with the launch key in it.
type simGuest struct {
	dir       *simtee.Directory
	registers [3][48]byte
	launchKey []byte
}

func newSimGuest(t *testing.T) *simGuest {
	t.Helper()
	g := &simGuest{launchKey: []byte("-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n")}
	var err error
	if g.dir, err = simtee.NewDirectory(filepath.Join(t.TempDir(), "authority"), time.Now()); err != nil {
		t.Fatal(err)
	}
	for i := range g.registers {
		g.registers[i] = sha512.Sum384([]byte{byte(i)})
	}
	hardware, err := g.dir.NewHardware(g.registers[0], g.registers[1], g.registers[2], "a shape")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := hardware.Encode()
	if err != nil {
		t.Fatal(err)
	}
	guest := t.TempDir()
	seed := runtimemeasure.Seed(g.launchKey)
	for path, data := range map[string][]byte{"simtee.json": encoded, "rtmr3": seed[:], "cpuinfo": []byte("flags\t\t: fpu vme de tsc_reliable\n")} {
		if err := os.WriteFile(filepath.Join(guest, path), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	paths := []*string{&simHardwarePath, &simRegisterPath, &cpuInfoPath, &tdxDevicePath}
	before := []string{simHardwarePath, simRegisterPath, cpuInfoPath, tdxDevicePath}
	simHardwarePath, simRegisterPath = filepath.Join(guest, "simtee.json"), filepath.Join(guest, "rtmr3")
	cpuInfoPath, tdxDevicePath = filepath.Join(guest, "cpuinfo"), filepath.Join(guest, "tdx_guest")
	forget := func() {
		simulated.once, simulated.tee, simulated.err = sync.Once{}, nil, nil
	}
	forget()
	t.Cleanup(func() {
		for i, path := range paths {
			*path = before[i]
		}
		forget()
	})
	return g
}

// A simulation build's guest holds the registers its launcher declared and
// the one its init made, extends that one as a TDX module's RTMR[3] extends,
// and quotes all four under the authority its hardware names. Its evidence
// passes the engine it makes for itself, and no engine as any other build
// makes it.
func TestSimulatedGuestQuotesTheRegistersItWasHanded(t *testing.T) {
	g := newSimGuest(t)
	tee, err := OpenTEE("tdx")
	if err != nil {
		t.Fatal(err)
	}
	if tee.Family() != teetypes.FamilyTDX {
		t.Fatalf("the simulated TEE's family is %s", tee.Family())
	}
	self, err := tee.Measurements(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seed := runtimemeasure.Seed(g.launchKey)
	if self.Claims.LaunchDigest != hex.EncodeToString(g.registers[0][:]) {
		t.Fatalf("MRTD as the guest reads it: %s", self.Claims.LaunchDigest)
	}
	shape := sha512.Sum384([]byte("c8s simulated TEE: machine\x00a shape"))
	for i, want := range [][48]byte{shape, g.registers[1], g.registers[2], seed} {
		got, err := self.Claims.RTMR(i)
		if err != nil || !bytes.Equal(got, want[:]) {
			t.Fatalf("RTMR[%d] as the guest reads it: %x, %v", i, got, err)
		}
	}
	if debug, err := self.Claims.DebugEnabled(); err != nil || debug {
		t.Fatalf("the simulated guest reads as debuggable: %v, %v", debug, err)
	}
	// The launch key the init extended is the one the agent checks the
	// register against, as on TDX.
	if err := runtimemeasure.VerifyBinding(self, g.launchKey, nil); err != nil {
		t.Fatalf("the register does not bind the launch key: %v", err)
	}

	register, err := tee.Register()
	if err != nil {
		t.Fatal(err)
	}
	event := runtimemeasure.Event("sha256:" + strings.Repeat("ab", 32))
	if err := register.Extend(event[:]); err != nil {
		t.Fatal(err)
	}
	want := runtimemeasure.Extend(seed, event)
	if got, err := register.Extension(); err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("the register after one event: %x, %v", got, err)
	}
	if err := register.Extend(event[:47]); err == nil {
		t.Fatal("an event that is no digest was extended")
	}
	// It is the guest's, and outlives the agent: another process finds the
	// chain where this one left it.
	if again, err := (&simRegister{path: simRegisterPath}).Extension(); err != nil || !bytes.Equal(again, want[:]) {
		t.Fatalf("the register as another process reads it: %x, %v", again, err)
	}

	reportData := []byte("the guest's key")
	env, err := tee.Evidence(context.Background(), reportData)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, make([]byte, 65)} {
		if _, err := tee.Evidence(context.Background(), bad); err == nil {
			t.Fatalf("evidence over %d bytes of report data", len(bad))
		}
	}
	engine, err := GuestEngine()
	if err != nil {
		t.Fatal(err)
	}
	vendor := simtee.NewVendor(g.dir.Authority, time.Now)
	docs, err := session.FetchSimulatedCollateral(context.Background(), vendor, session.CollateralPlatform{FMSPC: simtee.FMSPC, CA: "platform"})
	if err != nil {
		t.Fatal(err)
	}
	handed := session.AllowHandedDocuments(session.WithCollateralSource(context.Background(), func(context.Context) []session.CollateralDocument { return docs }))
	res, err := engine.VerifyEvidence(handed, env, reportData)
	if err != nil {
		t.Fatalf("the guest's evidence under its own authority: %v", err)
	}
	if got, err := res.Claims.RTMR(3); err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("RTMR[3] in the guest's quote: %x, %v", got, err)
	}
	if res.Claims.LaunchDigest != self.Claims.LaunchDigest {
		t.Fatal("the quote's MRTD is not the guest's")
	}
	// A guest's engine asks nobody: with nothing handed over it has no verdict.
	if _, err := engine.VerifyEvidence(context.Background(), env, reportData); err == nil {
		t.Fatal("a guest's engine judged with no documents")
	}
	var verdict *session.VerificationError
	shipped := session.NewEngine(session.EngineOptions{HandedCollateralOnly: true})
	if res, err := shipped.VerifyEvidence(handed, env, reportData); !errors.As(err, &verdict) || res != nil {
		t.Fatalf("an engine under the vendor's root took a simulated guest's evidence: %+v, %v", res, err)
	}

	// A replica's engine asks whoever serves the authority's documents, over
	// the road its host carries to the vendor's first service.
	services, err := session.VendorServices("tdx")
	if err != nil {
		t.Fatal(err)
	}
	var dialed []string
	replica, err := ReplicaEngine(session.EngineOptions{Dial: (&roadTo{handler: simtee.Handler(vendor), dialed: &dialed}).dial(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replica.VerifyEvidence(context.Background(), env, reportData); err != nil {
		t.Fatalf("the guest's evidence as a simulated replica judges it: %v", err)
	}
	if len(dialed) == 0 {
		t.Fatal("a replica's engine asked nobody")
	}
	for _, addr := range dialed {
		if addr != services[0] {
			t.Fatalf("a replica's engine dialed %s: its road is named for %s", addr, services[0])
		}
	}
	if files := hardwareFiles(); len(files) != 1 || files[simtee.HardwareFile] != simtee.MaxHardwareBytes {
		t.Fatalf("a simulation build's load copies %v", files)
	}
}

// roadTo is a road a guest's host carries: whatever address is dialed on it,
// it leads to handler.
type roadTo struct {
	handler http.Handler
	dialed  *[]string
}

func (r *roadTo) dial(t *testing.T) func(ctx context.Context, network, addr string) (net.Conn, error) {
	t.Helper()
	server := httptest.NewServer(r.handler)
	t.Cleanup(server.Close)
	var mu sync.Mutex
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		*r.dialed = append(*r.dialed, addr)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
}

// A simulation build runs in no trust domain, simulates no other platform
// than TDX, and has no TEE without what its launcher and its init left it.
func TestSimulationBuildRefuses(t *testing.T) {
	for name, c := range map[string]struct {
		change func(t *testing.T)
		want   string
	}{
		"a trust domain's device": {func(t *testing.T) {
			if err := os.WriteFile(tdxDevicePath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "this guest is a trust domain"},
		"a trust domain's CPU": {func(t *testing.T) {
			if err := os.WriteFile(cpuInfoPath, []byte("flags\t\t: fpu vme tsc_reliable tdx_guest\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "this guest is a trust domain"},
		"no hardware from its launcher": {func(t *testing.T) {
			if err := os.Remove(simHardwarePath); err != nil {
				t.Fatal(err)
			}
		}, "handed it no simulated hardware"},
		"hardware that is none": {func(t *testing.T) {
			if err := os.WriteFile(simHardwarePath, []byte(`{"mrtd":"00"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "simulated hardware"},
		"no register from its init": {func(t *testing.T) {
			if err := os.Remove(simRegisterPath); err != nil {
				t.Fatal(err)
			}
		}, "simulated RTMR[3]"},
		"a register that is short": {func(t *testing.T) {
			if err := os.WriteFile(simRegisterPath, make([]byte, 47), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "holds no 48 bytes"},
		"a register that is long": {func(t *testing.T) {
			if err := os.WriteFile(simRegisterPath, make([]byte, 49), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "holds no 48 bytes"},
		"a register that is a link": {func(t *testing.T) {
			elsewhere := filepath.Join(t.TempDir(), "rtmr3")
			if err := os.WriteFile(elsewhere, make([]byte, 48), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(simRegisterPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, simRegisterPath); err != nil {
				t.Fatal(err)
			}
		}, "simulated RTMR[3]"},
	} {
		t.Run(name, func(t *testing.T) {
			newSimGuest(t)
			c.change(t)
			if tee, err := OpenTEE("tdx"); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("a TEE was simulated, or refused for another reason: %v, %v", tee, err)
			}
			// What refused the TEE refuses both engines: neither is made
			// for a guest that has none.
			if _, err := GuestEngine(); err == nil {
				t.Fatal("a guest's engine was made without its TEE")
			}
			if _, err := ReplicaEngine(session.EngineOptions{}); err == nil {
				t.Fatal("a replica's engine was made without its TEE")
			}
		})
	}
	newSimGuest(t)
	if _, err := OpenTEE("snp"); err == nil || !strings.Contains(err.Error(), "not simulated") {
		t.Fatalf("SEV-SNP was simulated: %v", err)
	}
}
