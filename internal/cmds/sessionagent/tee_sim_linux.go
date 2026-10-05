//go:build linux && c8s_simtee

package sessionagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/simtee"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// This file is the guest's side of a TEE simulated in software, the second
// baseline of docs/session-performance.md. Only a build made with the
// c8s_simtee tag holds it, and it protects nothing: the registers are what
// the guest's launcher declared, the platform's key came on the launch
// volume, and RTMR[3] is a file in the guest's memory.

// The image's own paths. A simulation build takes its hardware from where
// its load step stages it, and its register from where its init made it.
var (
	simHardwarePath = filepath.Join(defaultLaunchDir, simtee.HardwareFile)
	simRegisterPath = simtee.RegisterPath
	// cpuInfoPath lists what the kernel found the CPU to be.
	cpuInfoPath = "/proc/cpuinfo"
	// tdxDevicePath is the device a trust domain's kernel has.
	tdxDevicePath = tdxGuestDevice
)

// errInsideTD refuses to simulate where there is hardware to ask. The
// image's build looks for the tag's name in the program's own text.
var errInsideTD = errors.New("this program simulates a TEE (c8s_simtee) and this guest is a trust domain: a simulation build runs in none")

// insideTD reports whether the guest runs in a trust domain.
func insideTD() bool {
	if _, err := os.Stat(tdxDevicePath); err == nil {
		return true
	}
	info, err := os.ReadFile(cpuInfoPath)
	return err == nil && bytes.Contains(info, []byte(" tdx_guest"))
}

var simulated struct {
	once sync.Once
	tee  *simTEE
	err  error
}

// simulatedTEE boots, once, on what the guest's launcher handed it in place
// of hardware.
func simulatedTEE() (*simTEE, error) {
	simulated.once.Do(func() { simulated.tee, simulated.err = bootSimulated() })
	return simulated.tee, simulated.err
}

func bootSimulated() (*simTEE, error) {
	if insideTD() {
		return nil, errInsideTD
	}
	data, err := session.ReadBounded(simHardwarePath, simtee.MaxHardwareBytes)
	if err != nil {
		return nil, fmt.Errorf("the guest's launcher handed it no simulated hardware: %w", err)
	}
	hardware, err := simtee.ParseHardware(data)
	if err != nil {
		return nil, err
	}
	machine, err := hardware.Boot()
	if err != nil {
		return nil, err
	}
	register := &simRegister{path: simRegisterPath}
	// The init made the register with the launch key in it. A guest without
	// one booted with no launch volume, and so with no hardware either.
	if _, err := register.Extension(); err != nil {
		return nil, err
	}
	return &simTEE{machine: machine, register: register}, nil
}

// OpenTEE returns the simulated TEE, which stands for TDX and for nothing
// else, and refuses where the guest is a trust domain.
func OpenTEE(platform string) (TEE, error) {
	if platform != "tdx" {
		return nil, fmt.Errorf("platform %q is not simulated", platform)
	}
	tee, err := simulatedTEE()
	if err != nil {
		return nil, err
	}
	return tee, nil
}

// GuestEngine is the engine of a simulated guest: it holds evidence to the
// simulated authority its hardware names, and judges by the documents its
// host hands it.
func GuestEngine() (session.Engine, error) {
	tee, err := simulatedTEE()
	if err != nil {
		return nil, err
	}
	return session.NewSimulatedEngine(session.EngineOptions{HandedCollateralOnly: true}, tee.machine.Root, nil)
}

// ReplicaEngine is the engine of a simulated key service replica: it holds
// evidence to the simulated authority, and asks whoever serves that
// authority's documents over the road opts names to the vendor's service.
func ReplicaEngine(opts session.EngineOptions) (session.Engine, error) {
	tee, err := simulatedTEE()
	if err != nil {
		return nil, err
	}
	services, err := session.VendorServices("tdx")
	if err != nil {
		return nil, err
	}
	// Every road of a simulated replica's launcher leads to the simulated
	// vendor, whichever of the vendor's services it is named for.
	return session.NewSimulatedEngine(opts, tee.machine.Root, simtee.NewRemote(services[0], opts.Dial))
}

// hardwareFiles are the files a simulated guest copies off its launch volume
// besides the ones every guest has: what stands for its hardware.
func hardwareFiles() map[string]int64 {
	return map[string]int64{simtee.HardwareFile: simtee.MaxHardwareBytes}
}

// simRegister is RTMR[3] of a simulated guest: a file in the guest's memory,
// which the init made with the launch key extended into it. It outlives the
// agent as a TDX module's register does, so an agent that starts again finds
// its chain where it left it.
type simRegister struct {
	mu   sync.Mutex
	path string
}

// open returns the register's file, held against every other process that
// would extend it.
func (r *simRegister) open(flag, how int) (*os.File, error) {
	// No O_CREATE: a guest whose init made no register has none to extend.
	f, err := os.OpenFile(r.path, flag|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("simulated RTMR[3]: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), how); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("simulated RTMR[3]: %w", err)
	}
	return f, nil
}

func (r *simRegister) value(f *os.File) (out [runtimemeasure.Size]byte, err error) {
	// One byte more than a register holds, to tell a longer file from one.
	buf := make([]byte, runtimemeasure.Size+1)
	n, err := f.ReadAt(buf, 0)
	if n != runtimemeasure.Size {
		return out, fmt.Errorf("simulated RTMR[3]: %s holds no %d bytes (%v)", r.path, runtimemeasure.Size, err)
	}
	copy(out[:], buf)
	return out, nil
}

func (r *simRegister) Extend(event []byte) error {
	if len(event) != runtimemeasure.Size {
		return fmt.Errorf("extend event is %d bytes, want %d", len(event), runtimemeasure.Size)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := r.open(os.O_RDWR, unix.LOCK_EX)
	if err != nil {
		return err
	}
	defer f.Close()
	current, err := r.value(f)
	if err != nil {
		return err
	}
	next := runtimemeasure.Extend(current, [runtimemeasure.Size]byte(event))
	// One write within one page of a file in memory: whole or not at all.
	if _, err := f.WriteAt(next[:], 0); err != nil {
		return fmt.Errorf("simulated RTMR[3]: %w", err)
	}
	return nil
}

func (r *simRegister) Extension() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := r.open(os.O_RDONLY, unix.LOCK_SH)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	current, err := r.value(f)
	if err != nil {
		return nil, err
	}
	return current[:], nil
}

// simTEE is the simulated TEE of one guest.
type simTEE struct {
	machine  *simtee.Machine
	register *simRegister
}

func (t *simTEE) Family() teetypes.Family { return teetypes.FamilyTDX }

func (t *simTEE) Register() (runtimemeasure.Register, error) { return t.register, nil }

// report is the guest's registers in the layout of the report a TDX module
// would give it.
func (t *simTEE) report() ([]byte, [runtimemeasure.Size]byte, error) {
	var rtmr3 [runtimemeasure.Size]byte
	current, err := t.register.Extension()
	if err != nil {
		return nil, rtmr3, err
	}
	copy(rtmr3[:], current)
	report := make([]byte, tdReportSize)
	copy(report[tdMRTD:], t.machine.MRTD[:])
	for i, value := range [][runtimemeasure.Size]byte{t.machine.RTMR[0], t.machine.RTMR[1], t.machine.RTMR[2], rtmr3} {
		copy(report[tdRTMR0+i*registerLength:], value[:])
	}
	return report, rtmr3, nil
}

func (t *simTEE) Measurements(context.Context) (*teetypes.VerificationResult, error) {
	report, _, err := t.report()
	if err != nil {
		return nil, err
	}
	return claimsFromTDReport(report)
}

func (t *simTEE) Evidence(_ context.Context, reportData []byte) (teetypes.AttestationEvidence, error) {
	if len(reportData) == 0 || len(reportData) > 64 {
		return teetypes.AttestationEvidence{}, fmt.Errorf("report data must be 1..64 bytes, got %d", len(reportData))
	}
	var rd [64]byte
	copy(rd[:], reportData)
	_, rtmr3, err := t.report()
	if err != nil {
		return teetypes.AttestationEvidence{}, err
	}
	quote, err := t.machine.Quote(rtmr3, rd)
	if err != nil {
		return teetypes.AttestationEvidence{}, err
	}
	return tdxEnvelope(quote)
}
