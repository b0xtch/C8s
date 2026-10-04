// Package sessiontest simulates a trust domain for session tests: registers that
// extend like hardware, evidence that binds REPORTDATA, and an engine that
// verifies it. It proves nothing about real silicon; hardware tests do that.
package sessiontest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// TD is a simulated TDX guest's measurement state.
type TD struct {
	mu    sync.Mutex
	MRTD  [48]byte
	RTMR  [4][48]byte
	Debug bool
	// Attributes are the TD's attributes besides the debug bit.
	Attributes uint64
}

// NewTD returns a guest with random image measurements and RTMR[3] at reset.
func NewTD() *TD {
	// What a VMM sets for a Linux guest: no #VE on a pending page.
	td := &TD{Attributes: 1 << 28}
	for _, reg := range [][]byte{td.MRTD[:], td.RTMR[0][:], td.RTMR[1][:], td.RTMR[2][:]} {
		if _, err := rand.Read(reg); err != nil {
			panic(err)
		}
	}
	return td
}

// SeedLaunchKey does what the measured initrd does with the opkeydata pubkey.
func (td *TD) SeedLaunchKey(pubPEM []byte) {
	td.mu.Lock()
	defer td.mu.Unlock()
	td.RTMR[3] = runtimemeasure.Seed(pubPEM)
}

// Extend implements runtimemeasure.Register over RTMR[3].
func (td *TD) Extend(event []byte) error {
	if len(event) != 48 {
		return fmt.Errorf("extend event is %d bytes, want 48", len(event))
	}
	td.mu.Lock()
	defer td.mu.Unlock()
	td.RTMR[3] = runtimemeasure.Extend(td.RTMR[3], [48]byte(event))
	return nil
}

// Extension implements runtimemeasure.Register over RTMR[3].
func (td *TD) Extension() ([]byte, error) {
	td.mu.Lock()
	defer td.mu.Unlock()
	return bytes.Clone(td.RTMR[3][:]), nil
}

type fakeQuote struct {
	MRTD       string    `json:"mrtd"`
	RTMR       [4]string `json:"rtmr"`
	Debug      bool      `json:"debug"`
	Attributes uint64    `json:"attributes"`
	ReportData string    `json:"report_data"`
}

// Evidence returns evidence for reportData over the guest's current registers.
func (td *TD) Evidence(reportData []byte) teetypes.AttestationEvidence {
	td.mu.Lock()
	defer td.mu.Unlock()
	padded := make([]byte, 64)
	copy(padded, reportData)
	q := fakeQuote{MRTD: hex.EncodeToString(td.MRTD[:]), Debug: td.Debug, Attributes: td.Attributes, ReportData: hex.EncodeToString(padded)}
	for i := range td.RTMR {
		q.RTMR[i] = hex.EncodeToString(td.RTMR[i][:])
	}
	raw, err := json.Marshal(q)
	if err != nil {
		panic(err)
	}
	// Same shape as real TDX evidence, so it survives the RA-TLS extension's
	// event-log strip, which keeps only "quote".
	evidence, err := json.Marshal(tdxEvidence{Quote: base64.StdEncoding.EncodeToString(raw)})
	if err != nil {
		panic(err)
	}
	return teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: evidence}
}

type tdxEvidence struct {
	Quote      string `json:"quote"`
	CCEventlog string `json:"cc_eventlog,omitempty"`
}

// TEE adapts a TD to the in-guest agent's TEE interface.
type TEE struct{ TD *TD }

func (t TEE) Family() teetypes.Family { return teetypes.FamilyTDX }

func (t TEE) Measurements(context.Context) (*teetypes.VerificationResult, error) {
	return t.TD.Result(), nil
}

func (t TEE) Register() (runtimemeasure.Register, error) { return t.TD, nil }

func (t TEE) Evidence(_ context.Context, reportData []byte) (teetypes.AttestationEvidence, error) {
	return t.TD.Evidence(reportData), nil
}

// Result is the verified claims a real verifier would extract from Evidence.
func (td *TD) Result() *teetypes.VerificationResult {
	// The hardware reports a debug guest to itself as readily as any other.
	td.mu.Lock()
	debug := td.Debug
	td.Debug = false
	td.mu.Unlock()
	evidence := td.Evidence(make([]byte, 48))
	td.mu.Lock()
	td.Debug = debug
	td.mu.Unlock()
	res, err := Engine{}.VerifyEvidence(context.Background(), evidence, make([]byte, 48))
	if err != nil {
		panic(err)
	}
	res.Claims.PlatformData["td_attributes_parsed"] = map[string]any{"debug": debug}
	return res
}

// WriteManifest writes the image manifest pinning this guest's build.
func (td *TD) WriteManifest(t testing.TB) string {
	t.Helper()
	manifest := map[string]any{"tdx": map[string]string{
		"mrtd":  hex.EncodeToString(td.MRTD[:]),
		"rtmr1": hex.EncodeToString(td.RTMR[1][:]),
		"rtmr2": hex.EncodeToString(td.RTMR[2][:]),
	}}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// Engine verifies evidence produced by TD.Evidence the way hardware
// verification would: binding and debug policy first, claims second.
type Engine struct{}

// Requirements makes Engine one whose clients keep verdicts.
func (Engine) Requirements() string { return "sessiontest" }

func (Engine) VerifyEvidence(_ context.Context, env teetypes.AttestationEvidence, expectedReportData []byte) (*teetypes.VerificationResult, error) {
	refuse := func(format string, args ...any) error {
		return &session.VerificationError{Err: fmt.Errorf(format, args...)}
	}
	if env.Platform != teetypes.PlatformTDX {
		return nil, refuse("unsupported platform %q", env.Platform)
	}
	var outer tdxEvidence
	if err := json.Unmarshal(env.Evidence, &outer); err != nil {
		return nil, refuse("quote signature invalid: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(outer.Quote)
	if err != nil {
		return nil, refuse("quote signature invalid: %v", err)
	}
	var q fakeQuote
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		return nil, refuse("quote signature invalid: %v", err)
	}
	want := make([]byte, 64)
	copy(want, expectedReportData)
	if len(expectedReportData) == 0 || len(expectedReportData) > sha512.Size || q.ReportData != hex.EncodeToString(want) {
		return nil, refuse("REPORTDATA does not match the expected binding")
	}
	if q.Debug {
		return nil, refuse("TD launched with debug attribute")
	}
	attributes := q.Attributes
	if q.Debug {
		attributes |= 1
	}
	return &teetypes.VerificationResult{
		SignatureValid:  true,
		Platform:        teetypes.PlatformTDX,
		ReportDataMatch: teetypes.Ptr(true),
		Claims: teetypes.Claims{
			LaunchDigest: q.MRTD,
			PlatformData: map[string]any{
				"rtmr_0": q.RTMR[0], "rtmr_1": q.RTMR[1], "rtmr_2": q.RTMR[2], "rtmr_3": q.RTMR[3],
				"td_attributes":        hex.EncodeToString(binary.LittleEndian.AppendUint64(nil, attributes)),
				"td_attributes_parsed": map[string]any{"debug": q.Debug},
			},
		},
	}, nil
}
