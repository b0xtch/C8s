// Package sessionagent is the measured in-guest agent of a session guest. It
// authenticates the signed launch document against the hardware-bound launch
// key, measures what it admits, and serves the attested API that is the only
// way in: the host has no control channel into the guest.
package sessionagent

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// TEE is this guest's own view of its hardware identity.
type TEE interface {
	Family() teetypes.Family
	// Measurements returns the guest's launch claims as the hardware reports
	// them to the guest itself. They come through the measured kernel, not
	// through a signature chain: authoritative here, proof to nobody else.
	Measurements(ctx context.Context) (*teetypes.VerificationResult, error)
	// Register is the runtime measurement register, or
	// runtimemeasure.ErrNoRegister on a platform without one.
	Register() (runtimemeasure.Register, error)
	// Evidence returns remotely verifiable evidence binding reportData.
	Evidence(ctx context.Context, reportData []byte) (teetypes.AttestationEvidence, error)
}

// TDREPORT layout (Intel TDX Module ABI, TDREPORT_STRUCT): REPORTMACSTRUCT is
// 256 bytes, TEE_TCB_INFO 239, 17 reserved, then TDINFO at 512.
const (
	tdReportSize   = 1024
	tdInfoOffset   = 512
	tdAttributes   = tdInfoOffset
	tdMRTD         = tdInfoOffset + 16
	tdRTMR0        = tdInfoOffset + 16 + 4*48
	tdReportData   = 128
	registerLength = 48
)

// claimsFromTDReport turns a TDREPORT the guest read about itself into the
// claims shape the shared policy helpers consume.
func claimsFromTDReport(report []byte) (*teetypes.VerificationResult, error) {
	if len(report) != tdReportSize {
		return nil, fmt.Errorf("TDREPORT is %d bytes, want %d", len(report), tdReportSize)
	}
	attributes := binary.LittleEndian.Uint64(report[tdAttributes : tdAttributes+8])
	data := map[string]any{
		"td_attributes":        hex.EncodeToString(report[tdAttributes : tdAttributes+8]),
		"td_attributes_parsed": map[string]any{"debug": attributes&1 != 0},
	}
	for i := 0; i < 4; i++ {
		off := tdRTMR0 + i*registerLength
		data[fmt.Sprintf("rtmr_%d", i)] = hex.EncodeToString(report[off : off+registerLength])
	}
	return &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformTDX,
		Claims: teetypes.Claims{
			LaunchDigest: hex.EncodeToString(report[tdMRTD : tdMRTD+registerLength]),
			ReportData:   append([]byte(nil), report[tdReportData:tdReportData+64]...),
			PlatformData: data,
		},
	}, nil
}
