//go:build linux

package sessionagent

import (
	"encoding/base64"
	"encoding/json"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// tdxGuestDevice is the device a trust domain's kernel has.
const tdxGuestDevice = "/dev/tdx_guest"

// tdxEnvelope is a quote as a session's verifier takes it. The firmware's
// event log stays out: a verifier holds the quote's registers to published
// values and replays no log, and the log is many times the quote's size.
func tdxEnvelope(quote []byte) (teetypes.AttestationEvidence, error) {
	evidence, err := json.Marshal(struct {
		Quote string `json:"quote"`
	}{base64.StdEncoding.EncodeToString(quote)})
	if err != nil {
		return teetypes.AttestationEvidence{}, err
	}
	return teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: evidence}, nil
}
