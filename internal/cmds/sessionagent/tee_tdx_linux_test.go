//go:build linux

package sessionagent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// A guest's evidence is its quote and nothing beside it. The firmware's
// event log, which other verifiers replay, is no part of it: a session's
// verifier holds the registers to published values, and every quote a guest
// serves, relays and keeps would carry the log's weight.
func TestTDXEvidenceIsTheQuoteAlone(t *testing.T) {
	quote := bytes.Repeat([]byte{0xa5}, 5006)
	evidence, err := tdxEnvelope(quote)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Platform != teetypes.PlatformTDX {
		t.Fatalf("the platform is %q", evidence.Platform)
	}
	var fields map[string]string
	if err := json.Unmarshal(evidence.Evidence, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 {
		t.Fatalf("the evidence has %d fields, want the quote alone", len(fields))
	}
	got, err := base64.StdEncoding.DecodeString(fields["quote"])
	if err != nil || !bytes.Equal(got, quote) {
		t.Fatalf("the quote did not come back as it went in: %v", err)
	}
	// A quote and its encoding, and little else.
	if most := base64.StdEncoding.EncodedLen(len(quote)) + 64; len(evidence.Evidence) > most {
		t.Fatalf("the evidence is %d bytes, more than %d", len(evidence.Evidence), most)
	}
}
