package session_test

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// A real, non-debug TDX quote: entry 0 of attestation-go v0.7.2's
// attestation/tdx/testdata/tdx-evidence-batch.json, event log dropped.
//
//go:embed testdata/tdx-evidence.json
var realTDXEvidence []byte

// realReportData is the REPORTDATA that quote carries (SHA-256 sized, zero tail).
var realReportData = mustHex("b8b9e582d1efb326120f7215e75a2ac2327da81aa5b44209f69460ae5af99e00")

func realEvidence(t *testing.T) teetypes.AttestationEvidence {
	t.Helper()
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(realTDXEvidence, &env); err != nil {
		t.Fatal(err)
	}
	return env
}

// Every case is refused on the quote alone, before the engine asks Intel for
// anything: none of them reaches the network.
func TestEngineRefusesRealQuote(t *testing.T) {
	engine := session.NewEngine(session.EngineOptions{OwnCollateralOnly: true})
	tamper := func(t *testing.T, offset int) teetypes.AttestationEvidence {
		env := realEvidence(t)
		var body struct {
			Quote string `json:"quote"`
		}
		if err := json.Unmarshal(env.Evidence, &body); err != nil {
			t.Fatal(err)
		}
		quote, err := base64.StdEncoding.DecodeString(body.Quote)
		if err != nil {
			t.Fatal(err)
		}
		quote[offset] ^= 1
		body.Quote = base64.StdEncoding.EncodeToString(quote)
		env.Evidence, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	wrong := append([]byte(nil), realReportData...)
	wrong[0] ^= 1
	relabelled := realEvidence(t)
	relabelled.Platform = "dstack"
	// A cloud overlay tag would bind REPORTDATA through a vTPM key the
	// attester names; only the bare-metal tag is accepted.
	overlay := realEvidence(t)
	overlay.Platform = teetypes.PlatformAzTDX

	// Offsets into a v4 quote: 48-byte header, then the TD report body.
	const mrtd, rtmr3, reportData, signature = 48 + 136, 48 + 472, 48 + 520, 48 + 584 + 4
	for name, tc := range map[string]struct {
		env teetypes.AttestationEvidence
		rd  []byte
	}{
		"wrong nonce":            {realEvidence(t), wrong},
		"no expected nonce":      {realEvidence(t), nil},
		"MRTD bit flipped":       {tamper(t, mrtd), realReportData},
		"RTMR[3] bit flipped":    {tamper(t, rtmr3), realReportData},
		"REPORTDATA bit flipped": {tamper(t, reportData), realReportData},
		"signature bit flipped":  {tamper(t, signature), realReportData},
		"unknown platform tag":   {relabelled, realReportData},
		"cloud overlay tag":      {overlay, realReportData},
	} {
		t.Run(name, func(t *testing.T) {
			if res, err := engine.VerifyEvidence(context.Background(), tc.env, tc.rd); err == nil {
				t.Fatalf("accepted: %+v", res)
			}
		})
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
