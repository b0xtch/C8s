package session

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// A PCK chain alone does not say which enclave signed a quote. Each field that
// identifies Intel's production TD quoting enclave, and the TDX module's
// signer, must be what Intel publishes.
func TestQuoteOriginIsPinned(t *testing.T) {
	env, _ := fixture(t)
	origin := func(env teetypes.AttestationEvidence) error {
		quote, _, err := parseTDQuote(env.Evidence)
		if err != nil {
			return err
		}
		return checkTDQuoteOrigin(quote)
	}
	if err := origin(env); err != nil {
		t.Fatalf("control: a genuine quote was refused: %v", err)
	}
	// Offsets into a v4 quote: 48-byte header, 584-byte TD report body, a
	// 4-byte length, the 64-byte signature and 64-byte attestation key, then
	// 6 bytes of certification header before the 384-byte QE report.
	const (
		body     = 48
		qeReport = 48 + 584 + 4 + 64 + 64 + 6
	)
	for name, tc := range map[string]struct {
		bent teetypes.AttestationEvidence
		want string
	}{
		"another enclave signer":        {flipQuote(t, env, qeReport+128), "not Intel's TD quoting enclave"},
		"another Intel enclave product": {flipQuote(t, env, qeReport+256), "enclave product"},
		// INIT, DEBUG, MODE64BIT and PROVISION_KEY: the genuine flags plus DEBUG.
		"debug quoting enclave":          {setQuoteByte(t, env, qeReport+48, 0x17), "not the production TD quoting enclave"},
		"quoting enclave MISCSELECT set": {flipQuote(t, env, qeReport+16), "MISCSELECT"},
		"TDX module from another signer": {flipQuote(t, env, body+64), "TDX module signer"},
		"TDX module attributes set":      {flipQuote(t, env, body+112), "TDX module attributes"},
	} {
		t.Run(name, func(t *testing.T) {
			err := origin(tc.bent)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a refusal mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

func setQuoteByte(t *testing.T, env teetypes.AttestationEvidence, offset int, value byte) teetypes.AttestationEvidence {
	t.Helper()
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
	quote[offset] = value
	body.Quote = base64.StdEncoding.EncodeToString(quote)
	if env.Evidence, err = json.Marshal(body); err != nil {
		t.Fatal(err)
	}
	return env
}
