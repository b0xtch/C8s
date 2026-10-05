package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

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

// The engine verifies the bytes this package decodes from the evidence, and
// what is read of the quote afterwards is parsed from those same bytes: one
// decoding, so there is no second reader to be shown another quote. Evidence
// whose quote does not decode, or is larger than a quote may be, is refused
// before anything verifies it.
func TestTDEvidenceIsDecodedOnce(t *testing.T) {
	env, reportData := fixture(t)
	raw, err := tdQuoteBytes(env.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	quote, parsed, err := parseTDQuote(env.Evidence)
	if err != nil || quote == nil || string(parsed) != string(raw) {
		t.Fatalf("the quote parsed for the checks is not the bytes handed to the engine: %v", err)
	}
	for name, evidence := range map[string]string{
		"no JSON":                  `quote`,
		"a quote that is no text":  `{"quote": 7}`,
		"no base64":                `{"quote": "not base64!"}`,
		"a quote beyond its bound": `{"quote": "` + strings.Repeat("A", teetypes.MaxEvidenceFieldSize+4) + `"}`,
	} {
		if got, err := tdQuoteBytes(json.RawMessage(evidence)); err == nil {
			t.Errorf("%s decoded to %d bytes", name, len(got))
		}
	}
	// A member beside the quote is not read, and changes no verdict: with an
	// event log that is none, the evidence verifies as it did without it.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(env.Evidence, &members); err != nil {
		t.Fatal(err)
	}
	members["cc_eventlog"] = json.RawMessage(`"` + base64.StdEncoding.EncodeToString([]byte("no event log")) + `"`)
	with, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	k := keptCollateral(t)
	engine := k.engineAt(k.newest.Add(10*time.Minute), k.intel(true), false)
	bent := teetypes.AttestationEvidence{Platform: env.Platform, Evidence: with}
	if _, err := engine.VerifyEvidence(lenient(), bent, reportData); err != nil {
		t.Fatalf("evidence with a member the verifier does not read: %v", err)
	}
	// More report data than a TD has is no report data to expect.
	if _, err := engine.VerifyEvidence(lenient(), env, make([]byte, 65)); !isVerdictErr(err) {
		t.Fatalf("65 bytes of expected report data: %v", err)
	}
}

func isVerdictErr(err error) bool {
	var verdict *VerificationError
	return errors.As(err, &verdict)
}
