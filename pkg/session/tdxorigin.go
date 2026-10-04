package session

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

// Intel's TD quoting enclave identity, as Intel PCS publishes it (enclave
// identity TD_QE, version 2). A PCK certificate chain alone does not tie a
// quote to that enclave: the platform's PCE certifies any provisioning enclave
// its host runs, and such an enclave could sign a TD report body of its own
// invention. With collateral, Intel's signed identity document makes this
// check; these constants make it without.
var (
	tdQEMrSigner       = mustDecodeHex("dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5")
	tdQEAttributes     = mustDecodeHex("11000000000000000000000000000000")
	tdQEAttributesMask = mustDecodeHex("fbffffffffffffff0000000000000000")
)

const tdQEProdID = 2

// parseTDQuote decodes the version 4 quote in bare-metal TDX evidence.
func parseTDQuote(evidence json.RawMessage) (*pb.QuoteV4, error) {
	var envelope struct {
		Quote string `json:"quote"`
	}
	if err := json.Unmarshal(evidence, &envelope); err != nil {
		return nil, fmt.Errorf("TDX evidence: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(envelope.Quote)
	if err != nil {
		return nil, fmt.Errorf("TDX quote encoding: %w", err)
	}
	parsed, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("TDX quote: %w", err)
	}
	quote, ok := parsed.(*pb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("TDX quote is a %T, want a version 4 quote", parsed)
	}
	return quote, nil
}

// checkTDQuoteOrigin requires a TDX quote to come from Intel's TD quoting
// enclave, running outside debug mode, over a report from an Intel-signed TDX
// module. It does not judge the enclave's version, which needs collateral.
func checkTDQuoteOrigin(quote *pb.QuoteV4) error {
	qe := quote.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetQeReport()
	if qe == nil {
		return errors.New("TDX quote carries no quoting enclave report")
	}
	if !bytes.Equal(qe.GetMrSigner(), tdQEMrSigner) {
		return fmt.Errorf("quote was signed by an enclave from signer %x, which is not Intel's TD quoting enclave", qe.GetMrSigner())
	}
	if qe.GetIsvProdId() != tdQEProdID {
		return fmt.Errorf("quote was signed by Intel enclave product %d, want the TD quoting enclave (%d)", qe.GetIsvProdId(), tdQEProdID)
	}
	if qe.GetMiscSelect() != 0 {
		return fmt.Errorf("quoting enclave MISCSELECT is %#x, want 0", qe.GetMiscSelect())
	}
	attributes := qe.GetAttributes()
	if len(attributes) != len(tdQEAttributes) {
		return fmt.Errorf("quoting enclave attributes are %d bytes, want %d", len(attributes), len(tdQEAttributes))
	}
	for i := range attributes {
		// The mask covers the DEBUG bit: a debug enclave's keys are host-readable.
		if attributes[i]&tdQEAttributesMask[i] != tdQEAttributes[i] {
			return fmt.Errorf("quoting enclave attributes %x are not the production TD quoting enclave's", attributes)
		}
	}
	body := quote.GetTdQuoteBody()
	if !allZero(body.GetMrSignerSeam()) || len(body.GetMrSignerSeam()) == 0 {
		return fmt.Errorf("TDX module signer is %x, want Intel's (all zero)", body.GetMrSignerSeam())
	}
	if !allZero(body.GetSeamAttributes()) {
		return fmt.Errorf("TDX module attributes are %x, want none", body.GetSeamAttributes())
	}
	return nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
