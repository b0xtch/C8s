package session

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
)

// Intel's TCB statuses. UpToDate is always accepted and Revoked never is; a
// policy may accept the ones in between by name.
const (
	TCBUpToDate = string(pcs.TcbComponentStatusUpToDate)
	TCBRevoked  = string(pcs.TcbComponentStatusRevoked)
)

var acceptableTCBStatuses = []string{
	string(pcs.TcbComponentStatusSwHardeningNeeded),
	string(pcs.TcbComponentStatusConfigurationNeeded),
	string(pcs.TcbComponentStatusConfigurationAndSWHardeningNeeded),
	string(pcs.TcbComponentStatusOutOfDate),
	string(pcs.TcbComponentStatusOutOfDateConfigurationNeeded),
}

// ValidateTCBStatuses checks a list of statuses a policy accepts besides
// UpToDate: each is one of Intel's that can be accepted, and the list is
// sorted and names none twice, so that a document that carries it has one
// form.
func ValidateTCBStatuses(statuses []string) error {
	for i, status := range statuses {
		if !slices.Contains(acceptableTCBStatuses, status) {
			return fmt.Errorf("TCB status %q cannot be accepted: choose from %s", status, strings.Join(acceptableTCBStatuses, ", "))
		}
		if i > 0 && statuses[i-1] >= status {
			return fmt.Errorf("accepted TCB statuses must be sorted and named once each, and %q follows %q", status, statuses[i-1])
		}
	}
	return nil
}

type acceptedTCBKey struct{}

// WithAcceptedTCB returns a context under which an engine also takes TDX
// evidence whose platform, TDX module or quoting enclave stands at one of
// these statuses. Without it every one of the three must be UpToDate. No
// context makes an engine take Revoked.
func WithAcceptedTCB(ctx context.Context, statuses []string) context.Context {
	if len(statuses) == 0 {
		return ctx
	}
	return context.WithValue(ctx, acceptedTCBKey{}, slices.Clone(statuses))
}

// AcceptedTCB is the statuses WithAcceptedTCB put in ctx, for an engine to
// judge by.
func AcceptedTCB(ctx context.Context) []string {
	statuses, _ := ctx.Value(acceptedTCBKey{}).([]string)
	return statuses
}

// TCBFinding is where a TDX platform stands in Intel's signed TCB info: the
// status of the TCB level each component matched.
type TCBFinding struct {
	// Platform covers the CPU's SGX and TDX TCB components and the PCE.
	Platform string `json:"platform"`
	// Module is the TDX module's own level. Empty when the report names no
	// module version (TDX 1.0).
	Module string `json:"tdx_module,omitempty"`
	// QuotingEnclave is the TD quoting enclave's level.
	QuotingEnclave string `json:"quoting_enclave"`
	// Advisories are the Intel security advisories of the matched levels.
	Advisories []string `json:"advisories,omitempty"`
}

// components lists each status with the name a refusal uses for it.
func (f *TCBFinding) components() []struct{ name, status string } {
	out := []struct{ name, status string }{{"platform", f.Platform}}
	if f.Module != "" {
		out = append(out, struct{ name, status string }{"TDX module", f.Module})
	}
	return append(out, struct{ name, status string }{"quoting enclave", f.QuotingEnclave})
}

// UpToDate reports whether every component is at Intel's current level.
func (f *TCBFinding) UpToDate() bool {
	for _, c := range f.components() {
		if c.status != TCBUpToDate {
			return false
		}
	}
	return true
}

// judge holds each component to the statuses a policy accepts.
func (f *TCBFinding) judge(accepted []string) error {
	for _, c := range f.components() {
		switch {
		case c.status == TCBUpToDate:
		case c.status == TCBRevoked:
			return refuse("%s TCB level is revoked", c.name)
		case !slices.Contains(accepted, c.status):
			return refuse("%s TCB status is %s, which this policy does not accept (advisories: %s)",
				c.name, c.status, strings.Join(f.Advisories, ", "))
		}
	}
	return nil
}

// evaluateTDXTCB matches a quote against Intel's TCB info and QE identity,
// following Intel's algorithm for "Get TDX TCB Info". It reports the platform
// level, the TDX module level and the quoting enclave's level separately, and
// a policy judges each of the three: see Policy.AcceptTCBStatus.
//
// Both documents must already be authenticated: the caller passes the bytes
// go-tdx-guest verified against Intel's signing chain.
func evaluateTDXTCB(quote *pb.QuoteV4, tcbInfoJSON, qeIdentityJSON []byte) (*TCBFinding, error) {
	chain, err := tdxverify.ExtractChainFromQuote(quote)
	if err != nil {
		return nil, fmt.Errorf("PCK certificate chain: %w", err)
	}
	exts, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		return nil, fmt.Errorf("PCK certificate extensions: %w", err)
	}
	var info pcs.TdxTcbInfo
	if err := json.Unmarshal(tcbInfoJSON, &info); err != nil {
		return nil, fmt.Errorf("TCB info: %w", err)
	}
	var identity pcs.QeIdentity
	if err := json.Unmarshal(qeIdentityJSON, &identity); err != nil {
		return nil, fmt.Errorf("QE identity: %w", err)
	}
	if !strings.EqualFold(exts.FMSPC, info.TcbInfo.Fmspc) {
		return nil, fmt.Errorf("TCB info is for FMSPC %s, the PCK certificate is %s", info.TcbInfo.Fmspc, exts.FMSPC)
	}
	teeTCBSVN := quote.GetTdQuoteBody().GetTeeTcbSvn()
	if len(teeTCBSVN) != 16 {
		return nil, fmt.Errorf("TEE TCB SVN is %d bytes, want 16", len(teeTCBSVN))
	}

	platform, ok := matchPlatformLevel(info.TcbInfo.TcbLevels, exts, teeTCBSVN)
	if !ok {
		return nil, fmt.Errorf("the platform's TCB matches no level Intel publishes for FMSPC %s", exts.FMSPC)
	}
	finding := &TCBFinding{Platform: string(platform.TcbStatus)}
	advisories := map[string]bool{}
	for _, id := range platform.AdvisoryIDs {
		advisories[id] = true
	}

	// Index 1 is the TDX module's major version, index 0 its SVN.
	if teeTCBSVN[1] > 0 {
		id := "TDX_" + hex.EncodeToString(teeTCBSVN[1:2])
		module, ok := matchModuleLevel(info.TcbInfo.TdxModuleIdentities, id, uint32(teeTCBSVN[0]))
		if !ok {
			return nil, fmt.Errorf("TDX module %s at SVN %d matches no level Intel publishes", id, teeTCBSVN[0])
		}
		finding.Module = string(module.TcbStatus)
		for _, id := range module.AdvisoryIDs {
			advisories[id] = true
		}
	}

	qeSVN := quote.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetQeReport().GetIsvSvn()
	qe, ok := matchQELevel(identity.EnclaveIdentity.TcbLevels, qeSVN)
	if !ok {
		return nil, fmt.Errorf("quoting enclave SVN %d matches no level Intel publishes", qeSVN)
	}
	finding.QuotingEnclave = string(qe.TcbStatus)
	for _, id := range qe.AdvisoryIDs {
		advisories[id] = true
	}

	for id := range advisories {
		finding.Advisories = append(finding.Advisories, id)
	}
	sort.Strings(finding.Advisories)
	return finding, nil
}

// matchPlatformLevel returns the first published level, highest first, that
// the platform meets in every SGX component, the PCE SVN and the TDX
// components. With a versioned TDX module, components 0 and 1 describe the
// module and are judged by its own identity.
func matchPlatformLevel(levels []pcs.TcbLevel, exts *pcs.PckExtensions, teeTCBSVN []byte) (pcs.TcbLevel, bool) {
	firstTDX := 0
	if teeTCBSVN[1] > 0 {
		firstTDX = 2
	}
	for _, level := range levels {
		if len(level.Tcb.SgxTcbcomponents) != len(exts.TCB.CPUSvnComponents) || len(level.Tcb.TdxTcbcomponents) != len(teeTCBSVN) {
			continue
		}
		meets := exts.TCB.PCESvn >= level.Tcb.Pcesvn
		for i, have := range exts.TCB.CPUSvnComponents {
			meets = meets && have >= level.Tcb.SgxTcbcomponents[i].Svn
		}
		for i := firstTDX; i < len(teeTCBSVN); i++ {
			meets = meets && teeTCBSVN[i] >= level.Tcb.TdxTcbcomponents[i].Svn
		}
		if meets {
			return level, true
		}
	}
	return pcs.TcbLevel{}, false
}

func matchModuleLevel(identities []pcs.TdxModuleIdentity, id string, svn uint32) (pcs.TcbLevel, bool) {
	for _, identity := range identities {
		if !strings.EqualFold(identity.ID, id) {
			continue
		}
		for _, level := range identity.TcbLevels {
			if svn >= level.Tcb.Isvsvn {
				return level, true
			}
		}
	}
	return pcs.TcbLevel{}, false
}

func matchQELevel(levels []pcs.TcbLevel, svn uint32) (pcs.TcbLevel, bool) {
	for _, level := range levels {
		if svn >= level.Tcb.Isvsvn {
			return level, true
		}
	}
	return pcs.TcbLevel{}, false
}
