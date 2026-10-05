package simtee

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/pcs"
)

// Evaluation is the TCB evaluation data number the simulated vendor's
// documents carry unless told otherwise: the one a verifier shipped with
// this tree takes as the oldest.
const Evaluation = 20

// reissueAfter is how long the simulated vendor answers with the document it
// last signed before it signs another, as the vendor's service does.
const reissueAfter = time.Hour

// Vendor stands for the vendor's service: it answers for the four documents
// a quote of its authority's platforms is judged against, each signed when
// it is first asked for and again an hour later. A test has it say what the
// vendor's service cannot be made to say.
type Vendor struct {
	authority *Authority
	now       func() time.Time

	mu sync.Mutex
	// revoked are the serials on each CRL.
	revokedPlatforms, revokedCAs []*big.Int
	// platform, module and enclave are the statuses of the levels the
	// simulated platform, its TDX module and its quoting enclave meet.
	platform, module, enclave pcs.TcbComponentStatus
	evaluation                int
	down                      error
	asked                     []string
	// signed are the documents as last signed, by URL, and state counts the
	// changes a test made since: a document signed under an earlier state
	// is signed anew.
	signed map[string]signed
	state  int
}

type signed struct {
	at     time.Time
	state  int
	header map[string][]string
	body   []byte
}

// NewVendor returns a vendor for authority whose clock is now.
func NewVendor(authority *Authority, now func() time.Time) *Vendor {
	return &Vendor{
		authority: authority, now: now, evaluation: Evaluation,
		platform: pcs.TcbComponentStatusUpToDate, module: pcs.TcbComponentStatusUpToDate, enclave: pcs.TcbComponentStatusUpToDate,
		signed: map[string]signed{},
	}
}

func (v *Vendor) change(apply func()) {
	v.mu.Lock()
	defer v.mu.Unlock()
	apply()
	v.state++
}

// Revoke puts a certificate of the authority's on the CRL of its issuer:
// a platform's on the platform CA's, and the platform CA's or the documents'
// signer's on the root's.
func (v *Vendor) Revoke(cert *x509.Certificate) {
	v.change(func() {
		if cert.Issuer.String() == v.authority.PlatformCA.Cert.Subject.String() && !cert.IsCA {
			v.revokedPlatforms = append(v.revokedPlatforms, cert.SerialNumber)
			return
		}
		v.revokedCAs = append(v.revokedCAs, cert.SerialNumber)
	})
}

// SetStatus has the documents say where the simulated platform, its TDX
// module and its quoting enclave stand. An empty status leaves one as it is.
func (v *Vendor) SetStatus(platform, module, enclave string) {
	v.change(func() {
		for _, set := range []struct {
			to   *pcs.TcbComponentStatus
			from string
		}{{&v.platform, platform}, {&v.module, module}, {&v.enclave, enclave}} {
			if set.from != "" {
				*set.to = pcs.TcbComponentStatus(set.from)
			}
		}
	})
}

// SetEvaluation has the TCB info and the enclave identity carry another TCB
// evaluation data number.
func (v *Vendor) SetEvaluation(number int) { v.change(func() { v.evaluation = number }) }

// SetDown has every request fail with err, or answer again with nil.
func (v *Vendor) SetDown(err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.down = err
}

// Asked is every URL the vendor was asked for, in order.
func (v *Vendor) Asked() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.asked...)
}

// Get answers for one document as the vendor's service does: the response's
// headers, which carry the chain the document is signed under, and its body.
func (v *Vendor) Get(document string) (map[string][]string, []byte, error) {
	return v.GetContext(context.Background(), document)
}

// GetContext is Get.
func (v *Vendor) GetContext(_ context.Context, document string) (map[string][]string, []byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.asked = append(v.asked, document)
	if v.down != nil {
		return nil, nil, v.down
	}
	now := v.now()
	if kept, ok := v.signed[document]; ok && kept.state == v.state && now.Sub(kept.at) >= 0 && now.Sub(kept.at) < reissueAfter {
		return kept.header, kept.body, nil
	}
	header, body, err := v.sign(document, now)
	if err != nil {
		return nil, nil, err
	}
	v.signed[document] = signed{at: now, state: v.state, header: header, body: body}
	return header, body, nil
}

// sign makes the document at an address anew. The caller holds the lock.
func (v *Vendor) sign(document string, now time.Time) (map[string][]string, []byte, error) {
	a := v.authority
	switch {
	case document == pcs.TcbInfoURL(FMSPC):
		body, err := v.signedJSON("tcbInfo", v.tcbInfo(now))
		return map[string][]string{pcs.TcbInfoIssuerChainPhrase: {chainHeader(a.Signer.Cert, a.Root.Cert)}}, body, err
	case document == pcs.QeIdentityURL():
		body, err := v.signedJSON("enclaveIdentity", v.enclaveIdentity(now))
		return map[string][]string{pcs.SgxQeIdentityIssuerChainPhrase: {chainHeader(a.Signer.Cert, a.Root.Cert)}}, body, err
	case document == pcs.PckCrlURL("platform"):
		body, err := crl(&a.PlatformCA, v.revokedPlatforms, now, now.AddDate(0, 0, 30))
		return map[string][]string{pcs.SgxPckCrlIssuerChainPhrase: {chainHeader(a.PlatformCA.Cert, a.Root.Cert)}}, body, err
	case document == RootCRLURL:
		body, err := crl(&a.Root, v.revokedCAs, now, now.AddDate(1, 0, 0))
		return map[string][]string{}, body, err
	}
	return nil, nil, fmt.Errorf("%s answered 404 Not Found", document)
}

// chainHeader is a signing certificate and its root as the vendor's service
// puts them in a response header.
func chainHeader(certs ...*x509.Certificate) string {
	return url.QueryEscape(string(chainPEM(certs...)))
}

func crl(by *issuer, revoked []*big.Int, issued, next time.Time) ([]byte, error) {
	template := &x509.RevocationList{Number: big.NewInt(issued.Unix()), ThisUpdate: issued, NextUpdate: next}
	for _, number := range revoked {
		template.RevokedCertificateEntries = append(template.RevokedCertificateEntries,
			x509.RevocationListEntry{SerialNumber: number, RevocationTime: issued.Add(-time.Minute)})
	}
	return x509.CreateRevocationList(rand.Reader, template, by.Cert, by.Key)
}

// signedJSON is a document of the vendor's: one member, and the signer's
// signature over that member's bytes.
func (v *Vendor) signedJSON(name string, member any) ([]byte, error) {
	raw, err := json.Marshal(member)
	if err != nil {
		return nil, err
	}
	signature, err := signRaw(v.authority.Signer.Key, raw)
	if err != nil {
		return nil, err
	}
	return []byte(`{"` + name + `":` + string(raw) + `,"signature":"` + hex.EncodeToString(signature) + `"}`), nil
}

// The documents' members, as the vendor's service spells them.
type (
	component struct {
		SVN byte `json:"svn"`
	}
	tcb struct {
		SGX    []component `json:"sgxtcbcomponents,omitempty"`
		PCESVN *uint16     `json:"pcesvn,omitempty"`
		TDX    []component `json:"tdxtcbcomponents,omitempty"`
		ISVSVN *uint32     `json:"isvsvn,omitempty"`
	}
	level struct {
		TCB         tcb                    `json:"tcb"`
		Date        string                 `json:"tcbDate"`
		Status      pcs.TcbComponentStatus `json:"tcbStatus"`
		AdvisoryIDs []string               `json:"advisoryIDs,omitempty"`
	}
	module struct {
		ID             string  `json:"id,omitempty"`
		MRSigner       string  `json:"mrsigner"`
		Attributes     string  `json:"attributes"`
		AttributesMask string  `json:"attributesMask"`
		Levels         []level `json:"tcbLevels,omitempty"`
	}
	tcbInfo struct {
		ID         string    `json:"id"`
		Version    int       `json:"version"`
		IssueDate  time.Time `json:"issueDate"`
		NextUpdate time.Time `json:"nextUpdate"`
		FMSPC      string    `json:"fmspc"`
		PCEID      string    `json:"pceId"`
		Type       int       `json:"tcbType"`
		Evaluation int       `json:"tcbEvaluationDataNumber"`
		Module     module    `json:"tdxModule"`
		Modules    []module  `json:"tdxModuleIdentities"`
		Levels     []level   `json:"tcbLevels"`
	}
	enclaveIdentity struct {
		ID             string    `json:"id"`
		Version        int       `json:"version"`
		IssueDate      time.Time `json:"issueDate"`
		NextUpdate     time.Time `json:"nextUpdate"`
		Evaluation     int       `json:"tcbEvaluationDataNumber"`
		MiscSelect     string    `json:"miscselect"`
		MiscSelectMask string    `json:"miscselectMask"`
		Attributes     string    `json:"attributes"`
		AttributesMask string    `json:"attributesMask"`
		MRSigner       string    `json:"mrsigner"`
		ProdID         int       `json:"isvprodid"`
		Levels         []level   `json:"tcbLevels"`
	}
)

func components(svn []byte) []component {
	out := make([]component, len(svn))
	for i, v := range svn {
		out[i] = component{SVN: v}
	}
	return out
}

func upper(raw []byte) string { return strings.ToUpper(hex.EncodeToString(raw)) }

// advisory is what a level that is not current names as its reason.
const advisory = "C8S-SIMULATED-00001"

func (v *Vendor) levelOf(status pcs.TcbComponentStatus, issued time.Time, of tcb) level {
	l := level{TCB: of, Date: issued.UTC().Format(time.RFC3339), Status: status}
	if status != pcs.TcbComponentStatusUpToDate {
		l.AdvisoryIDs = []string{advisory}
	}
	return l
}

// tcbInfo says where the simulated platform stands: the level it meets, and
// a lower one that every platform of its kind meets.
func (v *Vendor) tcbInfo(now time.Time) tcbInfo {
	issued := now.UTC().Truncate(time.Second)
	pce, low := uint16(PCESVN), uint16(0)
	moduleSVN, zero := uint32(TEETCBSVN[0]), uint32(0)
	// With a module version in component 1, components 0 and 1 are judged
	// by the module's own identity.
	meets := TEETCBSVN
	intel := module{MRSigner: upper(make([]byte, 48)), Attributes: upper(make([]byte, 8)), AttributesMask: upper([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})}
	versioned := intel
	versioned.ID = fmt.Sprintf("TDX_%02X", TEETCBSVN[1])
	versioned.Levels = []level{
		v.levelOf(v.module, issued, tcb{ISVSVN: &moduleSVN}),
		v.levelOf(pcs.TcbComponentStatusOutOfDate, issued, tcb{ISVSVN: &zero}),
	}
	return tcbInfo{
		ID: "TDX", Version: 3, IssueDate: issued, NextUpdate: issued.AddDate(0, 0, 30),
		FMSPC: strings.ToUpper(FMSPC), PCEID: strings.ToUpper(PCEID), Evaluation: v.evaluation,
		Module: intel, Modules: []module{versioned},
		Levels: []level{
			v.levelOf(v.platform, issued, tcb{SGX: components(CPUSVN[:]), PCESVN: &pce, TDX: components(meets[:])}),
			v.levelOf(pcs.TcbComponentStatusOutOfDate, issued, tcb{SGX: components(make([]byte, 16)), PCESVN: &low, TDX: components(make([]byte, 16))}),
		},
	}
}

// enclaveIdentity names the vendor's TD quoting enclave, which a simulated
// quote's enclave report is made to look like, and where its version stands.
func (v *Vendor) enclaveIdentity(now time.Time) enclaveIdentity {
	issued := now.UTC().Truncate(time.Second)
	svn, zero := uint32(QESVN), uint32(0)
	return enclaveIdentity{
		ID: "TD_QE", Version: 2, IssueDate: issued, NextUpdate: issued.AddDate(0, 0, 30), Evaluation: v.evaluation,
		MiscSelect: "00000000", MiscSelectMask: "FFFFFFFF",
		Attributes: upper(qeAttributes[:]), AttributesMask: upper([]byte{0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}),
		MRSigner: upper(qeMrSigner[:]), ProdID: qeProdID,
		Levels: []level{
			v.levelOf(v.enclave, issued, tcb{ISVSVN: &svn}),
			v.levelOf(pcs.TcbComponentStatusOutOfDate, issued, tcb{ISVSVN: &zero}),
		},
	}
}

// Subjects of a simulated authority's certificates carry Marker.
var errUnmarked = errors.New("a certificate of a simulated authority does not say so in its subject")

// Marked reports whether every certificate names itself as simulated.
func Marked(certs ...*x509.Certificate) error {
	for _, cert := range certs {
		if !marked(cert.Subject) {
			return errUnmarked
		}
	}
	return nil
}

func marked(name pkix.Name) bool {
	for _, organization := range name.Organization {
		if organization == Marker {
			return true
		}
	}
	return false
}
