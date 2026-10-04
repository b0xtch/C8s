package session

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

const (
	// VerdictFile is the name of a kept verdict in a binding directory.
	VerdictFile = "verdict.json"
	// VerdictSchema is the one version of that file.
	VerdictSchema   = "c8s-session-verdict/v1"
	maxVerdictBytes = 4096
	// verdictRules is part of every scope. Raise it with any change to what a
	// judgment requires of evidence, so that a verifier never takes the
	// verdict of an earlier one that required less.
	verdictRules = 3
)

// Verdict is a client's record that it judged a guest's evidence and found
// the guest its policy names: the instance key the evidence bound, what the
// evidence was judged against, and until when that judgment stands.
//
// Kept beside a binding, it lets the same owner's next process take a TLS
// handshake that ends at that key for that guest and ask it for no quote: see
// Kept. A guest's key never leaves the guest and a guest that restarted has
// another one, while a quote is a signature from a service every guest of
// the host shares, which each guest therefore rations.
//
// The file is trusted as the access key beside it is trusted: whoever can
// write one can already drive the guest.
type Verdict struct {
	SchemaVersion string `json:"schemaVersion"`
	// InstanceKey is the PKIX DER of the guest's key.
	InstanceKey []byte `json:"instanceKey"`
	// Scope names everything the judgment depended on: see scopeOf.
	Scope string `json:"scope"`
	// Until is when the evidence has to be judged again.
	Until time.Time `json:"until"`
}

// Described is an engine that says what it requires of evidence, so that a
// verdict one process reached is taken by another only when that one would
// have required the same. A client whose engine is not Described keeps no
// verdict and takes none.
type Described interface {
	// Requirements names every setting of the engine that decides a verdict.
	Requirements() string
}

// scopeOf names what a verdict of a client with this policy and engine
// depends on: the pinned image, every document and key of the policy, what
// the policy allows, and what the engine requires. It is empty when the
// engine does not say.
func scopeOf(policy Policy, engine Engine) string {
	described, ok := engine.(Described)
	if !ok || policy.Image == nil {
		return ""
	}
	type variant struct{ Label, Digest string }
	var launch []variant
	for _, v := range policy.Image.LaunchDigests() {
		launch = append(launch, variant{v.Label, hex.EncodeToString(v.Digest[:])})
	}
	registers := map[string]string{}
	for index, value := range policy.Image.RTMRs() {
		registers[strconv.Itoa(index)] = hex.EncodeToString(value[:])
	}
	// Fields are encoded in this order and maps by sorted key.
	encoded, err := json.Marshal(struct {
		Rules                                 int
		Family                                string
		Launch                                []variant
		Registers                             map[string]string
		LaunchKey, LaunchDoc, Authority, Bind []byte
		Tenant, Session                       string
		AllowBound, AllowReady                bool
		AllowNoMachine                        bool
		AcceptTCB                             []string
		Engine                                string
	}{
		verdictRules, string(policy.Image.Family()), launch, registers,
		policy.LaunchKey, policy.Launch, policy.Authority, policy.Bind,
		policy.Tenant, policy.Session, policy.AllowBound, policy.AllowReady,
		policy.AllowNoMachine, policy.AcceptTCBStatus,
		described.Requirements(),
	})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// usable reports whether v is a verdict a client of this scope and policy
// can take. Whether it still stands is for the clock at each handshake.
//
// A bind names its guest's key under the authority's signature, and a
// verdict under a policy that pins one is taken only for that key: what the
// file adds to the binding is then that the key was attested, and until
// when, never which key.
func (v *Verdict) usable(scope string, policy Policy) bool {
	if v == nil || scope == "" || v.SchemaVersion != VerdictSchema || v.Scope != scope || v.Until.IsZero() {
		return false
	}
	key, err := x509.ParsePKIXPublicKey(v.InstanceKey)
	if err != nil {
		return false
	}
	if policy.Bind == nil {
		return true
	}
	bind, err := ParseBind(policy.Bind)
	if err != nil {
		return false
	}
	named, err := InstanceKeyDigest(key)
	return err == nil && named == bind.InstanceKey
}

// stands is until when a judgment made at now stands: for the hour its
// collateral is reused, counted from when this verifier had the root CA CRL
// from Intel where it did, and never past the end of the certificate that
// carried the key or past Intel's date on the collateral under it. leaf and
// res may be nil.
func stands(now time.Time, leaf *x509.Certificate, res *teetypes.VerificationResult) time.Time {
	until := now.Add(servingVerdictTTL)
	if leaf != nil && leaf.NotAfter.Before(until) {
		until = leaf.NotAfter
	}
	finding := CollateralOf(res)
	if finding == nil {
		return until
	}
	if !finding.Expires.IsZero() && finding.Expires.Before(until) {
		until = finding.Expires
	}
	if !finding.RootCRLFetched.IsZero() {
		if end := finding.RootCRLFetched.Add(servingVerdictTTL); end.Before(until) {
			until = end
		}
	}
	return until
}

// ErrStaleRootCRL answers a send whose verdict would rest on a root CA CRL
// this verifier had from Intel longer ago than the reuse period, because
// Intel could not be asked for a newer one. It says nothing of the guest.
var ErrStaleRootCRL = errors.New("the root CA CRL this verifier has from Intel is more than an hour old, and Intel could not be asked for a newer one")

// standsNot says why a judgment made at now, which stands until, does not
// stand at all, or returns nil when it does.
func standsNot(now, until time.Time, leaf *x509.Certificate, res *teetypes.VerificationResult) error {
	if now.Before(until) {
		return nil
	}
	if finding := CollateralOf(res); finding != nil && !finding.RootCRLFetched.IsZero() && !now.Before(finding.RootCRLFetched.Add(servingVerdictTTL)) {
		return ErrStaleRootCRL
	}
	if leaf != nil && !now.Before(leaf.NotAfter) {
		return refuse("the guest's certificate ended at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return fmt.Errorf("the collateral under the verdict ended at %s", until.UTC().Format(time.RFC3339))
}

// WriteVerdict keeps v in dir, in place of any verdict there. A reader sees
// the old file or the new one, never a part of either.
func WriteVerdict(dir string, v *Verdict) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, VerdictFile+".*")
	if err != nil {
		return fmt.Errorf("keep verdict: %w", err)
	}
	_, err = tmp.Write(append(data, '\n'))
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(dir, VerdictFile))
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("keep verdict: %w", err)
	}
	return nil
}

// LoadVerdict reads the verdict kept in dir. A directory with none gives nil
// and no error. A file that its owner's group or anyone else could have
// written, or that another user owns, is an error: it is trusted as a key
// is, and is held to a key's file mode.
func LoadVerdict(dir string) (*Verdict, error) {
	path := filepath.Join(dir, VerdictFile)
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o022 != 0 || !ownedByUs(info) {
		return nil, fmt.Errorf("kept verdict %s: mode %s, or another user's: it must be this user's and writable by nobody else", path, info.Mode().Perm())
	}
	data, err := ReadBounded(path, maxVerdictBytes)
	if err != nil {
		return nil, err
	}
	var v Verdict
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("kept verdict: %w", err)
	}
	if v.SchemaVersion != VerdictSchema {
		return nil, fmt.Errorf("kept verdict: schema %q is not %s", v.SchemaVersion, VerdictSchema)
	}
	return &v, nil
}
