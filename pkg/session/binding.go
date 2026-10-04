package session

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	agratls "github.com/confidential-dot-ai/attestation-go/ratls"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// Phase is where the guest is in its one-way life. Each phase has exactly one
// measured event chain, so a verifier knows which register value to expect.
type Phase string

const (
	// PhaseReady: the guest has measured its launch document and waits for
	// its one bind. It belongs to nobody and nobody can drive it.
	PhaseReady Phase = "ready"
	// PhaseBound: the launch document and the bind are verified and
	// measured; the sandbox image has not been admitted yet.
	PhaseBound Phase = "bound"
	// PhaseRunning: the sandbox image the bind names is measured and started.
	// A bind without a sandbox reaches this phase directly.
	PhaseRunning Phase = "running"
)

// attestDomain separates the evidence transcript from every other SHA-256 input.
const attestDomain = "c8s-session-attest/v1\x00"

// NonceSize is the verifier nonce length for a fresh attestation.
const NonceSize = 32

// ExpectedEvents is the ordered digest chain a guest in phase must have
// extended on top of the launch-key seed: the launch document first, then
// the bind, then the sandbox image once it runs. launch is the exact
// launch.yaml bytes; bind is nil for a guest nobody has bound.
func ExpectedEvents(launch []byte, bind *SignedBind, phase Phase) ([]string, error) {
	events := []string{DocumentDigest(launch)}
	if phase == PhaseReady {
		if bind != nil {
			return nil, fmt.Errorf("a guest in phase %s has no bind", PhaseReady)
		}
		return events, nil
	}
	if bind == nil {
		return nil, fmt.Errorf("a guest in phase %s has a bind", phase)
	}
	events = append(events, DocumentDigest(bind.Raw))
	sandbox := bind.Doc.Policy.Sandbox
	switch phase {
	case PhaseBound:
		if sandbox == nil {
			return nil, fmt.Errorf("a guest without a sandbox has no %s phase", PhaseBound)
		}
	case PhaseRunning:
		if sandbox != nil {
			digest, err := sandbox.Digest()
			if err != nil {
				return nil, err
			}
			events = append(events, digest)
		}
	default:
		return nil, fmt.Errorf("unknown phase %q", phase)
	}
	return events, nil
}

// EvidenceBinding folds the verifier's nonce and the guest's measured events
// into the nonce of a fresh attestation. On SEV-SNP, which has no runtime
// register, this transcript is the only place the events are bound.
func EvidenceBinding(nonce []byte, events []string) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("attestation nonce must be %d bytes", NonceSize)
	}
	h := sha256.New()
	h.Write([]byte(attestDomain))
	h.Write(nonce)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(events)))
	h.Write(n[:])
	for _, event := range events {
		raw, err := eventBytes(event)
		if err != nil {
			return nil, err
		}
		h.Write(raw)
	}
	return h.Sum(nil), nil
}

// ReportData is the REPORTDATA a fresh attestation must carry: the RA-TLS key
// binding over the instance key, with the evidence binding as its nonce. The
// first 48 bytes are the digest; hardware zero-pads the rest.
func ReportData(instanceKey crypto.PublicKey, nonce []byte, events []string) ([]byte, error) {
	binding, err := EvidenceBinding(nonce, events)
	if err != nil {
		return nil, err
	}
	rd, err := agratls.ReportDataForKey(instanceKey, binding)
	if err != nil {
		return nil, err
	}
	return rd[:sha512.Size384], nil
}

// eventBytes decodes one canonical "sha256:<64 hex>" event to its 32 bytes.
func eventBytes(event string) ([]byte, error) {
	canonical, err := runtimemeasure.CanonicalDigest(event)
	if err != nil || canonical != event {
		return nil, fmt.Errorf("event %q is not a canonical sha256 digest", event)
	}
	return hex.DecodeString(strings.TrimPrefix(event, "sha256:"))
}
