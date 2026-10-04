package session_test

import (
	"context"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

func machineOf(td *sessiontest.TD) string { return hex.EncodeToString(td.RTMR[0][:]) }

// A launch document may list the machines its guests may be, as values of
// RTMR[0], in one order.
func TestLaunchDocumentMachines(t *testing.T) {
	td := sessiontest.NewTD()
	a, b := strings.Repeat("a", 96), strings.Repeat("b", 96)
	_, pinned := newBundle(t, td, func(o *session.BundleOptions) { o.Machines = []string{b, a} })
	doc := pinned.Document
	if doc.Machine == nil || !slices.Equal(doc.Machine.RTMR0, []string{a, b}) {
		t.Fatalf("the document lists %+v", doc.Machine)
	}
	raw := func(s string) []byte {
		out, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if !doc.Machine.Allows(raw(a)) || !doc.Machine.Allows(raw(b)) || doc.Machine.Allows(raw(strings.Repeat("c", 96))) || doc.Machine.Allows(nil) {
		t.Fatal("the area does not allow exactly what it lists")
	}
	// A document that lists none allows any machine.
	_, plain := newBundle(t, td, nil)
	if plain.Document.Machine != nil || !plain.Document.Machine.Allows(raw(a)) {
		t.Fatalf("a document with no list: %+v", plain.Document.Machine)
	}
	// It carries its list beside its list of images.
	_, both := newBundle(t, td, func(o *session.BundleOptions) {
		o.Prestage, o.Machines = []string{sandboxImage}, []string{a}
	})
	if d := both.Document; len(d.Prestage) != 1 || !slices.Equal(d.Machine.RTMR0, []string{a}) {
		t.Fatalf("the document: %+v, %v", d.Machine, d.Prestage)
	}
	// The same value twice is refused when the document is written.
	if err := session.NewBundle(session.BundleOptions{
		Dir: t.TempDir() + "/twice", ManifestPath: td.WriteManifest(t), Pool: "agents", Class: "s-4x16", Machines: []string{a, a},
	}); err == nil {
		t.Fatal("a document that lists one machine twice was signed")
	}

	valid := string(pinned.Launch)
	list := "machine:\n    rtmr0:\n        - " + a + "\n        - " + b + "\n"
	if !strings.Contains(valid, list) {
		t.Fatalf("fixture: the document does not render its list as expected:\n%s", valid)
	}
	relist := func(values ...string) string {
		out := "machine:\n    rtmr0:\n"
		for _, v := range values {
			out += "        - " + v + "\n"
		}
		return strings.Replace(valid, list, out, 1)
	}
	many := make([]string, session.MaxMachines+1)
	for i := range many {
		many[i] = "a" + strings.Repeat("0", 94) + string("0123456789abcdef"[i])
	}
	digits := strings.Repeat("7", 96)
	for name, text := range map[string]string{
		"an empty list":        strings.Replace(valid, list, "machine:\n    rtmr0: []\n", 1),
		"no list":              strings.Replace(valid, list, "machine: {}\n", 1),
		"descending":           relist(b, a),
		"one value twice":      relist(a, a),
		"an uppercase value":   relist(strings.ToUpper(a), b),
		"a short value":        relist(a[:95], b),
		"a long value":         relist(a, b+"b"),
		"not hex":              relist(a, strings.Repeat("g", 96)),
		"more than the bound":  relist(many...),
		"a field of its own":   strings.Replace(valid, list, list+"    shape: small\n", 1),
		"a value under a name": strings.Replace(valid, list, "machine:\n    rtmr0:\n        small: "+a+"\n", 1),
		// Digits alone are a number to a YAML reader unless they are quoted.
		"a value of digits, bare": relist(digits, a),
	} {
		if _, err := session.Parse([]byte(text)); err == nil {
			t.Errorf("%s: accepted:\n%s", name, text)
		}
	}
	if _, err := session.Parse([]byte(relist(many[:session.MaxMachines]...))); err != nil {
		t.Errorf("a document that lists %d machines: %v", session.MaxMachines, err)
	}
	if doc, err := session.Parse([]byte(relist(`"`+digits+`"`, a))); err != nil || doc.Machine.RTMR0[0] != digits {
		t.Errorf("a value of digits, quoted: %v", err)
	}

	// Only a TD has the register.
	snp := *doc
	snp.Image = session.Image{Platform: "snp", Measurement: strings.Repeat("1", 96)}
	if err := snp.Validate(); err == nil || !strings.Contains(err.Error(), "TDX") {
		t.Fatalf("a machine pinned for an SEV-SNP guest: %v", err)
	}
	snp.Machine = nil
	if err := snp.Validate(); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// A verifier holds a guest to the machines its launch document lists: the
// host that built the guest another machine gets no verdict for it, on a
// fresh attestation or on the evidence in a serving certificate.
func TestVerifierHoldsAGuestToItsDocumentsMachines(t *testing.T) {
	td := sessiontest.NewTD()
	other := strings.Repeat("0", 96)
	_, bundle := newBundle(t, td, func(o *session.BundleOptions) { o.Machines = []string{machineOf(td), other} })
	g := bootGuest(t, td, bundle, newKey(t), nil, session.PhaseReady)
	policy := policyFor(t, td, bundle)
	policy.AllowReady = true
	nonce := freshNonce(t)
	att, err := session.VerifyAttestation(context.Background(), policy, sessiontest.Engine{}, &g.key.PublicKey, nonce, g.attest(t, nonce))
	if err != nil || att.Document.Machine == nil {
		t.Fatalf("a guest on a machine its document lists: %v", err)
	}
	// Required of it, it has one.
	policy.RequireMachine = true
	if _, err := session.VerifyAttestation(context.Background(), policy, sessiontest.Engine{}, &g.key.PublicKey, nonce, g.attest(t, nonce)); err != nil {
		t.Fatalf("a pinned machine, required: %v", err)
	}
	// The same guest in every other respect, on a machine the document does
	// not list.
	td.RTMR[0][0] ^= 1
	assertRefused(t, policy, &g.key.PublicKey, nonce, g.attest(t, nonce), "is none of the 2 its launch document lists")
	policy.RequireMachine = false
	assertRefused(t, policy, &g.key.PublicKey, nonce, g.attest(t, nonce), "is none of the 2 its launch document lists")
}

// A document that pins no machine is taken as before, unless the policy
// wants one pinned.
func TestVerifierMayRequireAPinnedMachine(t *testing.T) {
	td := sessiontest.NewTD()
	_, bundle := newBundle(t, td, nil)
	g := bootGuest(t, td, bundle, newKey(t), nil, session.PhaseReady)
	policy := policyFor(t, td, bundle)
	policy.AllowReady = true
	nonce := freshNonce(t)
	if _, err := session.VerifyAttestation(context.Background(), policy, sessiontest.Engine{}, &g.key.PublicKey, nonce, g.attest(t, nonce)); err != nil {
		t.Fatal(err)
	}
	// Any machine will do for it.
	td.RTMR[0][0] ^= 1
	if _, err := session.VerifyAttestation(context.Background(), policy, sessiontest.Engine{}, &g.key.PublicKey, nonce, g.attest(t, nonce)); err != nil {
		t.Fatalf("a document that pins no machine, on another machine: %v", err)
	}
	policy.RequireMachine = true
	assertRefused(t, policy, &g.key.PublicKey, nonce, g.attest(t, nonce), "pins no machine")
}
