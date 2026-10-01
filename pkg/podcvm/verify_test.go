package podcvm_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
	"github.com/confidential-dot-ai/c8s/pkg/podcvm"
)

// guest simulates what the measured agent does to the registers and what it
// answers to an attestation request.
type guest struct {
	td     *podcvmtest.TD
	bundle *podcvm.Bundle
	key    *ecdsa.PrivateKey
	events []string
	phase  podcvm.Phase
}

func bootGuest(t *testing.T, td *podcvmtest.TD, bundle *podcvm.Bundle, phase podcvm.Phase) *guest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	events, err := podcvm.ExpectedEvents(bundle.Launch, bundle.Document, phase)
	if err != nil {
		t.Fatal(err)
	}
	td.SeedLaunchKey(bundle.LaunchKey)
	for _, event := range events {
		digest := runtimemeasure.Event(event)
		if err := td.Extend(digest[:]); err != nil {
			t.Fatal(err)
		}
	}
	return &guest{td: td, bundle: bundle, key: key, events: events, phase: phase}
}

func (g *guest) attest(t *testing.T, nonce []byte) *podcvm.AttestResponse {
	t.Helper()
	rd, err := podcvm.ReportData(&g.key.PublicKey, nonce, g.events)
	if err != nil {
		t.Fatal(err)
	}
	return &podcvm.AttestResponse{
		Evidence:  g.td.Evidence(rd),
		Launch:    bytes.Clone(g.bundle.Launch),
		Signature: g.bundle.Signature,
		Events:    append([]string(nil), g.events...),
		Phase:     g.phase,
	}
}

func policyFor(t *testing.T, td *podcvmtest.TD, bundle *podcvm.Bundle) podcvm.Policy {
	t.Helper()
	identity, err := runtimemeasure.LoadImageManifest(td.WriteManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	return podcvm.Policy{Image: identity, LaunchKey: bundle.LaunchKey, Launch: bundle.Launch}
}

func freshNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, podcvm.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return nonce
}

func withWorkload(o *podcvm.BundleOptions) {
	o.Workload = &podcvm.Workload{Image: workloadImage}
}

func TestVerifyAttestationAccepts(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*podcvm.BundleOptions)
		phase  podcvm.Phase
		events int
	}{
		"no workload":      {nil, podcvm.PhaseRunning, 1},
		"workload running": {withWorkload, podcvm.PhaseRunning, 2},
	} {
		t.Run(name, func(t *testing.T) {
			td := podcvmtest.NewTD()
			_, bundle := newBundle(t, td, tc.mutate)
			g := bootGuest(t, td, bundle, tc.phase)
			nonce := freshNonce(t)
			att, err := podcvm.VerifyAttestation(context.Background(), policyFor(t, td, bundle), podcvmtest.Engine{}, &g.key.PublicKey, nonce, g.attest(t, nonce))
			if err != nil {
				t.Fatalf("VerifyAttestation: %v", err)
			}
			if len(att.Events) != tc.events || att.Phase != tc.phase || att.Document.Sandbox != "sbx-1" || len(att.InstanceKey) == 0 {
				t.Fatalf("unexpected attestation: %+v", att)
			}
		})
	}
}

func TestVerifyAttestationPinsTenantWithoutDocument(t *testing.T) {
	td := podcvmtest.NewTD()
	_, bundle := newBundle(t, td, nil)
	g := bootGuest(t, td, bundle, podcvm.PhaseRunning)
	policy := policyFor(t, td, bundle)
	policy.Launch = nil
	nonce := freshNonce(t)

	if _, err := podcvm.VerifyAttestation(context.Background(), policy, podcvmtest.Engine{}, &g.key.PublicKey, nonce, g.attest(t, nonce)); err == nil {
		t.Fatal("a policy pinning neither the document nor the tenant was accepted")
	}
	policy.Tenant, policy.Sandbox = "acme.user-42", "sbx-1"
	if _, err := podcvm.VerifyAttestation(context.Background(), policy, podcvmtest.Engine{}, &g.key.PublicKey, nonce, g.attest(t, nonce)); err != nil {
		t.Fatalf("tenant-pinned policy: %v", err)
	}
	policy.Tenant = "someone-else"
	assertRefused(t, policy, &g.key.PublicKey, nonce, g.attest(t, nonce), "tenant")
}

func assertRefused(t *testing.T, policy podcvm.Policy, key *ecdsa.PublicKey, nonce []byte, resp *podcvm.AttestResponse, want string) {
	t.Helper()
	_, err := podcvm.VerifyAttestation(context.Background(), policy, podcvmtest.Engine{}, key, nonce, resp)
	if err == nil {
		t.Fatal("accepted")
	}
	var verdict *podcvm.VerificationError
	if !errors.As(err, &verdict) {
		t.Fatalf("refusal is not a VerificationError: %v", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refused for the wrong reason: %v (want %q)", err, want)
	}
}

// Each case is one way a host could hand a verifier evidence that is not the
// pinned guest, launched for this key, running this document, fresh, and bound
// to this key. Every one must be refused, and for the reason named.
func TestVerifyAttestationRejects(t *testing.T) {
	type world struct {
		td     *podcvmtest.TD
		dir    string
		bundle *podcvm.Bundle
		g      *guest
		policy podcvm.Policy
		nonce  []byte
		key    *ecdsa.PublicKey
		resp   *podcvm.AttestResponse
	}
	build := func(t *testing.T) *world {
		td := podcvmtest.NewTD()
		dir, bundle := newBundle(t, td, withWorkload)
		g := bootGuest(t, td, bundle, podcvm.PhaseRunning)
		nonce := freshNonce(t)
		return &world{td: td, dir: dir, bundle: bundle, g: g, policy: policyFor(t, td, bundle), nonce: nonce, key: &g.key.PublicKey, resp: g.attest(t, nonce)}
	}
	// sameKey signs another document with the tenant's own launch key: the
	// case where the host swaps in a document the developer really did sign.
	sameKey := func(t *testing.T, w *world, mutate func(*podcvm.BundleOptions)) *podcvm.Bundle {
		_, other := newBundle(t, w.td, func(o *podcvm.BundleOptions) {
			withWorkload(o)
			o.KeyPath = filepath.Join(w.dir, podcvm.BundleKeyFile)
			if mutate != nil {
				mutate(o)
			}
		})
		if !bytes.Equal(other.LaunchKey, w.bundle.LaunchKey) {
			t.Fatal("fixture: second bundle is not signed by the same launch key")
		}
		return other
	}
	otherKey := func(t *testing.T) *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}

	for name, tc := range map[string]struct {
		break_ func(t *testing.T, w *world)
		want   string
	}{
		"stale evidence replayed for a new nonce": {func(t *testing.T, w *world) {
			w.nonce = freshNonce(t)
		}, "REPORTDATA"},
		"evidence bound to another key": {func(t *testing.T, w *world) {
			w.key = &otherKey(t).PublicKey
		}, "REPORTDATA"},
		"different guest image (MRTD)": {func(t *testing.T, w *world) {
			w.td.MRTD[0] ^= 1
			w.resp = w.g.attest(t, w.nonce)
		}, "MRTD mismatch"},
		"different kernel (RTMR[1])": {func(t *testing.T, w *world) {
			w.td.RTMR[1][5] ^= 1
			w.resp = w.g.attest(t, w.nonce)
		}, "image pin mismatch"},
		"different rootfs (RTMR[2])": {func(t *testing.T, w *world) {
			w.td.RTMR[2][5] ^= 1
			w.resp = w.g.attest(t, w.nonce)
		}, "image pin mismatch"},
		"debug guest": {func(t *testing.T, w *world) {
			w.td.Debug = true
			w.resp = w.g.attest(t, w.nonce)
		}, "debug"},
		"extra event extended after the workload": {func(t *testing.T, w *world) {
			extra := runtimemeasure.Event("sha256:" + strings.Repeat("9", 64))
			if err := w.td.Extend(extra[:]); err != nil {
				t.Fatal(err)
			}
			w.resp = w.g.attest(t, w.nonce)
		}, "RTMR[3]"},
		"guest launched for another key": {func(t *testing.T, w *world) {
			// The host boots the pinned image with its own key and a document it
			// signed itself, then replays the tenant's signed document.
			attacker := otherKey(t)
			pub, err := podcvm.PublicKeyPEM(&attacker.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			td := podcvmtest.NewTD()
			td.MRTD, td.RTMR[1], td.RTMR[2] = w.td.MRTD, w.td.RTMR[1], w.td.RTMR[2]
			td.SeedLaunchKey(pub)
			for _, event := range w.g.events {
				digest := runtimemeasure.Event(event)
				if err := td.Extend(digest[:]); err != nil {
					t.Fatal(err)
				}
			}
			w.g.td = td
			w.resp = w.g.attest(t, w.nonce)
		}, "RTMR[3]"},
		"document replaced under the original signature": {func(t *testing.T, w *world) {
			w.resp.Launch = sameKey(t, w, nil).Launch
		}, "signature"},
		"another tenant's document, validly signed by the same key": {func(t *testing.T, w *world) {
			other := sameKey(t, w, func(o *podcvm.BundleOptions) { o.Tenant = "another-tenant" })
			w.resp.Launch, w.resp.Signature = other.Launch, other.Signature
		}, "policy pins"},
		"same-key document for another tenant, policy pins the tenant": {func(t *testing.T, w *world) {
			other := sameKey(t, w, func(o *podcvm.BundleOptions) { o.Tenant = "another-tenant" })
			w.resp.Launch, w.resp.Signature = other.Launch, other.Signature
			w.policy.Launch, w.policy.Tenant, w.policy.Sandbox = nil, "acme.user-42", "sbx-1"
		}, "tenant"},
		"same-key document for this tenant that the guest never measured": {func(t *testing.T, w *world) {
			// Same tenant and sandbox, so only the measurement can tell them apart.
			other := sameKey(t, w, nil)
			w.resp.Launch, w.resp.Signature = other.Launch, other.Signature
			w.policy.Launch, w.policy.Tenant, w.policy.Sandbox = nil, "acme.user-42", "sbx-1"
		}, "events"},
		"unmeasured same-key document with events rewritten to match": {func(t *testing.T, w *world) {
			other := sameKey(t, w, nil)
			w.resp.Launch, w.resp.Signature = other.Launch, other.Signature
			events, err := podcvm.ExpectedEvents(other.Launch, other.Document, podcvm.PhaseRunning)
			if err != nil {
				t.Fatal(err)
			}
			w.resp.Events = events
			w.policy.Launch, w.policy.Tenant, w.policy.Sandbox = nil, "acme.user-42", "sbx-1"
		}, "REPORTDATA"},
		"workload event claimed but not measured": {func(t *testing.T, w *world) {
			td := podcvmtest.NewTD()
			td.MRTD, td.RTMR[1], td.RTMR[2] = w.td.MRTD, w.td.RTMR[1], w.td.RTMR[2]
			td.SeedLaunchKey(w.bundle.LaunchKey)
			digest := runtimemeasure.Event(w.g.events[0])
			if err := td.Extend(digest[:]); err != nil {
				t.Fatal(err)
			}
			w.g.td = td
			w.resp = w.g.attest(t, w.nonce)
		}, "RTMR[3]"},
		"events reordered": {func(t *testing.T, w *world) {
			w.resp.Events[0], w.resp.Events[1] = w.resp.Events[1], w.resp.Events[0]
		}, "events"},
		"staged guest when the policy wants the workload": {func(t *testing.T, w *world) {
			w.resp.Phase = podcvm.PhaseStaged
		}, "phase"},
		"unknown phase": {func(t *testing.T, w *world) {
			w.resp.Phase = "ready"
		}, "phase"},
		"evidence truncated": {func(t *testing.T, w *world) {
			w.resp.Evidence.Evidence = w.resp.Evidence.Evidence[:len(w.resp.Evidence.Evidence)/2]
		}, "signature"},
		"platform relabelled": {func(t *testing.T, w *world) {
			w.resp.Evidence.Platform = "snp"
		}, "platform"},
		"policy pins another image": {func(t *testing.T, w *world) {
			other := podcvmtest.NewTD()
			w.policy = policyFor(t, other, w.bundle)
		}, "image measurement"},
		"policy pins another launch key": {func(t *testing.T, w *world) {
			pub, err := podcvm.PublicKeyPEM(&otherKey(t).PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			w.policy.LaunchKey = pub
		}, "signature"},
	} {
		t.Run(name, func(t *testing.T) {
			w := build(t)
			if _, err := podcvm.VerifyAttestation(context.Background(), w.policy, podcvmtest.Engine{}, w.key, w.nonce, w.resp); err != nil {
				t.Fatalf("control must pass before the break: %v", err)
			}
			tc.break_(t, w)
			assertRefused(t, w.policy, w.key, w.nonce, w.resp, tc.want)
		})
	}
}

func TestStagedGuestNeedsAllowStaged(t *testing.T) {
	td := podcvmtest.NewTD()
	_, bundle := newBundle(t, td, withWorkload)
	g := bootGuest(t, td, bundle, podcvm.PhaseStaged)
	policy := policyFor(t, td, bundle)
	nonce := freshNonce(t)

	assertRefused(t, policy, &g.key.PublicKey, nonce, g.attest(t, nonce), "phase")
	policy.AllowStaged = true
	att, err := podcvm.VerifyAttestation(context.Background(), policy, podcvmtest.Engine{}, &g.key.PublicKey, nonce, g.attest(t, nonce))
	if err != nil || att.Phase != podcvm.PhaseStaged || len(att.Events) != 1 {
		t.Fatalf("staged attestation = %+v, %v", att, err)
	}
	// A staged guest must not pass as running by claiming the later phase.
	resp := g.attest(t, nonce)
	resp.Phase = podcvm.PhaseRunning
	assertRefused(t, policy, &g.key.PublicKey, nonce, resp, "events")
}

func TestSessionBindingCommitsToEveryInput(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, podcvm.NonceSize)
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	base, err := podcvm.SessionBinding(nonce, []string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{8}, podcvm.NonceSize)
	for name, tc := range map[string]struct {
		nonce  []byte
		events []string
	}{
		"nonce":         {other, []string{a, b}},
		"event order":   {nonce, []string{b, a}},
		"event dropped": {nonce, []string{a}},
		"event added":   {nonce, []string{a, b, a}},
	} {
		got, err := podcvm.SessionBinding(tc.nonce, tc.events)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(got, base) {
			t.Fatalf("%s does not change the binding", name)
		}
	}
	for name, tc := range map[string]struct {
		nonce  []byte
		events []string
	}{
		"short nonce":     {nonce[:16], []string{a}},
		"uppercase event": {nonce, []string{"sha256:" + strings.Repeat("A", 64)}},
		"tagged event":    {nonce, []string{"name@" + a}},
	} {
		if _, err := podcvm.SessionBinding(tc.nonce, tc.events); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
