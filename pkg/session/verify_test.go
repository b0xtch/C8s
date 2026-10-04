package session_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// Each case is one way a host could hand a verifier evidence that is not the
// pinned guest, launched for this key, bound by this bind, running this
// sandbox, fresh, and bound to this key. Every one must be refused, and for
// the reason named.
func TestVerifyAttestationRejects(t *testing.T) {
	type world struct {
		*fixture
		g     *guest
		nonce []byte
		key   *ecdsa.PublicKey
		resp  *session.AttestResponse
	}
	build := func(t *testing.T) *world {
		f := newFixture(t, nil)
		g := f.boot(t, f.bind, session.PhaseRunning)
		nonce := freshNonce(t)
		return &world{fixture: f, g: g, nonce: nonce, key: &f.instance.PublicKey, resp: g.attest(t, nonce)}
	}
	// sameKey signs another document with the pool's own launch key: the case
	// where the host swaps in a document the platform really did sign.
	sameKey := func(t *testing.T, w *world) *session.Bundle {
		_, other := newBundle(t, w.td, func(o *session.BundleOptions) {
			o.KeyPath, o.Pool = filepath.Join(w.dir, session.BundleKeyFile), "another-pool"
		})
		if !bytes.Equal(other.LaunchKey, w.bundle.LaunchKey) {
			t.Fatal("fixture: second bundle is not signed by the same launch key")
		}
		return other
	}
	// twin is another TD of the same image, seeded and extended as told.
	twin := func(t *testing.T, w *world, launchKey []byte, events []string) *sessiontest.TD {
		td := sessiontest.NewTD()
		td.MRTD, td.RTMR[1], td.RTMR[2] = w.td.MRTD, w.td.RTMR[1], w.td.RTMR[2]
		td.SeedLaunchKey(launchKey)
		for _, event := range events {
			digest := runtimemeasure.Event(event)
			if err := td.Extend(digest[:]); err != nil {
				t.Fatal(err)
			}
		}
		return td
	}

	for name, tc := range map[string]struct {
		break_ func(t *testing.T, w *world)
		want   string
	}{
		"stale evidence replayed for a new nonce": {func(t *testing.T, w *world) {
			w.nonce = freshNonce(t)
		}, "REPORTDATA"},
		"evidence presented under another key": {func(t *testing.T, w *world) {
			w.key = &newKey(t).PublicKey
		}, "instance key"},
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
		"a TD its host may migrate": {func(t *testing.T, w *world) {
			w.td.Attributes |= 1 << 29
			w.resp = w.g.attest(t, w.nonce)
		}, "migrate"},
		"a TD its host may profile": {func(t *testing.T, w *world) {
			w.td.Attributes |= 1 << 5
			w.resp = w.g.attest(t, w.nonce)
		}, "profile"},
		"extra event extended after the sandbox": {func(t *testing.T, w *world) {
			extra := runtimemeasure.Event("sha256:" + strings.Repeat("9", 64))
			if err := w.td.Extend(extra[:]); err != nil {
				t.Fatal(err)
			}
			w.resp = w.g.attest(t, w.nonce)
		}, "RTMR[3]"},
		"guest launched for another key": {func(t *testing.T, w *world) {
			// The host boots the pinned image with its own launch key, then
			// replays the pool's signed document and the owner's bind.
			w.g.td = twin(t, w, []byte(keyPEM(t, newKey(t))), w.g.events)
			w.resp = w.g.attest(t, w.nonce)
		}, "RTMR[3]"},
		"document replaced under the original signature": {func(t *testing.T, w *world) {
			w.resp.Launch = sameKey(t, w).Launch
		}, "signature"},
		"another pool's document, validly signed by the same key": {func(t *testing.T, w *world) {
			other := sameKey(t, w)
			w.resp.Launch, w.resp.Signature = other.Launch, other.Signature
		}, "policy pins"},
		"a same-key document that the guest never measured": {func(t *testing.T, w *world) {
			// Only the measurement can tell the two documents apart.
			other := sameKey(t, w)
			w.resp.Launch, w.resp.Signature = other.Launch, other.Signature
			w.policy.Launch = nil
		}, "events"},
		"an unmeasured same-key document with events rewritten to match": {func(t *testing.T, w *world) {
			other := sameKey(t, w)
			w.resp.Launch, w.resp.Signature = other.Launch, other.Signature
			events, err := session.ExpectedEvents(other.Launch, w.bind, session.PhaseRunning)
			if err != nil {
				t.Fatal(err)
			}
			w.resp.Events = events
			w.policy.Launch = nil
		}, "REPORTDATA"},
		"sandbox event claimed but not measured": {func(t *testing.T, w *world) {
			w.g.td = twin(t, w, w.bundle.LaunchKey, w.g.events[:2])
			w.resp = w.g.attest(t, w.nonce)
		}, "RTMR[3]"},
		"bind event claimed but not measured": {func(t *testing.T, w *world) {
			w.g.td = twin(t, w, w.bundle.LaunchKey, w.g.events[:1])
			w.resp = w.g.attest(t, w.nonce)
		}, "RTMR[3]"},
		"events reordered": {func(t *testing.T, w *world) {
			w.resp.Events[0], w.resp.Events[1] = w.resp.Events[1], w.resp.Events[0]
		}, "events"},
		"a guest whose sandbox does not run yet": {func(t *testing.T, w *world) {
			w.resp.Phase = session.PhaseBound
		}, "phase"},
		"unknown phase": {func(t *testing.T, w *world) {
			w.resp.Phase = "paused"
		}, "phase"},
		"evidence truncated": {func(t *testing.T, w *world) {
			w.resp.Evidence.Evidence = w.resp.Evidence.Evidence[:len(w.resp.Evidence.Evidence)/2]
		}, "signature"},
		"platform relabelled": {func(t *testing.T, w *world) {
			w.resp.Evidence.Platform = "snp"
		}, "platform"},
		"policy pins another image": {func(t *testing.T, w *world) {
			pinned := policyFor(t, sessiontest.NewTD(), w.bundle)
			w.policy.Image = pinned.Image
		}, "image measurement"},
		"policy pins another launch key": {func(t *testing.T, w *world) {
			w.policy.LaunchKey = []byte(keyPEM(t, newKey(t)))
		}, "signature"},
	} {
		t.Run(name, func(t *testing.T) {
			w := build(t)
			if _, err := session.VerifyAttestation(context.Background(), w.policy, sessiontest.Engine{}, w.key, w.nonce, w.resp); err != nil {
				t.Fatalf("control must pass before the break: %v", err)
			}
			tc.break_(t, w)
			assertRefused(t, w.policy, w.key, w.nonce, w.resp, tc.want)
		})
	}
}

func TestEvidenceBindingCommitsToEveryInput(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, session.NonceSize)
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	base, err := session.EvidenceBinding(nonce, []string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{8}, session.NonceSize)
	for name, tc := range map[string]struct {
		nonce  []byte
		events []string
	}{
		"nonce":         {other, []string{a, b}},
		"event order":   {nonce, []string{b, a}},
		"event dropped": {nonce, []string{a}},
		"event added":   {nonce, []string{a, b, a}},
	} {
		got, err := session.EvidenceBinding(tc.nonce, tc.events)
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
		if _, err := session.EvidenceBinding(tc.nonce, tc.events); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
