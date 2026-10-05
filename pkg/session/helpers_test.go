package session_test

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
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

const sandboxImage = "ghcr.io/acme/agent@sha256:1111111111111111111111111111111111111111111111111111111111111111"

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func keyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	pub, err := session.PublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pub)
}

// newBundle writes a pool's launch bundle for the image td runs.
func newBundle(t *testing.T, td *sessiontest.TD, mutate func(*session.BundleOptions)) (string, *session.Bundle) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bundle")
	opts := session.BundleOptions{
		Dir: dir, ManifestPath: td.WriteManifest(t), Pool: "agents", Class: "s-4x16",
		// A guest whose document lists no machine takes no bind.
		Machines: []string{machineOf(td)},
	}
	if mutate != nil {
		mutate(&opts)
	}
	if err := session.NewBundle(opts); err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	bundle, err := session.LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	return dir, bundle
}

// bindOptions is a bind an authority would write for the guest holding instance.
func bindOptions(t *testing.T, authority, instance *ecdsa.PrivateKey) session.BindOptions {
	t.Helper()
	access := keyPEM(t, newKey(t))
	return session.BindOptions{
		Authority: authority, InstanceKey: &instance.PublicKey,
		Tenant: "acme", Session: "sbx-1", NotAfter: time.Now().Add(time.Hour),
		Policy: session.BindPolicy{
			Sandbox:     &session.Sandbox{Image: sandboxImage, Process: session.ProcessImage},
			Access:      session.Access{Exec: []string{access}, Credentials: []string{access}},
			Credentials: []session.Credential{{Name: "test-token", MaxBytes: 128}},
		},
	}
}

// guest simulates what the measured agent does to the registers and what it
// answers to an attestation request, at one step of its life.
type guest struct {
	td     *sessiontest.TD
	bundle *session.Bundle
	key    *ecdsa.PrivateKey
	bind   *session.SignedBind
	events []string
	phase  session.Phase
}

// bootGuest boots a guest that holds key. bind, when given, is measured, and
// the sandbox after it unless phase is bound.
func bootGuest(t *testing.T, td *sessiontest.TD, bundle *session.Bundle, key *ecdsa.PrivateKey, bind *session.SignedBind, phase session.Phase) *guest {
	t.Helper()
	events, err := session.ExpectedEvents(bundle.Launch, bind, phase)
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
	return &guest{td: td, bundle: bundle, key: key, bind: bind, events: events, phase: phase}
}

func (g *guest) attest(t *testing.T, nonce []byte) *session.AttestResponse {
	t.Helper()
	rd, err := session.ReportData(&g.key.PublicKey, nonce, g.events)
	if err != nil {
		t.Fatal(err)
	}
	resp := &session.AttestResponse{
		Evidence:  g.td.Evidence(rd),
		Launch:    bytes.Clone(g.bundle.Launch),
		Signature: g.bundle.Signature,
		Events:    append([]string(nil), g.events...),
		Phase:     g.phase,
	}
	if g.bind != nil {
		resp.Bind, resp.BindSignature = bytes.Clone(g.bind.Raw), g.bind.Signature
	}
	return resp
}

// policyFor pins the image td runs and the pool's documents. A test adds
// whose guest it is to accept.
func policyFor(t *testing.T, td *sessiontest.TD, bundle *session.Bundle) session.Policy {
	t.Helper()
	identity, err := runtimemeasure.LoadImageManifest(td.WriteManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	return session.Policy{Image: identity, LaunchKey: bundle.LaunchKey, Launch: bundle.Launch}
}

func freshNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, session.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return nonce
}

func assertRefused(t *testing.T, policy session.Policy, key *ecdsa.PublicKey, nonce []byte, resp *session.AttestResponse, want string) {
	t.Helper()
	_, err := session.VerifyAttestation(context.Background(), policy, sessiontest.Engine{}, key, nonce, resp)
	if err == nil {
		t.Fatal("accepted")
	}
	var verdict *session.VerificationError
	if !errors.As(err, &verdict) {
		t.Fatalf("refusal is not a VerificationError: %v", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refused for the wrong reason: %v (want %q)", err, want)
	}
}

// fixture is a pool, one of its guests' keys, an owner's authority, the bind
// that authority signed for the guest, and the policy of whoever relies on
// the bound guest.
type fixture struct {
	td        *sessiontest.TD
	dir       string
	bundle    *session.Bundle
	authority *ecdsa.PrivateKey
	instance  *ecdsa.PrivateKey
	bind      *session.SignedBind
	policy    session.Policy
}

func newFixture(t *testing.T, mutate func(*session.BindOptions)) *fixture {
	t.Helper()
	f := &fixture{td: sessiontest.NewTD(), authority: newKey(t), instance: newKey(t)}
	f.dir, f.bundle = newBundle(t, f.td, nil)
	opts := bindOptions(t, f.authority, f.instance)
	if mutate != nil {
		mutate(&opts)
	}
	var err error
	if f.bind, err = session.NewBind(opts); err != nil {
		t.Fatal(err)
	}
	f.policy = policyFor(t, f.td, f.bundle)
	f.policy.Authority, f.policy.Bind = []byte(keyPEM(t, f.authority)), f.bind.Raw
	return f
}

// boot boots the fixture's guest: bound and running unless told otherwise.
func (f *fixture) boot(t *testing.T, bind *session.SignedBind, phase session.Phase) *guest {
	t.Helper()
	return bootGuest(t, f.td, f.bundle, f.instance, bind, phase)
}
