package session_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	agratls "github.com/confidential-dot-ai/attestation-go/ratls"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sessionagent"
	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// oneTimePair is a pair of one-time keys and the signing key's private half.
type oneTimePair struct {
	keys    *session.OneTimeKeys
	signing ed25519.PrivateKey
}

func newOneTimePair(t *testing.T) *oneTimePair {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &oneTimePair{keys: &session.OneTimeKeys{Signing: public, KEM: kem.PublicKey().Bytes()}, signing: private}
}

func (p *oneTimePair) sign(message []byte) ([]byte, error) {
	return ed25519.Sign(p.signing, message), nil
}

// keyHolder is a guest as whoever holds its keys can make it speak: its
// hardware, which quotes whatever report data code in the guest asks for
// over the registers as they stand, and its instance key, which signs any
// certificate. It is what a session has that broke out of its sandbox, and
// it has no agent.
type keyHolder struct {
	td     *sessiontest.TD
	key    *ecdsa.PrivateKey
	bundle *session.Bundle
	policy session.Policy
}

// newKeyHolder is a guest that has measured its launch document and nothing
// else.
func newKeyHolder(t *testing.T) *keyHolder {
	t.Helper()
	td := sessiontest.NewTD()
	_, bundle := newBundle(t, td, nil)
	td.SeedLaunchKey(bundle.LaunchKey)
	h := &keyHolder{td: td, key: newKey(t), bundle: bundle}
	h.extend(t, session.DocumentDigest(bundle.Launch))
	h.policy = policyFor(t, td, bundle)
	h.policy.Launch, h.policy.AllowReady = nil, true
	return h
}

// sibling is another guest of the same pool: the same image under the same
// launch document, with a key and registers of its own, and nobody's.
func (h *keyHolder) sibling(t *testing.T) *keyHolder {
	t.Helper()
	td := sessiontest.NewTD()
	td.MRTD, td.RTMR[0], td.RTMR[1], td.RTMR[2] = h.td.MRTD, h.td.RTMR[0], h.td.RTMR[1], h.td.RTMR[2]
	td.SeedLaunchKey(h.bundle.LaunchKey)
	s := &keyHolder{td: td, key: newKey(t), bundle: h.bundle, policy: h.policy}
	s.extend(t, session.DocumentDigest(h.bundle.Launch))
	return s
}

func (h *keyHolder) extend(t *testing.T, digest string) {
	t.Helper()
	event := runtimemeasure.Event(digest)
	if err := h.td.Extend(event[:]); err != nil {
		t.Fatal(err)
	}
}

// certificate is one the instance key signs: it carries carried, and its
// quote is taken now, over report data that binds quoted.
func (h *keyHolder) certificate(t *testing.T, carried, quoted *session.OneTimeKeys, ttl time.Duration) []byte {
	t.Helper()
	rd, err := session.CertificateReportData(&h.key.PublicKey, quoted)
	if err != nil {
		t.Fatal(err)
	}
	att, err := agratls.NewAttestation(h.td.Evidence(rd))
	if err != nil {
		t.Fatal(err)
	}
	opts := &ratls.CertOptions{TTL: ttl}
	if carried != nil {
		ext, err := carried.Extension()
		if err != nil {
			t.Fatal(err)
		}
		opts.Extensions = []pkix.Extension{ext}
	}
	der, err := ratls.CreateAttestedCert(h.key, att, opts)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// ready is what a host relays of the guest as it was when it was nobody's,
// under certificate.
func (h *keyHolder) ready(certificate []byte) *session.Relayed {
	return &session.Relayed{
		Certificate: certificate, Phase: session.PhaseReady, Launch: h.bundle.Launch, Signature: h.bundle.Signature,
		Events: []string{session.DocumentDigest(h.bundle.Launch)},
	}
}

// A guest's one-time keys are the ones the quote in its certificate binds. A
// session that broke out of its sandbox holds the guest's instance key, so
// it can sign any certificate, and its host still has the quote the guest
// took when it was nobody's. Neither gives another binder keys the session
// holds: the old quote binds the keys the guest erased, and every quote the
// hardware gives now shows the bind.
func TestOneTimeKeysAreTakenFromTheQuoteAlone(t *testing.T) {
	h := newKeyHolder(t)
	engine := sessiontest.Engine{}
	guests, sessions := newOneTimePair(t), newOneTimePair(t)

	// The guest as it was: its certificate carries its keys, and its quote
	// binds them.
	genuine := h.certificate(t, guests.keys, guests.keys, 0)
	ready, err := session.VerifyReady(within(t), h.policy, engine, h.ready(genuine), time.Now())
	if err != nil {
		t.Fatalf("the guest's own certificate: %v", err)
	}
	if ready.OneTime == nil || !bytes.Equal(ready.OneTime.Signing, guests.keys.Signing) || !bytes.Equal(ready.OneTime.KEM, guests.keys.KEM) {
		t.Fatalf("the keys taken from the guest's evidence are not the guest's: %+v", ready.OneTime)
	}

	// Before any bind, the keys carried and the keys quoted must be the same,
	// each of the two.
	otherKEM := &session.OneTimeKeys{Signing: guests.keys.Signing, KEM: sessions.keys.KEM}
	otherSigning := &session.OneTimeKeys{Signing: sessions.keys.Signing, KEM: guests.keys.KEM}
	for name, certificate := range map[string][]byte{
		"a certificate that carries other keys than its quote binds": h.certificate(t, sessions.keys, guests.keys, 0),
		"a certificate that carries another KEM key than its quote":  h.certificate(t, otherKEM, guests.keys, 0),
		"a certificate that carries another signing key than quoted": h.certificate(t, otherSigning, guests.keys, 0),
		"a certificate that carries keys its quote does not bind":    h.certificate(t, sessions.keys, nil, 0),
		"a certificate that drops the keys its quote binds":          h.certificate(t, nil, guests.keys, 0),
	} {
		if got, err := session.VerifyReady(within(t), h.policy, engine, h.ready(certificate), time.Now()); !isVerdict(err) {
			t.Errorf("%s passed as a ready guest's, with keys %+v: %v", name, got, err)
		}
	}
	// A guest that makes no such keys is no guest a bind is signed for.
	if got, err := session.VerifyReady(within(t), h.policy, engine, h.ready(h.certificate(t, nil, nil, 0)), time.Now()); !isVerdict(err) {
		t.Errorf("a guest whose evidence binds no one-time keys passed as ready: %+v, %v", got, err)
	}

	// The guest takes its bind. From here on the hardware's word shows it.
	bind, err := session.NewBind(session.BindOptions{
		Authority: newKey(t), InstanceKey: &h.key.PublicKey, Tenant: "acme", Session: "sbx-1", NotAfter: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.extend(t, session.DocumentDigest(bind.Raw))
	// The session's own keys, under a quote the hardware gives it now: the
	// register is no longer a ready guest's.
	if got, err := session.VerifyReady(within(t), h.policy, engine, h.ready(h.certificate(t, sessions.keys, sessions.keys, 0)), time.Now()); !isVerdict(err) {
		t.Errorf("a quote taken after the bind passed as a ready guest's, with keys %+v: %v", got, err)
	}
	// The quote from before still verifies, and still binds the guest's keys
	// and no others.
	replayed, err := session.VerifyReady(within(t), h.policy, engine, h.ready(genuine), time.Now())
	if err != nil || !bytes.Equal(replayed.OneTime.Signing, guests.keys.Signing) {
		t.Fatalf("the replayed evidence: %+v, %v", replayed, err)
	}

	// So a receipt the session signs for another binder's bind, with its own
	// one-time key or with the guest's instance key, is not the guest's.
	other, err := session.NewBind(session.BindOptions{
		Authority: newKey(t), InstanceKey: &h.key.PublicKey, Tenant: "other", Session: "sbx-2", NotAfter: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := session.ExpectedEvents(nil, other, session.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	bound := (&session.Binding{LaunchKey: h.bundle.LaunchKey, Launch: h.bundle.Launch, Bind: other}).Policy(h.policy.Image)
	forged, err := session.NewBindReceipt(sessions.sign, other, events[1:], session.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := session.VerifyBoundReceipt(bound, replayed, other, &session.Relayed{Receipt: forged}); !isVerdict(err) {
		t.Errorf("a receipt signed with a key the session made passed as the guest's: %+v, %v", got, err)
	}
	// The guest's own, had it taken that bind, does pass.
	own, err := session.NewBindReceipt(guests.sign, other, events[1:], session.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.VerifyBoundReceipt(bound, replayed, other, &session.Relayed{Receipt: own}); err != nil {
		t.Fatalf("the guest's own receipt: %v", err)
	}
}

// A kept receipt is checked for as long as the session lives, against the
// certificate the guest issued before its bind: of the same guest, still
// nobody's then, with the receipt's key bound in its quote. The certificate's
// own dates do not end that.
func TestKeptReceiptIsHeldToTheCertificateFromBeforeTheBind(t *testing.T) {
	h := newKeyHolder(t)
	engine := sessiontest.Engine{}
	guests, sessions := newOneTimePair(t), newOneTimePair(t)
	// A certificate that has run out by the time anybody reads it.
	before := h.certificate(t, guests.keys, guests.keys, time.Nanosecond)
	// Another guest of the pool, nobody's, whose evidence binds the keys a
	// session of this guest made.
	sibling := h.sibling(t)

	bind, err := session.NewBind(session.BindOptions{
		Authority: newKey(t), InstanceKey: &h.key.PublicKey, Tenant: "acme", Session: "sbx-1", NotAfter: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.extend(t, session.DocumentDigest(bind.Raw))
	events, err := session.ExpectedEvents(h.bundle.Launch, bind, session.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := session.NewBindReceipt(guests.sign, bind, events[1:], session.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&h.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// What a verifier has of the bound guest once it has attested it.
	att := &session.Attestation{
		Document: h.bundle.Document, Launch: h.bundle.Launch, Bind: bind, Events: events, Phase: session.PhaseRunning, InstanceKey: der,
	}
	policy := (&session.Binding{LaunchKey: h.bundle.LaunchKey, Launch: h.bundle.Launch, Bind: bind}).Policy(h.policy.Image)

	time.Sleep(2 * time.Millisecond)
	if leaf, err := x509.ParseCertificate(before); err != nil || time.Now().Before(leaf.NotAfter) {
		t.Fatalf("the certificate from before the bind has not run out: %v", err)
	}
	got, err := session.ConfirmReceipt(within(t), policy, engine, receipt, att, before)
	if err != nil {
		t.Fatalf("the guest's receipt, held to its certificate from before the bind: %v", err)
	}
	if got.Bind != session.DocumentDigest(bind.Raw) {
		t.Fatalf("the receipt is for %s", got.Bind)
	}

	forged, err := session.NewBindReceipt(sessions.sign, bind, events[1:], session.PhaseRunning)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		certificate []byte
		receipt     *session.SignedReceipt
	}{
		"no certificate from before the bind":         {nil, receipt},
		"bytes that are no certificate":               {[]byte("a certificate"), receipt},
		"another guest's certificate":                 {sibling.certificate(t, sessions.keys, sessions.keys, 0), forged},
		"a certificate the guest issued after it":     {h.certificate(t, nil, nil, 0), receipt},
		"keys under a quote taken after the bind":     {h.certificate(t, sessions.keys, sessions.keys, 0), forged},
		"keys the certificate carries and no quote":   {h.certificate(t, sessions.keys, nil, 0), forged},
		"keys carried beside the quote of other keys": {h.certificate(t, sessions.keys, guests.keys, 0), forged},
		"a receipt signed with another key":           {before, forged},
	} {
		if got, err := session.ConfirmReceipt(within(t), policy, engine, tc.receipt, att, tc.certificate); !isVerdict(err) {
			t.Errorf("the receipt was held to %s: %+v, %v", name, got, err)
		}
	}
	// A verifier that pins another image finds no such guest.
	elsewhere := policy
	elsewhere.Image = policyFor(t, sessiontest.NewTD(), h.bundle).Image
	if got, err := session.ConfirmReceipt(within(t), elsewhere, engine, receipt, att, before); !isVerdict(err) {
		t.Errorf("the receipt was held under a policy for another image: %+v, %v", got, err)
	}
}

// The real guest, end to end: the certificate it serves before its bind
// carries its one-time keys; it signs its receipt under the first and keeps
// serving that certificate, at its handshakes and with its state. Its bind is
// no reason to issue another: the next one comes when that one's time is
// half up, and carries no one-time keys.
func TestGuestServesItsCertificateFromBeforeTheBind(t *testing.T) {
	// A certificate short enough for the test to see the next one.
	const lifetime = 4 * time.Second
	s := serveReady(t, sessiontest.NewTD(), func(cfg *sessionagent.Config) { cfg.CertTTL = lifetime })
	issued := time.Now()
	engine := sessiontest.Engine{}
	before := relayedState(t, s)
	ready, err := session.VerifyReady(within(t), s.policy, engine, before, time.Now())
	if err != nil {
		t.Fatalf("VerifyReady: %v", err)
	}
	if err := ready.OneTime.Validate(); err != nil {
		t.Fatalf("the ready guest's one-time keys: %v", err)
	}
	var unbound session.StateResponse
	relay(t, s, http.MethodGet, session.PathState, nil, &unbound)
	if len(unbound.ReadyCertificate) != 0 {
		t.Fatal("an unbound guest serves a certificate from before a bind it has not taken")
	}

	bind := bindFor(t, s, ready)
	answer := relayedBind(t, s, bind)
	bound := (&session.Binding{LaunchKey: s.bundle.LaunchKey, Launch: ready.Launch, Bind: bind}).Policy(s.policy.Image)
	if _, err := session.VerifyBoundReceipt(bound, ready, bind, answer); err != nil {
		t.Fatalf("the guest's receipt, held to the keys its ready evidence bound: %v", err)
	}
	// The receipt is no word of the instance key.
	signature, err := base64.StdEncoding.DecodeString(answer.Receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatalf("the receipt's signature is %d bytes: %v", len(signature), err)
	}

	var state session.StateResponse
	relay(t, s, http.MethodGet, session.PathState, nil, &state)
	if !bytes.Equal(state.ReadyCertificate, before.Certificate) {
		t.Fatal("the bound guest does not serve the certificate it had when its bind came")
	}
	att, err := session.VerifyBound(within(t), bound, engine, ready, bind, answer)
	if err != nil {
		t.Fatalf("VerifyBound: %v", err)
	}
	if _, err := session.ConfirmReceipt(within(t), bound, engine, answer.Receipt, att, state.ReadyCertificate); err != nil {
		t.Fatalf("the receipt, held to the certificate the guest serves from before its bind: %v", err)
	}

	// The bound guest serves the certificate from before its bind until
	// that one is due to be replaced. The one it issues then carries no
	// one-time keys, and is none a receipt is held to.
	var after []byte
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		after = relay(t, s, http.MethodGet, session.PathState, nil, new(session.StateResponse))
		if !bytes.Equal(after, before.Certificate) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the bound guest never issued a certificate of its own")
		}
	}
	if early := lifetime/2 - time.Since(issued); early > 0 {
		t.Fatalf("the bound guest issued a certificate %s before the one from before its bind was due to be replaced", early)
	}
	leaf, err := x509.ParseCertificate(after)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(session.OIDOneTimeKeys) {
			t.Fatal("a certificate issued after the bind carries one-time keys")
		}
	}
	if got, err := session.ConfirmReceipt(within(t), bound, engine, answer.Receipt, att, after); !isVerdict(err) {
		t.Errorf("the receipt was held to a certificate from after the bind: %+v, %v", got, err)
	}
	// A client that attests the guest holds its kept receipt the same way.
	client, err := session.NewClient("https://"+s.addr, bound, engine, s.signer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	fresh, err := client.Attest(within(t))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if _, err := client.ConfirmReceipt(within(t), answer.Receipt, fresh); err != nil {
		t.Fatalf("the client's check of the kept receipt: %v", err)
	}
}
