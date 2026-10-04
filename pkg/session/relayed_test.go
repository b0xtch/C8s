package session_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// relay does what a host does that hands a guest's words on: it asks the
// guest, verifies nothing and returns what it was told, with the certificate
// the guest served it under.
func relay(t *testing.T, s *served, method, path string, body []byte, out any) []byte {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // a host that relays verifies nothing
		DisableKeepAlives: true,
	}}
	req, err := http.NewRequestWithContext(within(t), method, "https://"+s.addr+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s: HTTP %d, %v: %s", method, path, resp.StatusCode, err, data)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
	return resp.TLS.PeerCertificates[0].Raw
}

// relayedState is what a host relays of a guest before any bind.
func relayedState(t *testing.T, s *served) *session.Relayed {
	t.Helper()
	var state session.StateResponse
	leaf := relay(t, s, http.MethodGet, session.PathState, nil, &state)
	return &session.Relayed{
		Certificate: leaf, Phase: state.Phase, Launch: state.Launch, Signature: state.Signature,
		Events: state.Events, Bind: state.Bind, BindSignature: state.BindSignature,
	}
}

// relayedBind hands the guest its bind as a host does and returns what the
// host relays: the guest's receipt, and the evidence the guest took over the
// bind's nonce, from the answer or from the guest's state once it is there.
func relayedBind(t *testing.T, s *served, bind *session.SignedBind) *session.Relayed {
	t.Helper()
	body, err := json.Marshal(session.BindRequest{Bind: bind.Raw, Signature: bind.Signature})
	if err != nil {
		t.Fatal(err)
	}
	var answer session.BindResponse
	leaf := relay(t, s, http.MethodPost, session.PathBind, body, &answer)
	if answer.Receipt == nil {
		t.Fatal("the guest answered its bind with no receipt")
	}
	att := answer.Attestation
	for deadline := time.Now().Add(5 * time.Second); att == nil; time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the guest never served the evidence over its bind's nonce")
		}
		var state session.StateResponse
		leaf = relay(t, s, http.MethodGet, session.PathState, nil, &state)
		att = state.Attestation
	}
	evidence, err := json.Marshal(att.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	return &session.Relayed{
		Certificate: leaf, Phase: att.Phase, Launch: att.Launch, Signature: att.Signature,
		Events: att.Events, Bind: att.Bind, BindSignature: att.BindSignature, Evidence: evidence, Receipt: answer.Receipt,
	}
}

func bindFor(t *testing.T, s *served, ready *session.ReadyTD) *session.SignedBind {
	t.Helper()
	bind, err := session.NewBind(session.BindOptions{
		Authority: s.authority, InstanceKey: ready.InstanceKey, Tenant: "acme", Session: "sbx-1", NotAfter: time.Now().Add(time.Minute),
		Policy: session.BindPolicy{Access: session.Access{Exec: []string{s.accessPub}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return bind
}

// A binder that never talks to the guest verifies it from what its host
// relays: before the bind, that it is the pinned image under the pinned
// launch key and nobody's yet; after it, that it took exactly this bind.
func TestRelayedEvidenceIsJudgedLikeTheGuestsOwn(t *testing.T) {
	s := serveReady(t, sessiontest.NewTD())
	engine := sessiontest.Engine{}
	ready, err := session.VerifyReady(within(t), s.policy, engine, relayedState(t, s), time.Now())
	if err != nil {
		t.Fatalf("VerifyReady: %v", err)
	}
	bind := bindFor(t, s, ready)
	answer := relayedBind(t, s, bind)
	bound := (&session.Binding{LaunchKey: s.bundle.LaunchKey, Launch: ready.Launch, Bind: bind}).Policy(s.policy.Image)
	receipt, err := session.VerifyBoundReceipt(bound, ready, bind, answer)
	if err != nil {
		t.Fatalf("VerifyBoundReceipt: %v", err)
	}
	att, err := session.VerifyBound(within(t), bound, engine, ready.InstanceKey, bind, answer)
	if err != nil {
		t.Fatalf("VerifyBound: %v", err)
	}
	if att.Tenant != "acme" || att.Session != "sbx-1" || att.Phase != session.PhaseRunning || len(att.Events) != 2 {
		t.Fatalf("the attestation: %+v", att)
	}
	if err := receipt.Confirmed(att); err != nil {
		t.Fatalf("the quote does not confirm the receipt: %v", err)
	}
	// The verdict on it is one the owner's next process takes: a client
	// under the same policy asks the guest for no quote.
	leaf, err := x509.ParseCertificate(answer.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := session.VerdictOn(bound, engine, att, leaf, time.Now())
	if err != nil || verdict == nil {
		t.Fatalf("VerdictOn: %v, %v", verdict, err)
	}
	counting := &judging{}
	client, err := session.NewClient("https://"+s.addr, bound, counting, s.signer, session.Kept(verdict))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Exec(within(t), session.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("a command under the kept verdict: %v", err)
	}
	if n := counting.calls.Load(); n != 0 {
		t.Fatalf("the client judged evidence %d times under a verdict that stands", n)
	}

	// The guest is bound now, and what its host relays says so.
	if _, err := session.VerifyReady(within(t), s.policy, engine, relayedState(t, s), time.Now()); !isVerdict(err) {
		t.Fatalf("a bound guest passed as ready: %v", err)
	}
}

func TestRelayedEvidenceIsRefused(t *testing.T) {
	engine := sessiontest.Engine{}
	s := serveReady(t, sessiontest.NewTD())
	other := serveReady(t, sessiontest.NewTD())
	state := relayedState(t, s)
	for name, tc := range map[string]struct {
		policy func(p *session.Policy)
		relay  func(r *session.Relayed)
	}{
		"a guest of another image":          {policy: func(p *session.Policy) { p.Image = other.policy.Image }},
		"a guest under another launch key":  {policy: func(p *session.Policy) { p.LaunchKey = other.bundle.LaunchKey }},
		"another guest's certificate":       {relay: func(r *session.Relayed) { r.Certificate = relayedState(t, other).Certificate }},
		"a certificate that does not parse": {relay: func(r *session.Relayed) { r.Certificate = r.Certificate[:len(r.Certificate)/2] }},
		"another pool's document":           {relay: func(r *session.Relayed) { r.Launch, r.Signature = other.bundle.Launch, other.bundle.Signature }},
		"an event the guest did not have":   {relay: func(r *session.Relayed) { r.Events = append(r.Events, r.Events[0]) }},
		"no event":                          {relay: func(r *session.Relayed) { r.Events = nil }},
		"a phase past ready":                {relay: func(r *session.Relayed) { r.Phase = session.PhaseRunning }},
	} {
		policy, relayed := s.policy, *state
		relayed.Events = append([]string(nil), state.Events...)
		if tc.policy != nil {
			tc.policy(&policy)
		}
		if tc.relay != nil {
			tc.relay(&relayed)
		}
		if _, err := session.VerifyReady(within(t), policy, engine, &relayed, time.Now()); !isVerdict(err) {
			t.Errorf("%s passed as a ready guest of the pool: %v", name, err)
		}
	}

	ready, err := session.VerifyReady(within(t), s.policy, engine, state, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bind := bindFor(t, s, ready)
	answer := relayedBind(t, s, bind)
	bound := (&session.Binding{LaunchKey: s.bundle.LaunchKey, Launch: ready.Launch, Bind: bind}).Policy(s.policy.Image)
	// A second guest of the pool, bound by the same authority.
	otherReady, err := session.VerifyReady(within(t), other.policy, engine, relayedState(t, other), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]func(r *session.Relayed){
		"no evidence":                          func(r *session.Relayed) { r.Evidence = nil },
		"evidence that does not parse":         func(r *session.Relayed) { r.Evidence = []byte("{") },
		"the state alone, which has no quote":  func(r *session.Relayed) { *r = *relayedState(t, s) },
		"events the quote does not cover":      func(r *session.Relayed) { r.Events = r.Events[:1] },
		"a phase the guest did not report":     func(r *session.Relayed) { r.Phase = session.PhaseBound },
		"another bind in the bind's place":     func(r *session.Relayed) { r.Bind = bindFor(t, s, ready).Raw },
		"another launch document in its place": func(r *session.Relayed) { r.Launch, r.Signature = other.bundle.Launch, other.bundle.Signature },
	} {
		relayed := *answer
		relayed.Events = append([]string(nil), answer.Events...)
		tc(&relayed)
		if _, err := session.VerifyBound(within(t), bound, engine, ready.InstanceKey, bind, &relayed); !isVerdict(err) {
			t.Errorf("%s passed as the guest's answer to the bind: %v", name, err)
		}
	}
	// The answer is fresh for this bind's nonce and bound to this guest's
	// key, and for no other.
	if _, err := session.VerifyBound(within(t), bound, engine, otherReady.InstanceKey, bind, answer); !isVerdict(err) {
		t.Errorf("the answer passed for another guest's key: %v", err)
	}
	stale := bindFor(t, s, ready)
	stalePolicy := (&session.Binding{LaunchKey: s.bundle.LaunchKey, Launch: ready.Launch, Bind: stale}).Policy(s.policy.Image)
	if _, err := session.VerifyBound(within(t), stalePolicy, engine, ready.InstanceKey, stale, answer); !isVerdict(err) {
		t.Errorf("the answer to one bind passed for another: %v", err)
	}
	if _, err := session.VerifyBound(within(t), bound, engine, ready.InstanceKey, stale, answer); err == nil || isVerdict(err) {
		t.Errorf("a policy that pins another bind than the one sent: %v", err)
	}
	var refused *session.VerificationError
	if _, err := session.VerifyBound(within(t), bound, engine, ready.InstanceKey, bind, answer); errors.As(err, &refused) {
		t.Fatalf("the guest's own answer was refused: %v", err)
	}
}
