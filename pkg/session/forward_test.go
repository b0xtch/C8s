package session_test

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// Forward is an area of the policy of its own, with a key class of its own.
// Present, it opens ports, so a bind with no port, no sandbox to have ports
// or no key that could open them is refused, and so is a key with nothing to
// open.
func TestBindForwardArea(t *testing.T) {
	authority, instance := newKey(t), newKey(t)
	forwarder := keyPEM(t, newKey(t))
	open := func(o *session.BindOptions) {
		o.Policy.Forward = &session.Forward{Ports: []int{80, 9000}}
		o.Policy.Access.Forward = []string{forwarder}
	}
	opts := bindOptions(t, authority, instance)
	open(&opts)
	bind, err := session.NewBind(opts)
	if err != nil {
		t.Fatalf("a bind that opens two ports: %v", err)
	}
	if !bytes.Contains(bind.Raw, []byte(`"forward":{"ports":[80,9000]}`)) || !bytes.Contains(bind.Raw, []byte(`"forward":["-----BEGIN PUBLIC KEY-----`)) {
		t.Errorf("the policy does not carry forward as an area and a key class of its own: %s", bind.Raw)
	}
	parsed, err := session.ParseBind(bind.Raw)
	if err != nil || !parsed.Policy.Forward.Opens(80) || !parsed.Policy.Forward.Opens(9000) || parsed.Policy.Forward.Opens(81) {
		t.Fatalf("ParseBind: %+v, %v", parsed, err)
	}
	// A key that may only open streams still attests the guest first.
	if keys := parsed.Policy.Access; len(keys.ForwardKeys()) != 1 || len(keys.AttestKeys()) != 2 || len(keys.ExecKeys()) != 1 {
		t.Errorf("forward %d, attest %d, exec %d keys; want 1, 2, 1", len(keys.ForwardKeys()), len(keys.AttestKeys()), len(keys.ExecKeys()))
	}
	var none *session.Forward
	if none.Opens(80) {
		t.Error("a policy with no forward area opens a port")
	}

	many := make([]int, 17)
	for i := range many {
		many[i] = 9000 + i
	}
	for name, tc := range map[string]struct {
		mutate func(*session.BindOptions)
		want   string
	}{
		"no sandbox":            {func(o *session.BindOptions) { o.Policy.Sandbox = nil }, "policy.forward needs a sandbox image"},
		"no port":               {func(o *session.BindOptions) { o.Policy.Forward.Ports = []int{} }, "policy.forward.ports must list"},
		"no list":               {func(o *session.BindOptions) { o.Policy.Forward.Ports = nil }, "policy.forward.ports must list"},
		"too many ports":        {func(o *session.BindOptions) { o.Policy.Forward.Ports = many }, "policy.forward.ports must list"},
		"port 0":                {func(o *session.BindOptions) { o.Policy.Forward.Ports = []int{0, 80} }, "0 is not a TCP port"},
		"a port past the last":  {func(o *session.BindOptions) { o.Policy.Forward.Ports = []int{65536} }, "65536 is not a TCP port"},
		"a negative port":       {func(o *session.BindOptions) { o.Policy.Forward.Ports = []int{-80} }, "-80 is not a TCP port"},
		"ports out of order":    {func(o *session.BindOptions) { o.Policy.Forward.Ports = []int{9000, 80} }, "ascending order"},
		"a port listed twice":   {func(o *session.BindOptions) { o.Policy.Forward.Ports = []int{80, 80} }, "ascending order"},
		"the egress proxy":      {func(o *session.BindOptions) { o.Policy.Forward.Ports = []int{80, session.SandboxProxyPort} }, "egress proxy"},
		"no key to open them":   {func(o *session.BindOptions) { o.Policy.Access.Forward = nil }, "policy.access.forward names no key"},
		"a key with no port":    {func(o *session.BindOptions) { o.Policy.Forward = nil }, "policy.access.forward names keys"},
		"a key listed twice":    {func(o *session.BindOptions) { o.Policy.Access.Forward = []string{forwarder, forwarder} }, "policy.access.forward lists one key twice"},
		"something not a key":   {func(o *session.BindOptions) { o.Policy.Access.Forward = []string{"not a key"} }, "policy.access.forward"},
		"exec keys do not open": {func(o *session.BindOptions) { o.Policy.Access.Forward, o.Policy.Access.Exec = nil, []string{forwarder} }, "policy.access.forward names no key"},
	} {
		opts := bindOptions(t, authority, instance)
		open(&opts)
		tc.mutate(&opts)
		if _, err := session.NewBind(opts); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want a refusal saying %q", name, err, tc.want)
		}
	}

	// The guest reads the same rules: a bind edited after it was rendered is
	// refused by the parser, whoever signed it.
	for name, edit := range map[string][2]string{
		"ports under the sandbox": {`"image":`, `"ports":[80],"image":`},
		"an address":              {`"ports":[80,9000]`, `"ports":["127.0.0.1:80"]`},
		"a port as text":          {`"ports":[80,9000]`, `"ports":["80"]`},
		"a port with a fraction":  {`"ports":[80,9000]`, `"ports":[80.5]`},
		"a field of its own":      {`"forward":{"ports":[80,9000]}`, `"forward":{"address":"0.0.0.0","ports":[80,9000]}`},
	} {
		if !bytes.Contains(bind.Raw, []byte(edit[0])) {
			t.Fatalf("%s: fixture has no %s in %s", name, edit[0], bind.Raw)
		}
		if _, err := session.ParseBind(bytes.Replace(bind.Raw, []byte(edit[0]), []byte(edit[1]), 1)); err == nil {
			t.Errorf("a bind with %s parsed", name)
		}
	}
}

// A verifier reads what a guest opens, and to whom, from the bind the
// evidence binds.
func TestAttestationShowsWhatIsForwarded(t *testing.T) {
	forwarder := newKey(t)
	f := newFixture(t, func(o *session.BindOptions) {
		o.Policy.Forward = &session.Forward{Ports: []int{80}}
		o.Policy.Access.Forward = []string{keyPEM(t, forwarder)}
	})
	g := f.boot(t, f.bind, session.PhaseRunning)
	nonce := freshNonce(t)
	att, err := session.VerifyAttestation(context.Background(), f.policy, sessiontest.Engine{}, &f.instance.PublicKey, nonce, g.attest(t, nonce))
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
	want, err := session.InstanceKeyDigest(&forwarder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if area, keys := att.Forward(); !area.Opens(80) || !slices.Equal(keys, []string{want}) {
		t.Errorf("the attestation shows forward %+v to %v, want port 80 to %s", area, keys, want)
	}

	closed := newFixture(t, nil)
	g = closed.boot(t, closed.bind, session.PhaseRunning)
	att, err = session.VerifyAttestation(context.Background(), closed.policy, sessiontest.Engine{}, &closed.instance.PublicKey, nonce, g.attest(t, nonce))
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
	if area, keys := att.Forward(); area != nil || keys != nil {
		t.Errorf("a bind with no forward area shows %+v to %v", area, keys)
	}
}
