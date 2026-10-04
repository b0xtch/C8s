package session_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

func TestBindRoundTrip(t *testing.T) {
	authority, instance := newKey(t), newKey(t)
	bind, err := session.NewBind(bindOptions(t, authority, instance))
	if err != nil {
		t.Fatal(err)
	}
	got, err := session.VerifyBind(bind.Raw, bind.Signature)
	if err != nil {
		t.Fatalf("VerifyBind: %v", err)
	}
	if got.Doc.Tenant != "acme" || got.Doc.Session != "sbx-1" || got.Doc.Policy.Sandbox.Image != sandboxImage ||
		len(got.Doc.Policy.Access.ExecKeys()) != 1 || got.Doc.Policy.Credentials[0].Limit() != 128 {
		t.Fatalf("unexpected bind: %+v", got.Doc)
	}
	if !got.SignedBy([]byte(keyPEM(t, authority))) || got.SignedBy([]byte(keyPEM(t, newKey(t)))) {
		t.Fatal("SignedBy does not tell the authority from another key")
	}
	if err := got.Doc.Targets(&instance.PublicKey); err != nil {
		t.Fatalf("Targets: %v", err)
	}
	if err := got.Doc.Targets(&newKey(t).PublicKey); err == nil {
		t.Fatal("a bind for one instance key was accepted for another")
	}
	if got.Doc.Purpose != session.PurposeStart || len(got.Doc.EvidenceNonce()) != session.NonceSize {
		t.Fatalf("a new bind has purpose %q and a nonce of %d bytes", got.Doc.Purpose, len(got.Doc.EvidenceNonce()))
	}
	// Rendering is deterministic: the same document is the same bytes.
	again, err := got.Doc.Canonical()
	if err != nil || !bytes.Equal(again, bind.Raw) {
		t.Fatalf("canonical form is not stable: %v", err)
	}
}

func TestVerifyBindRefuses(t *testing.T) {
	authority, instance := newKey(t), newKey(t)
	bind, err := session.NewBind(bindOptions(t, authority, instance))
	if err != nil {
		t.Fatal(err)
	}
	other, err := operatorauth.SignDetached(newKey(t), bind.Raw)
	if err != nil {
		t.Fatal(err)
	}
	flipped := bytes.Replace(bind.Raw, []byte(`"tenant":"acme"`), []byte(`"tenant":"evil"`), 1)
	for name, tc := range map[string]struct {
		raw       []byte
		signature string
		want      string
	}{
		"signed by another key":  {bind.Raw, other, "signature"},
		"changed after signing":  {flipped, bind.Signature, "signature"},
		"no signature":           {bind.Raw, "", "signature"},
		"an oversized signature": {bind.Raw, strings.Repeat("A", 8192), "too large"},
		"an empty bind":          {nil, bind.Signature, "1.."},
	} {
		if _, err := session.VerifyBind(tc.raw, tc.signature); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Every way two JSON parsers could read one document differently, and every
// field out of bounds, is refused before a signature is even looked at.
func TestParseBindRefuses(t *testing.T) {
	authority, instance := newKey(t), newKey(t)
	bind, err := session.NewBind(bindOptions(t, authority, instance))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.ParseBind(bind.Raw); err != nil {
		t.Fatalf("control: %v", err)
	}
	replace := func(old, new string) []byte {
		t.Helper()
		if !bytes.Contains(bind.Raw, []byte(old)) {
			t.Fatalf("fixture has no %q", old)
		}
		return bytes.Replace(bind.Raw, []byte(old), []byte(new), 1)
	}
	var tree map[string]any
	if err := json.Unmarshal(bind.Raw, &tree); err != nil {
		t.Fatal(err)
	}
	indented, _ := json.MarshalIndent(tree, "", " ")
	for name, tc := range map[string]struct {
		raw  []byte
		want string
	}{
		"whitespace":                             {indented, "canonical"},
		"a trailing newline":                     {append(bytes.Clone(bind.Raw), '\n'), "canonical"},
		"members out of order":                   {replace(`"schemaVersion":"c8s-bind/v1","session":"sbx-1"`, `"session":"sbx-1","schemaVersion":"c8s-bind/v1"`), "canonical"},
		"a duplicate member":                     {replace(`"tenant":"acme"`, `"tenant":"evil","tenant":"acme"`), "canonical"},
		"a member in another case":               {replace(`"tenant":"acme"`, `"Tenant":"acme"`), "canonical"},
		"an escape nobody needs":                 {replace(`"tenant":"acme"`, `"tenant":"\u0061cme"`), "canonical"},
		"an explicit null":                       {replace(`"command":["/bin/agent"]`, `"command":null`), "canonical"},
		"an empty optional member":               {replace(`"command":["/bin/agent"]`, `"command":[]`), "canonical"},
		"a subject, which nothing enforces yet":  {replace(`"session":"sbx-1"`, `"session":"sbx-1","subject":"user-42"`), "unknown field"},
		"a second value":                         {append(bytes.Clone(bind.Raw), []byte(`{}`)...), "exactly one"},
		"a member the agent does not enforce":    {replace(`"policy":{`, `"policy":{"persistence":"files",`), "unknown field"},
		"an egress rule with no port":            {replace(`"policy":{`, `"policy":{"egress":{"allow":["example.com"]},`), "policy.egress"},
		"egress under the sandbox":               {replace(`"image":`, `"egress":{"allow":["example.com:443"]},"image":`), "unknown field"},
		"an unknown top-level member":            {replace(`"tenant":"acme"`, `"tenant":"acme","tier":"gold"`), "unknown field"},
		"invalid UTF-8":                          {replace(`"tenant":"acme"`, "\"tenant\":\"ac\xffme\""), "UTF-8"},
		"another schema":                         {replace(`c8s-bind/v1`, `c8s-bind/v2`), "schemaVersion"},
		"a launch document's schema":             {replace(`c8s-bind/v1`, `c8s-session-launch/v1`), "schemaVersion"},
		"a launch id, which no bind names":       {replace(`"instanceKey":`, `"launch":"0123456789abcdef0123456789abcdef","instanceKey":`), "unknown field"},
		"a purpose this agent does not take":     {replace(`"purpose":"start"`, `"purpose":"restore"`), "purpose"},
		"a generation, which only a restore has": {replace(`"purpose":"start"`, `"generation":3,"purpose":"start"`), "unknown field"},
		"disks, which this agent does not open":  {replace(`"instanceKey":`, `"disks":{"in":"sha256:00"},"instanceKey":`), "unknown field"},
		"a short nonce":                          {replace(bind.Doc.Nonce, bind.Doc.Nonce[:62]), "nonce"},
		"a nonce in capitals":                    {replace(bind.Doc.Nonce, strings.ToUpper(bind.Doc.Nonce)), "nonce"},
		"an instance key that is not a digest":   {replace(`"instanceKey":"sha256:`, `"instanceKey":"sha512:`), "instanceKey"},
		"a tenant that is not a name":            {replace(`"tenant":"acme"`, `"tenant":"Acme Corp"`), "tenant"},
		"a session that is not a label":          {replace(`"session":"sbx-1"`, `"session":"sbx.1"`), "session"},
		"an image without a digest":              {replace(sandboxImage, "ghcr.io/acme/agent:latest"), "digest-pinned"},
		"a time with an offset":                  {replace(bind.Doc.NotAfter, strings.TrimSuffix(bind.Doc.NotAfter, "Z")+"+00:00"), "notAfter"},
		"a time with a fraction":                 {replace(bind.Doc.NotAfter, strings.TrimSuffix(bind.Doc.NotAfter, "Z")+".5Z"), "notAfter"},
		"a number as a string":                   {replace(`"maxBytes":128`, `"maxBytes":"128"`), "decode"},
		"a fractional number":                    {replace(`"maxBytes":128`, `"maxBytes":128.0`), "decode"},
	} {
		if _, err := session.ParseBind(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, tc.want)
		}
	}
}

func TestNewBindValidatesPolicy(t *testing.T) {
	authority, instance := newKey(t), newKey(t)
	for name, mutate := range map[string]func(*session.BindOptions){
		"credentials nobody may release": func(o *session.BindOptions) { o.Policy.Access.Credentials = nil },
		"a key listed twice": func(o *session.BindOptions) {
			o.Policy.Access.Exec = append(o.Policy.Access.Exec, o.Policy.Access.Exec[0])
		},
		"a credential named twice": func(o *session.BindOptions) {
			o.Policy.Credentials = append(o.Policy.Credentials, o.Policy.Credentials[0])
		},
		"no tenant":       func(o *session.BindOptions) { o.Tenant = "" },
		"no authority":    func(o *session.BindOptions) { o.Authority = nil },
		"no instance key": func(o *session.BindOptions) { o.InstanceKey = nil },
	} {
		opts := bindOptions(t, authority, instance)
		mutate(&opts)
		if _, err := session.NewBind(opts); err == nil {
			t.Errorf("%s was signed", name)
		}
	}
	// A bind may grant nothing at all: a sandbox that needs no driving.
	opts := bindOptions(t, authority, instance)
	opts.Policy.Access, opts.Policy.Credentials = session.Access{}, nil
	if _, err := session.NewBind(opts); err != nil {
		t.Errorf("a bind with no access: %v", err)
	}
	// Left to itself a bind is good for a minute and carries a nonce of its
	// own. Given a nonce it carries that one.
	opts = bindOptions(t, authority, instance)
	opts.NotAfter, opts.Nonce = time.Time{}, bytes.Repeat([]byte{7}, session.NonceSize)
	bind, err := session.NewBind(opts)
	if err != nil {
		t.Fatal(err)
	}
	if left := time.Until(bind.Doc.Expiry()); left <= 0 || left > session.DefaultBindTTL {
		t.Errorf("a bind with no time of its own expires in %s", left)
	}
	if bind.Doc.Nonce != hex.EncodeToString(opts.Nonce) {
		t.Errorf("the bind carries nonce %s", bind.Doc.Nonce)
	}
	opts.Nonce = opts.Nonce[:16]
	if _, err := session.NewBind(opts); err == nil {
		t.Error("a bind with a short nonce was signed")
	}
}

// What a bind decides is validated field by field, as the document that once
// carried it was.
func TestBindPolicyValidation(t *testing.T) {
	authority, instance := newKey(t), newKey(t)
	for name, mutate := range map[string]func(*session.BindPolicy){
		"credential over the cap":  func(p *session.BindPolicy) { p.Credentials[0].MaxBytes = session.MaxCredentialBytes + 1 },
		"negative credential size": func(p *session.BindPolicy) { p.Credentials[0].MaxBytes = -1 },
		"credential name":          func(p *session.BindPolicy) { p.Credentials[0].Name = "Test/Token" },
		"env name":                 func(p *session.BindPolicy) { p.Sandbox.Env = map[string]string{"A-B": "x"} },
		"relative working dir":     func(p *session.BindPolicy) { p.Sandbox.WorkingDir = "work" },
		"unclean working dir":      func(p *session.BindPolicy) { p.Sandbox.WorkingDir = "/a/../b" },
		"NUL in args":              func(p *session.BindPolicy) { p.Sandbox.Args = []string{"a\x00b"} },
		"empty command":            func(p *session.BindPolicy) { p.Sandbox.Command = []string{""} },
		"tag-pinned image":         func(p *session.BindPolicy) { p.Sandbox.Image = "ghcr.io/acme/agent:latest" },
		"bare digest image":        func(p *session.BindPolicy) { p.Sandbox.Image = "sha256:" + strings.Repeat("1", 64) },
	} {
		opts := bindOptions(t, authority, instance)
		mutate(&opts.Policy)
		if _, err := session.NewBind(opts); err == nil {
			t.Errorf("a bind with %s was signed", name)
		}
	}
	bind, err := session.NewBind(bindOptions(t, authority, instance))
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	if c, ok := bind.Doc.Policy.Credential("test-token"); !ok || c.Limit() != 128 {
		t.Fatalf("credential limit = %d, %v", c.Limit(), ok)
	}
	if c := (session.Credential{Name: "plain"}); c.Limit() != 64*1024 {
		t.Fatalf("default credential limit = %d", c.Limit())
	}
}

// Egress is an area of the policy of its own, beside the sandbox it holds to
// its list. Present, it is enforced, so a bind with nothing to enforce it on
// is refused.
func TestBindEgressPolicy(t *testing.T) {
	authority, instance := newKey(t), newKey(t)
	opts := bindOptions(t, authority, instance)
	opts.Policy.Egress = &session.Egress{Allow: []string{"api.example.com:443", "*.pkg.example.org:443", "10.1.2.3:8443"}}
	bind, err := session.NewBind(opts)
	if err != nil {
		t.Fatalf("a bind with an egress policy: %v", err)
	}
	if !bytes.Contains(bind.Raw, []byte(`"policy":{"access":`)) || !bytes.Contains(bind.Raw, []byte(`"egress":{"allow":["api.example.com:443","*.pkg.example.org:443","10.1.2.3:8443"]}`)) {
		t.Errorf("the policy does not carry egress as an area of its own: %s", bind.Raw)
	}
	parsed, err := session.ParseBind(bind.Raw)
	if err != nil || parsed.Policy.Egress == nil || len(parsed.Policy.Egress.Allow) != 3 {
		t.Fatalf("ParseBind: %+v, %v", parsed, err)
	}

	// An empty list is a policy: nothing is allowed. It survives the round trip.
	opts.Policy.Egress = &session.Egress{Allow: []string{}}
	if bind, err = session.NewBind(opts); err != nil || !bytes.Contains(bind.Raw, []byte(`"egress":{"allow":[]}`)) {
		t.Fatalf("a bind that allows no destination: %v, %s", err, bind.Raw)
	}

	for name, mutate := range map[string]func(*session.BindOptions){
		"egress with no sandbox": func(o *session.BindOptions) { o.Policy.Sandbox = nil },
		"egress with no list":    func(o *session.BindOptions) { o.Policy.Egress = &session.Egress{} },
		"a rule that is no host": func(o *session.BindOptions) { o.Policy.Egress.Allow = []string{"https://example.com"} },
		"a rule listed twice":    func(o *session.BindOptions) { o.Policy.Egress.Allow = []string{"a.example:443", "a.example:443"} },
	} {
		opts := bindOptions(t, authority, instance)
		opts.Policy.Egress = &session.Egress{Allow: []string{"api.example.com:443"}}
		mutate(&opts)
		if _, err := session.NewBind(opts); err == nil || !strings.Contains(err.Error(), "policy.egress") {
			t.Errorf("%s: %v, want a refusal naming policy.egress", name, err)
		}
	}
}

func TestVerifyAttestationAcceptsABoundGuest(t *testing.T) {
	f := newFixture(t, nil)
	g := f.boot(t, f.bind, session.PhaseRunning)
	nonce := freshNonce(t)
	att, err := session.VerifyAttestation(context.Background(), f.policy, sessiontest.Engine{}, &f.instance.PublicKey, nonce, g.attest(t, nonce))
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
	if len(att.Events) != 3 || att.Events[1] != session.DocumentDigest(f.bind.Raw) || att.Tenant != "acme" || att.Session != "sbx-1" || att.Bind == nil ||
		att.Document.Pool != "agents" || len(att.InstanceKey) == 0 {
		t.Fatalf("unexpected attestation: %+v", att)
	}
	if _, ok := att.Credential("test-token"); !ok {
		t.Fatal("the bind's credential is not found through the attestation")
	}

	// Pinned by tenant and session instead of the exact documents.
	loose := f.policy
	loose.Launch, loose.Bind, loose.Tenant, loose.Session = nil, nil, "acme", "sbx-1"
	if _, err := session.VerifyAttestation(context.Background(), loose, sessiontest.Engine{}, &f.instance.PublicKey, nonce, g.attest(t, nonce)); err != nil {
		t.Fatalf("tenant-pinned policy: %v", err)
	}
	loose.Tenant = "someone-else"
	assertRefused(t, loose, &f.instance.PublicKey, nonce, g.attest(t, nonce), "tenant")
	loose.Tenant, loose.Session = "acme", "sbx-2"
	assertRefused(t, loose, &f.instance.PublicKey, nonce, g.attest(t, nonce), "session")
}

// A bind that names no sandbox runs on two events.
func TestVerifyAttestationAcceptsABoundGuestWithNoSandbox(t *testing.T) {
	f := newFixture(t, func(o *session.BindOptions) { o.Policy.Sandbox = nil })
	g := f.boot(t, f.bind, session.PhaseRunning)
	nonce := freshNonce(t)
	att, err := session.VerifyAttestation(context.Background(), f.policy, sessiontest.Engine{}, &f.instance.PublicKey, nonce, g.attest(t, nonce))
	if err != nil || len(att.Events) != 2 || att.Phase != session.PhaseRunning {
		t.Fatalf("attestation %+v, %v", att, err)
	}
}

// Each case is a guest, or an answer, that must not pass for the owner's own
// bound guest.
func TestVerifyAttestationRefusesWrongBindings(t *testing.T) {
	type attempt struct {
		policy session.Policy
		key    *ecdsa.PublicKey
		resp   *session.AttestResponse
	}
	for name, tc := range map[string]struct {
		build func(t *testing.T, f *fixture, nonce []byte) attempt
		want  string
	}{
		"bound by another authority": {func(t *testing.T, f *fixture, nonce []byte) attempt {
			// What an operator does to pass off a guest it bound itself.
			theirs, err := session.NewBind(bindOptions(t, newKey(t), f.instance))
			if err != nil {
				t.Fatal(err)
			}
			policy := f.policy
			policy.Bind, policy.Tenant, policy.Session = nil, "acme", "sbx-1"
			return attempt{policy, &f.instance.PublicKey, f.boot(t, theirs, session.PhaseRunning).attest(t, nonce)}
		}, "another authority"},
		"another bind the same authority signed": {func(t *testing.T, f *fixture, nonce []byte) attempt {
			opts := bindOptions(t, f.authority, f.instance)
			opts.Session = "sbx-2"
			other, err := session.NewBind(opts)
			if err != nil {
				t.Fatal(err)
			}
			return attempt{f.policy, &f.instance.PublicKey, f.boot(t, other, session.PhaseRunning).attest(t, nonce)}
		}, "policy pins"},
		"a bind for another guest's instance key": {func(t *testing.T, f *fixture, nonce []byte) attempt {
			// A twin of the same pool, answering with the bind the authority
			// signed for the first guest.
			twin := newKey(t)
			g := bootGuest(t, f.td, f.bundle, twin, f.bind, session.PhaseRunning)
			return attempt{f.policy, &twin.PublicKey, g.attest(t, nonce)}
		}, "instance key"},
		"nobody bound it": {func(t *testing.T, f *fixture, nonce []byte) attempt {
			return attempt{f.policy, &f.instance.PublicKey, f.boot(t, nil, session.PhaseReady).attest(t, nonce)}
		}, "nobody has bound"},
		"the bind is left out of the answer": {func(t *testing.T, f *fixture, nonce []byte) attempt {
			resp := f.boot(t, f.bind, session.PhaseRunning).attest(t, nonce)
			resp.Bind, resp.BindSignature = nil, ""
			return attempt{f.policy, &f.instance.PublicKey, resp}
		}, "bind must contain"},
		"the bind's signature is replaced": {func(t *testing.T, f *fixture, nonce []byte) attempt {
			resp := f.boot(t, f.bind, session.PhaseRunning).attest(t, nonce)
			sig, err := operatorauth.SignDetached(newKey(t), resp.Bind)
			if err != nil {
				t.Fatal(err)
			}
			resp.BindSignature = sig
			return attempt{f.policy, &f.instance.PublicKey, resp}
		}, "signature"},
		"the register never absorbed the bind": {func(t *testing.T, f *fixture, nonce []byte) attempt {
			// An unbound guest that claims a bind in its answer: the events
			// would have to match a register that does not hold them.
			resp := f.boot(t, nil, session.PhaseReady).attest(t, nonce)
			resp.Phase, resp.Bind, resp.BindSignature = session.PhaseRunning, f.bind.Raw, f.bind.Signature
			events, err := session.ExpectedEvents(f.bundle.Launch, f.bind, session.PhaseRunning)
			if err != nil {
				t.Fatal(err)
			}
			resp.Events = events
			return attempt{f.policy, &f.instance.PublicKey, resp}
		}, "REPORTDATA"},
		"a bound guest that says it is ready": {func(t *testing.T, f *fixture, nonce []byte) attempt {
			resp := f.boot(t, f.bind, session.PhaseRunning).attest(t, nonce)
			resp.Phase = session.PhaseReady
			policy := f.policy
			policy.AllowReady = true
			return attempt{policy, &f.instance.PublicKey, resp}
		}, "reports a bind in phase"},
		"a bound guest, under a policy with no authority": {func(t *testing.T, f *fixture, nonce []byte) attempt {
			policy := f.policy
			policy.Authority, policy.Bind, policy.AllowReady = nil, nil, true
			return attempt{policy, &f.instance.PublicKey, f.boot(t, f.bind, session.PhaseRunning).attest(t, nonce)}
		}, "names no authority"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			nonce := freshNonce(t)
			a := tc.build(t, f, nonce)
			assertRefused(t, a.policy, a.key, nonce, a.resp, tc.want)
		})
	}
}

func TestUnboundGuestNeedsAllowReady(t *testing.T) {
	f := newFixture(t, nil)
	g := f.boot(t, nil, session.PhaseReady)
	nonce := freshNonce(t)
	for name, policy := range map[string]session.Policy{
		"an authority that may bind it": func() session.Policy {
			p := f.policy
			p.Bind, p.AllowReady = nil, true
			return p
		}(),
		"no authority at all": func() session.Policy {
			p := f.policy
			p.Authority, p.Bind, p.AllowReady = nil, nil, true
			return p
		}(),
	} {
		att, err := session.VerifyAttestation(context.Background(), policy, sessiontest.Engine{}, &f.instance.PublicKey, nonce, g.attest(t, nonce))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if att.Phase != session.PhaseReady || att.Tenant != "" || att.Session != "" || att.Bind != nil || len(att.Events) != 1 {
			t.Fatalf("%s: unexpected attestation: %+v", name, att)
		}
		if _, ok := att.Egress(); ok {
			t.Fatalf("%s: an unbound guest has an egress policy", name)
		}
	}
}

func TestBoundGuestNeedsAllowBoundBeforeItsSandboxRuns(t *testing.T) {
	f := newFixture(t, nil)
	g := f.boot(t, f.bind, session.PhaseBound)
	nonce := freshNonce(t)
	assertRefused(t, f.policy, &f.instance.PublicKey, nonce, g.attest(t, nonce), "not admitted its sandbox")
	policy := f.policy
	policy.AllowBound = true
	att, err := session.VerifyAttestation(context.Background(), policy, sessiontest.Engine{}, &f.instance.PublicKey, nonce, g.attest(t, nonce))
	if err != nil || len(att.Events) != 2 || att.Phase != session.PhaseBound {
		t.Fatalf("bound guest: %+v, %v", att, err)
	}
	// It must not pass as running by claiming the later phase.
	resp := g.attest(t, nonce)
	resp.Phase = session.PhaseRunning
	assertRefused(t, policy, &f.instance.PublicKey, nonce, resp, "events")
}

func TestPolicyValidation(t *testing.T) {
	f := newFixture(t, nil)
	g := f.boot(t, f.bind, session.PhaseRunning)
	nonce := freshNonce(t)
	for name, mutate := range map[string]func(*session.Policy){
		"no image":                           func(p *session.Policy) { p.Image = nil },
		"no launch key":                      func(p *session.Policy) { p.LaunchKey = nil },
		"a bind pin without an authority":    func(p *session.Policy) { p.Authority = nil },
		"an authority that is not a key":     func(p *session.Policy) { p.Authority = []byte("not a key") },
		"an authority and nothing pinned":    func(p *session.Policy) { p.Bind = nil },
		"no authority and nothing allowed":   func(p *session.Policy) { p.Authority, p.Bind = nil, nil },
		"no authority, and a tenant":         func(p *session.Policy) { p.Authority, p.Bind, p.AllowReady, p.Tenant = nil, nil, true, "acme" },
		"no authority, and a bound guest ok": func(p *session.Policy) { p.Authority, p.Bind, p.AllowReady, p.AllowBound = nil, nil, true, true },
	} {
		policy := f.policy
		mutate(&policy)
		_, err := session.VerifyAttestation(context.Background(), policy, sessiontest.Engine{}, &f.instance.PublicKey, nonce, g.attest(t, nonce))
		var verdict *session.VerificationError
		if err == nil || errors.As(err, &verdict) {
			t.Errorf("%s: %v, want a policy that is refused before any evidence is judged", name, err)
		}
	}
}

func TestExpectedEvents(t *testing.T) {
	f := newFixture(t, nil)
	bare := newFixture(t, func(o *session.BindOptions) { o.Policy.Sandbox = nil })
	launch, bind := session.DocumentDigest(f.bundle.Launch), session.DocumentDigest(f.bind.Raw)
	image, _ := f.bind.Doc.Policy.Sandbox.Digest()
	for name, tc := range map[string]struct {
		f     *fixture
		bind  bool
		phase session.Phase
		want  []string
	}{
		"ready":                   {f, false, session.PhaseReady, []string{launch}},
		"bound":                   {f, true, session.PhaseBound, []string{launch, bind}},
		"running":                 {f, true, session.PhaseRunning, []string{launch, bind, image}},
		"ready with a bind":       {f, true, session.PhaseReady, nil},
		"bound without a bind":    {f, false, session.PhaseBound, nil},
		"running without a bind":  {f, false, session.PhaseRunning, nil},
		"bound without a sandbox": {bare, true, session.PhaseBound, nil},
		"a phase nobody knows":    {f, true, "paused", nil},
	} {
		var b *session.SignedBind
		if tc.bind {
			b = tc.f.bind
		}
		got, err := session.ExpectedEvents(tc.f.bundle.Launch, b, tc.phase)
		if (tc.want == nil) != (err != nil) || strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: %v, %v, want %v", name, got, err, tc.want)
		}
	}
	// A bound guest without a sandbox runs on two events.
	got, err := session.ExpectedEvents(bare.bundle.Launch, bare.bind, session.PhaseRunning)
	if err != nil || len(got) != 2 {
		t.Errorf("bound without a sandbox: %v, %v", got, err)
	}
}
