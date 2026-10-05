package session_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// sealedGuest is the guest's end of a sealed message: its instance key, its
// one-time KEM key, and the bind its owner wrote for it.
type sealedGuest struct {
	instance *ecdsa.PrivateKey
	kem      hpke.PrivateKey
	ready    *session.ReadyTD
	bind     *session.SignedBind
	// signer holds a key the bind grants the exec and credential routes, and
	// granted is that key.
	signer  *operatorauth.Signer
	granted *ecdsa.PublicKey
}

func newSealedGuest(t *testing.T) *sealedGuest {
	t.Helper()
	g := &sealedGuest{instance: newKey(t)}
	var err error
	if g.kem, err = hpke.MLKEM768X25519().GenerateKey(); err != nil {
		t.Fatal(err)
	}
	pair := newOneTimePair(t)
	pair.keys.KEM = g.kem.PublicKey().Bytes()
	g.ready = &session.ReadyTD{InstanceKey: &g.instance.PublicKey, OneTime: pair.keys, Until: time.Now().Add(time.Hour)}
	access := newKey(t)
	accessPEM, err := certutil.MarshalECKeyPEM(access)
	if err != nil {
		t.Fatal(err)
	}
	if g.signer, err = operatorauth.NewSignerFromKeyPEM(accessPEM); err != nil {
		t.Fatal(err)
	}
	g.granted = &access.PublicKey
	g.bind = g.bindFor(t, g.instance)
	return g
}

// bindFor is a bind for the guest that holds instance, granting the guest's
// access key: each call draws a nonce of its own, so each is another bind.
// It declares two credentials its binder holds, and one a key hands over.
func (g *sealedGuest) bindFor(t *testing.T, instance *ecdsa.PrivateKey) *session.SignedBind {
	t.Helper()
	opts := bindOptions(t, newKey(t), instance)
	granted := keyPEM(t, &ecdsa.PrivateKey{PublicKey: *g.granted})
	opts.Policy.Access.Exec = []string{granted}
	opts.Policy.Access.Credentials = []string{granted}
	opts.Policy.Credentials = []session.Credential{
		{Name: "api-token", Source: session.SourceBinder, MaxBytes: 64},
		{Name: "handed-later", MaxBytes: 64},
		{Name: "signing-key", Source: session.SourceBinder},
	}
	bind, err := session.NewBind(opts)
	if err != nil {
		t.Fatal(err)
	}
	return bind
}

// authorizes checks a token as the route it is for would: for this guest,
// that method and path, and those bytes.
func (g *sealedGuest) authorizes(t *testing.T, instance *ecdsa.PublicKey, method, path, authorization string, body []byte) error {
	t.Helper()
	audience, err := session.InstanceKeyDigest(instance)
	if err != nil {
		t.Fatal(err)
	}
	asked, err := http.NewRequest(method, path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	asked.Header.Set("Authorization", authorization)
	verifier := operatorauth.Verifier{Keys: []*ecdsa.PublicKey{g.granted}, ClockSkew: time.Minute, Audience: audience}
	_, err = verifier.AuthorizedBy(asked, body)
	return err
}

func echo() *session.ExecRequest {
	return &session.ExecRequest{Argv: []string{"/bin/echo", "ready"}, Env: map[string]string{"MODE": "first"}, Stdin: []byte("input")}
}

// heldByBinder are the credentials the binder of these tests holds.
func heldByBinder() map[string][]byte {
	return map[string][]byte{"signing-key": []byte("-----BEGIN KEY-----"), "api-token": []byte("s3cr3t-token")}
}

func mustSeal(t *testing.T, g *sealedGuest, bind *session.SignedBind, parts session.SealedParts) *session.SealedMessage {
	t.Helper()
	message, err := session.SealWithBind(g.ready, bind, g.signer, parts)
	if err != nil {
		t.Fatalf("SealWithBind: %v", err)
	}
	return message
}

func mustOpen(t *testing.T, g *sealedGuest, message *session.SealedMessage) *session.OpenedSealed {
	t.Helper()
	opened, err := session.OpenSealed(g.kem, g.bind, message.Sealed)
	if err != nil {
		t.Fatalf("OpenSealed: %v", err)
	}
	if opened.Malformed {
		t.Fatal("a message this package sealed opened as none")
	}
	return opened
}

// allHeld is the outcome of a guest that took every credential of opened.
func allHeld(opened *session.OpenedSealed) []session.CredentialOutcome {
	var out []session.CredentialOutcome
	for _, c := range opened.Credentials {
		out = append(out, session.CredentialOutcome{Name: c.Name, Status: session.SealedHeld})
	}
	return out
}

// A sealed message opens in the guest whose one-time KEM key it was sealed
// to, under the bind it was sealed for: the exec request its sender wrote,
// and each credential, each with a token its own route would take. Its
// answer opens at its sender, and nowhere else.
func TestSealedMessageOpensInItsGuestAndItsAnswerAtItsSender(t *testing.T) {
	g := newSealedGuest(t)
	message := mustSeal(t, g, g.bind, session.SealedParts{Command: echo(), Credentials: heldByBinder()})
	opened := mustOpen(t, g, message)

	var req session.ExecRequest
	if err := json.Unmarshal(opened.Command.Exec, &req); err != nil {
		t.Fatal(err)
	}
	want := echo()
	if strings.Join(req.Argv, " ") != strings.Join(want.Argv, " ") || req.Env["MODE"] != "first" || string(req.Stdin) != "input" {
		t.Fatalf("the guest opened %+v, want what was sealed", req)
	}
	// The sender drew the id the guest runs the command once under, and
	// keeps the request under it for a road of its own.
	if req.Validate() != nil || message.Command.ID != req.ID {
		t.Fatalf("the opened request is not the one its sender keeps: %v, id %q and %q", req.Validate(), req.ID, message.Command.ID)
	}
	if err := g.authorizes(t, &g.instance.PublicKey, http.MethodPost, session.PathExec, opened.Command.Authorization, opened.Command.Exec); err != nil {
		t.Fatalf("the token that came with the command: %v", err)
	}
	// The token names the guest it is for: another guest that grants the
	// same key does not take it.
	if err := g.authorizes(t, &newKey(t).PublicKey, http.MethodPost, session.PathExec, opened.Command.Authorization, opened.Command.Exec); err == nil {
		t.Fatal("the command's token passes at another guest")
	}

	// The credentials come in name order, each as its route would be put it.
	held := heldByBinder()
	if len(opened.Credentials) != 2 || opened.Credentials[0].Name != "api-token" || opened.Credentials[1].Name != "signing-key" {
		t.Fatalf("the guest opened credentials %+v", opened.Credentials)
	}
	for _, c := range opened.Credentials {
		var put session.CredentialRequest
		if err := json.Unmarshal(c.Put, &put); err != nil || !bytes.Equal(put.Value, held[c.Name]) {
			t.Errorf("credential %s opened as %q: %v", c.Name, put.Value, err)
		}
		path := session.PathCredentials + c.Name
		if err := g.authorizes(t, &g.instance.PublicKey, http.MethodPut, path, c.Authorization, c.Put); err != nil {
			t.Errorf("the token that came with credential %s: %v", c.Name, err)
		}
		// A credential's token is for that name, those bytes and this guest.
		if err := g.authorizes(t, &g.instance.PublicKey, http.MethodPut, session.PathCredentials+"handed-later", c.Authorization, c.Put); err == nil {
			t.Errorf("the token of credential %s passes for another name", c.Name)
		}
		if err := g.authorizes(t, &g.instance.PublicKey, http.MethodPut, path, c.Authorization, []byte(`{"value":"AAAA"}`)); err == nil {
			t.Errorf("the token of credential %s passes for another value", c.Name)
		}
		if err := g.authorizes(t, &newKey(t).PublicKey, http.MethodPut, path, c.Authorization, c.Put); err == nil {
			t.Errorf("the token of credential %s passes at another guest", c.Name)
		}
		if err := g.authorizes(t, &g.instance.PublicKey, http.MethodPost, session.PathExec, c.Authorization, c.Put); err == nil {
			t.Errorf("the token of credential %s passes at the exec route", c.Name)
		}
	}

	result := &session.ExecResponse{ExitCode: 3, Stdout: []byte("ready\n"), Stderr: []byte("warn"), DurationMillis: 2}
	answer, err := opened.Seal(session.SealedOutcome{Command: result, Credentials: []session.CredentialOutcome{
		{Name: "api-token", Status: session.SealedHeld}, {Name: "signing-key", Status: session.SealedFailed},
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := message.Open(answer)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Command == nil || got.CommandError != "" || got.Command.ExitCode != 3 || string(got.Command.Stdout) != "ready\n" || string(got.Command.Stderr) != "warn" {
		t.Fatalf("the sender opened %+v", got)
	}
	if len(got.Credentials) != 2 || got.Credentials["api-token"] != session.SealedHeld || got.Credentials["signing-key"] != session.SealedFailed {
		t.Fatalf("the sender reads of its credentials: %v", got.Credentials)
	}
	// The host carries both ways, and reads neither.
	for name, carried := range map[string][]byte{"the message": message.Sealed, "the answer": answer} {
		for _, plain := range []string{"/bin/echo", "input", "ready", "Bearer", "warn", "s3cr3t-token", "BEGIN KEY", "api-token", "held"} {
			if bytes.Contains(carried, []byte(plain)) {
				t.Errorf("%s as it travels holds %q", name, plain)
			}
		}
	}

	// A second message sealed the same way is another, and neither answer
	// opens at the other's sender.
	other := mustSeal(t, g, g.bind, session.SealedParts{Command: echo(), Credentials: heldByBinder()})
	if bytes.Equal(other.Sealed, message.Sealed) {
		t.Fatal("two messages sealed alike are the same bytes")
	}
	if _, err := other.Open(answer); !isVerdict(err) {
		t.Fatalf("an answer opened at the sender of another message: %v", err)
	}
}

// A message may hold a command alone, or credentials alone, and its answer
// says what became of exactly what it held.
func TestSealedMessageHoldsACommandCredentialsOrBoth(t *testing.T) {
	g := newSealedGuest(t)

	alone := mustSeal(t, g, g.bind, session.SealedParts{Command: echo()})
	opened := mustOpen(t, g, alone)
	if opened.Command == nil || len(opened.Credentials) != 0 {
		t.Fatalf("a command alone opened as %+v", opened)
	}
	answer, err := opened.Seal(session.SealedOutcome{Command: &session.ExecResponse{Stdout: []byte("out")}})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := alone.Open(answer); err != nil || got.Command == nil || len(got.Credentials) != 0 {
		t.Fatalf("the answer to a command alone: %+v, %v", got, err)
	}

	only := mustSeal(t, g, g.bind, session.SealedParts{Credentials: heldByBinder()})
	if only.Command != nil {
		t.Fatal("a message with no command keeps one for another road")
	}
	opened = mustOpen(t, g, only)
	if opened.Command != nil || len(opened.Credentials) != 2 {
		t.Fatalf("credentials alone opened as %+v", opened)
	}
	// A guest that ran a command nobody sealed says nothing of it: the
	// answer holds what the message held.
	answer, err = opened.Seal(session.SealedOutcome{Command: &session.ExecResponse{Stdout: []byte("never asked for")}, Credentials: allHeld(opened)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := only.Open(answer)
	if err != nil || got.Command != nil || got.CommandError != "" || got.Credentials["api-token"] != session.SealedHeld {
		t.Fatalf("the answer to credentials alone: %+v, %v", got, err)
	}
}

// A message opens under the bind it was sealed for alone, and with the key
// it was sealed to alone: the same guest under another bind does not open
// it, and neither does another guest under the same bind.
func TestSealedMessageOpensUnderItsBindAndItsKeyAlone(t *testing.T) {
	g := newSealedGuest(t)
	message := mustSeal(t, g, g.bind, session.SealedParts{Command: echo(), Credentials: heldByBinder()})

	if _, err := session.OpenSealed(g.kem, g.bindFor(t, g.instance), message.Sealed); err == nil {
		t.Error("the message opened under another bind for the same guest")
	}
	stranger, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.OpenSealed(stranger, g.bind, message.Sealed); err == nil {
		t.Error("the message opened with another guest's key")
	}
	// Any byte of it changed, it opens nowhere.
	for _, at := range []int{0, 31, 1087, 1088, 1119, 1120, len(message.Sealed) - 1} {
		changed := bytes.Clone(message.Sealed)
		changed[at] ^= 1
		if _, err := session.OpenSealed(g.kem, g.bind, changed); err == nil {
			t.Errorf("the message opened with byte %d changed", at)
		}
	}
	for name, sealed := range map[string][]byte{
		"nothing":                    nil,
		"an encapsulated key alone":  message.Sealed[:1120],
		"less than one":              message.Sealed[:500],
		"more than a message may be": make([]byte, session.MaxSealedBytes+1),
	} {
		if _, err := session.OpenSealed(g.kem, g.bind, sealed); err == nil {
			t.Errorf("%s opened as a message", name)
		}
	}
}

// A binder seals only to keys its own check of the guest's evidence gave it,
// for a bind that names that guest: a request the exec route would take, and
// credentials that bind says come from its binder, each within its size.
func TestMessageIsSealedOnlyToAVerifiedGuestAndAsItsBindSays(t *testing.T) {
	g := newSealedGuest(t)
	long := echo()
	long.Stdin = make([]byte, session.MaxExecStdin+1)
	noKEM := *g.ready
	noKEM.OneTime = &session.OneTimeKeys{Signing: g.ready.OneTime.Signing, KEM: []byte("no key")}
	forABind, over := *g.ready, *g.ready
	forABind.Until, over.Until = time.Time{}, time.Now().Add(-time.Second)
	command := func(req *session.ExecRequest) session.SealedParts { return session.SealedParts{Command: req} }
	credential := func(name string, value []byte) session.SealedParts {
		return session.SealedParts{Credentials: map[string][]byte{name: value}}
	}
	many := map[string][]byte{}
	for i := range 33 {
		many[fmt.Sprintf("credential-%d", i)] = []byte("x")
	}
	for name, tc := range map[string]struct {
		ready *session.ReadyTD
		bind  *session.SignedBind
		parts session.SealedParts
	}{
		"no verdict on the guest":                {nil, g.bind, command(echo())},
		"a guest whose evidence binds none":      {&session.ReadyTD{InstanceKey: &g.instance.PublicKey, Until: g.ready.Until}, g.bind, command(echo())},
		"a verdict that is enough for a bind":    {&forABind, g.bind, command(echo())},
		"a verdict whose time is up":             {&over, g.bind, credential("api-token", []byte("x"))},
		"a key that is none":                     {&noKEM, g.bind, command(echo())},
		"a bind for another guest":               {g.ready, g.bindFor(t, newKey(t)), command(echo())},
		"nothing to seal":                        {g.ready, g.bind, session.SealedParts{}},
		"a request with no command":              {g.ready, g.bind, command(&session.ExecRequest{})},
		"a request the exec route refuses":       {g.ready, g.bind, command(long)},
		"an id of the sender's own making":       {g.ready, g.bind, command(&session.ExecRequest{ID: "not an id", Argv: []string{"/bin/true"}})},
		"a credential the bind does not declare": {g.ready, g.bind, credential("unheard-of", []byte("x"))},
		"a credential a key hands over":          {g.ready, g.bind, credential("handed-later", []byte("x"))},
		"a credential with no value":             {g.ready, g.bind, credential("api-token", nil)},
		"a credential beyond its declared size":  {g.ready, g.bind, credential("api-token", make([]byte, 65))},
		"a credential beyond the default size":   {g.ready, g.bind, credential("signing-key", make([]byte, 64*1024+1))},
		"more credentials than a bind declares":  {g.ready, g.bind, session.SealedParts{Credentials: many}},
	} {
		if message, err := session.SealWithBind(tc.ready, tc.bind, g.signer, tc.parts); err == nil {
			t.Errorf("%s: sealed %d bytes", name, len(message.Sealed))
		}
	}
	// At its declared size, a credential seals.
	if _, err := session.SealWithBind(g.ready, g.bind, g.signer, credential("api-token", make([]byte, 64))); err != nil {
		t.Errorf("a credential of its declared size: %v", err)
	}
}

// sealedInfo and sealedExport are the labels of a sealed message's HPKE
// context, as another implementation of a binder would write them.
const (
	sealedInfo   = "c8s-session sealed with a bind/v1\x00"
	sealedExport = "c8s-session sealed with a bind/v1 answer"
)

// What is sealed to the guest's key under its bind and is no message opens,
// since it was sealed to this guest, and the guest's answer says so to its
// sender alone. The seal is HPKE in base mode over the hybrid KEM, with the
// bind's digest in its info.
func TestSealedBytesThatAreNoMessageAreAnsweredAsSuch(t *testing.T) {
	g := newSealedGuest(t)
	key, err := hpke.MLKEM768X25519().NewPublicKey(g.ready.OneTime.KEM)
	if err != nil {
		t.Fatal(err)
	}
	info := append([]byte(sealedInfo), session.DocumentDigest(g.bind.Raw)...)
	put := `{"name":"api-token","authorization":"Bearer x","put":{"value":"eA=="}}`
	for name, plain := range map[string]string{
		"no JSON":                   "run this",
		"another document":          `{"argv":["/bin/true"]}`,
		"a member more":             `{"command":{"authorization":"Bearer x","exec":{"id":"00"}},"note":"x"}`,
		"a command's member more":   `{"command":{"authorization":"Bearer x","exec":{"id":"00"},"note":"x"}}`,
		"no exec request":           `{"command":{"authorization":"Bearer x"}}`,
		"an empty document":         `{}`,
		"no credentials in a list":  `{"credentials":[]}`,
		"one name twice":            `{"credentials":[` + put + `,` + put + `]}`,
		"a credential with no put":  `{"credentials":[{"name":"api-token","authorization":"Bearer x"}]}`,
		"a second document behind":  `{"credentials":[` + put + `]} {"command":{"authorization":"x","exec":{}}}`,
		"more than a bind declares": `{"credentials":[` + strings.TrimSuffix(strings.Repeat(`{"name":"n","authorization":"x","put":{}},`, 33), ",") + `]}`,
	} {
		enc, sender, err := hpke.NewSender(key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext, err := sender.Seal(nil, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		opened, err := session.OpenSealed(g.kem, g.bind, append(enc, ciphertext...))
		if err != nil {
			t.Errorf("%s: sealed to this guest under this bind, and it did not open: %v", name, err)
			continue
		}
		if !opened.Malformed || opened.Command != nil || len(opened.Credentials) != 0 {
			t.Errorf("%s: opened as a message with %d credentials", name, len(opened.Credentials))
		}
		// Whatever the guest says it did, the answer says what was sealed
		// is no message.
		answer, err := opened.Seal(session.SealedOutcome{Command: &session.ExecResponse{}, Credentials: []session.CredentialOutcome{{Name: "api-token", Status: session.SealedHeld}}})
		if err != nil {
			t.Errorf("%s: the guest cannot say so: %v", name, err)
			continue
		}
		// Its sender opens the answer as Oblivious HTTP opens a response:
		// under a key from the secret both ends export, salted with the
		// message's encapsulated key and the value the answer leads with.
		if got := openAnswer(t, sender, enc, answer); got != `{"error":"invalid"}` {
			t.Errorf("%s: the guest's answer holds %q", name, got)
		}
	}
	// A message another implementation seals opens as one.
	enc, sender, err := hpke.NewSender(key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sender.Seal(nil, []byte(`{"credentials":[`+put+`]}`))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := session.OpenSealed(g.kem, g.bind, append(enc, ciphertext...))
	if err != nil || opened.Malformed || len(opened.Credentials) != 1 || string(opened.Credentials[0].Put) != `{"value":"eA=="}` {
		t.Fatalf("a message of another's making did not open as one: %v", err)
	}
	answer, err := opened.Seal(session.SealedOutcome{Credentials: []session.CredentialOutcome{{Name: "api-token", Status: session.SealedUnauthorized}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := openAnswer(t, sender, enc, answer); got != `{"credentials":[{"name":"api-token","status":"unauthorized"}]}` {
		t.Errorf("the guest's answer holds %q", got)
	}
	// The same bytes under an info that leaves the bind out do not open: the
	// bind is what the seal is for.
	enc, sender, err = hpke.NewSender(key, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(sealedInfo))
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext, err = sender.Seal(nil, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := session.OpenSealed(g.kem, g.bind, append(enc, ciphertext...)); err == nil {
		t.Error("bytes sealed for no bind opened under one")
	}
}

// openAnswer opens a sealed answer with nothing of this package's: what
// another implementation of a binder would do with it.
func openAnswer(t *testing.T, sender *hpke.Sender, enc, answer []byte) string {
	t.Helper()
	secret, err := sender.Export(sealedExport, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(answer) < 32 {
		t.Fatalf("an answer of %d bytes", len(answer))
	}
	nonce, ciphertext := answer[:32], answer[32:]
	prk, err := hkdf.Extract(sha256.New, secret, append(bytes.Clone(enc), nonce...))
	if err != nil {
		t.Fatal(err)
	}
	key, err := hkdf.Expand(sha256.New, prk, "key", 32)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := hkdf.Expand(sha256.New, prk, "nonce", 12)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := aead.Open(nil, iv, ciphertext, nil)
	if err != nil {
		t.Fatalf("the answer does not open as its format says: %v", err)
	}
	return string(plain)
}

// A sender takes as its message's answer only what the guest that opened the
// message sealed, and only an answer that says what became of each part it
// sealed: a command not run is told apart from a result, and bytes of anyone
// else's making are no answer.
func TestSealedAnswerIsTheGuestsAloneAndSaysWhatBecameOfEachPart(t *testing.T) {
	g := newSealedGuest(t)
	message := mustSeal(t, g, g.bind, session.SealedParts{Command: echo(), Credentials: heldByBinder()})
	opened := mustOpen(t, g, message)
	held := allHeld(opened)

	for _, reason := range []string{session.SealedUnauthorized, session.SealedInvalid, session.SealedFailed} {
		sealed, err := opened.Seal(session.SealedOutcome{CommandError: reason, Credentials: held})
		if err != nil {
			t.Fatal(err)
		}
		got, err := message.Open(sealed)
		if err != nil || got.Command != nil || got.CommandError != reason || got.Credentials["signing-key"] != session.SealedHeld {
			t.Errorf("a command not run as %s reads: %+v, %v", reason, got, err)
		}
	}

	ran := &session.ExecResponse{Stdout: []byte("out")}
	for name, outcome := range map[string]session.SealedOutcome{
		"no word on the command":         {Credentials: held},
		"a result and a refusal at once": {Command: ran, CommandError: session.SealedFailed, Credentials: held},
		"no word on the credentials":     {Command: ran},
		"a credential left out":          {Command: ran, Credentials: held[:1]},
		"a credential more":              {Command: ran, Credentials: append(append([]session.CredentialOutcome(nil), held...), session.CredentialOutcome{Name: "handed-later", Status: session.SealedHeld})},
		"another credential's name":      {Command: ran, Credentials: []session.CredentialOutcome{held[0], {Name: "handed-later", Status: session.SealedHeld}}},
		"the credentials out of order":   {Command: ran, Credentials: []session.CredentialOutcome{held[1], held[0]}},
		"a credential with no word":      {Command: ran, Credentials: []session.CredentialOutcome{held[0], {Name: held[1].Name}}},
	} {
		sealed, err := opened.Seal(outcome)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := message.Open(sealed); !isVerdict(err) {
			t.Errorf("an answer with %s was taken: %+v, %v", name, got, err)
		}
	}

	answer, err := opened.Seal(session.SealedOutcome{Command: ran, Credentials: held})
	if err != nil {
		t.Fatal(err)
	}
	again, err := opened.Seal(session.SealedOutcome{Command: ran, Credentials: held})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(answer, again) {
		t.Error("the same outcome sealed twice is the same bytes: the answer's nonce is not drawn anew")
	}
	for at := range answer {
		changed := bytes.Clone(answer)
		changed[at] ^= 1
		if _, err := message.Open(changed); !isVerdict(err) {
			t.Fatalf("an answer with byte %d changed: %v", at, err)
		}
	}
	for name, bytes := range map[string][]byte{
		"nothing":                    nil,
		"less than its nonce":        answer[:31],
		"its nonce alone":            answer[:32],
		"more than an answer may be": make([]byte, session.MaxSealedAnswerBytes+1),
	} {
		if _, err := message.Open(bytes); !isVerdict(err) {
			t.Errorf("%s as an answer: %v", name, err)
		}
	}
	// A guest that opened another message of the same sender does not answer
	// this one.
	otherOpened := mustOpen(t, g, mustSeal(t, g, g.bind, session.SealedParts{Command: echo(), Credentials: heldByBinder()}))
	stray, err := otherOpened.Seal(session.SealedOutcome{Command: ran, Credentials: held})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := message.Open(stray); !isVerdict(err) {
		t.Errorf("the answer to another message: %v", err)
	}
	// Once the guest forgets what it sealed answers under, it seals none,
	// and holds no credential of the message any more.
	values := opened.Credentials
	opened.Forget()
	if late, err := opened.Seal(session.SealedOutcome{Command: ran, Credentials: held}); err == nil {
		t.Errorf("the guest sealed %d bytes under a secret it forgot", len(late))
	}
	for _, c := range values {
		if !bytes.Equal(c.Put, make([]byte, len(c.Put))) {
			t.Errorf("credential %s is still in the forgotten message", c.Name)
		}
	}
	if len(opened.Credentials) != 0 {
		t.Error("a forgotten message still lists its credentials")
	}
}

// The largest result a command can have fits in an answer: both outputs at
// their bound, beside a word on every credential a bind can declare, are
// within what a sender opens. The largest request fits in a message, and a
// binder that holds more than fits beside it is told so before it sends.
func TestLargestSealedAnswerAndRequestFit(t *testing.T) {
	g := newSealedGuest(t)
	message := mustSeal(t, g, g.bind, session.SealedParts{Command: echo(), Credentials: heldByBinder()})
	opened := mustOpen(t, g, message)
	full := &session.ExecResponse{
		ExitCode: 255, Stdout: bytes.Repeat([]byte{0xff}, session.MaxExecOutput), Stderr: bytes.Repeat([]byte{0xfe}, session.MaxExecOutput),
		StdoutTruncated: true, StderrTruncated: true, TimedOut: true, DurationMillis: 1 << 40,
	}
	answer, err := opened.Seal(session.SealedOutcome{Command: full, Credentials: allHeld(opened)})
	if err != nil {
		t.Fatal(err)
	}
	if len(answer) > session.MaxSealedAnswerBytes {
		t.Fatalf("the largest answer is %d bytes, and a sender opens at most %d", len(answer), session.MaxSealedAnswerBytes)
	}
	got, err := message.Open(answer)
	if err != nil || len(got.Command.Stdout) != session.MaxExecOutput || len(got.Command.Stderr) != session.MaxExecOutput {
		t.Fatalf("the largest answer did not open whole: %v", err)
	}
	// The largest request fits in a sealed message, with credentials beside
	// it.
	largest := &session.ExecRequest{Argv: []string{"/bin/cat"}, Stdin: bytes.Repeat([]byte{0xff}, session.MaxExecStdin)}
	beside := map[string][]byte{"api-token": bytes.Repeat([]byte{0xff}, 64), "signing-key": bytes.Repeat([]byte{0xff}, 64*1024)}
	whole, err := session.SealWithBind(g.ready, g.bind, g.signer, session.SealedParts{Command: largest, Credentials: beside})
	if err != nil {
		t.Fatalf("the largest request does not seal with credentials beside it: %v", err)
	}
	if _, err := session.OpenSealed(g.kem, g.bind, whole.Sealed); err != nil {
		t.Fatalf("the largest request does not open: %v", err)
	}
	// What a bind may declare is more than a message holds: the binder
	// learns that when it seals, and puts the rest over a connection.
	opts := bindOptions(t, newKey(t), g.instance)
	granted := keyPEM(t, &ecdsa.PrivateKey{PublicKey: *g.granted})
	opts.Policy.Access.Exec, opts.Policy.Access.Credentials = []string{granted}, []string{granted}
	opts.Policy.Credentials = nil
	much := map[string][]byte{}
	for i := range 32 {
		name := fmt.Sprintf("credential-%02d", i)
		opts.Policy.Credentials = append(opts.Policy.Credentials, session.Credential{Name: name, Source: session.SourceBinder})
		much[name] = bytes.Repeat([]byte{0xff}, 64*1024)
	}
	wide, err := session.NewBind(opts)
	if err != nil {
		t.Fatal(err)
	}
	if message, err := session.SealWithBind(g.ready, wide, g.signer, session.SealedParts{Credentials: much}); err == nil {
		t.Errorf("credentials beyond what a message holds sealed as %d bytes", len(message.Sealed))
	}
}
