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
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// commandGuest is the guest's end of a first command: its instance key, its
// one-time KEM key, and the bind its owner wrote for it.
type commandGuest struct {
	instance *ecdsa.PrivateKey
	kem      hpke.PrivateKey
	ready    *session.ReadyTD
	bind     *session.SignedBind
	// signer holds a key the bind grants the exec route, and granted is that
	// key.
	signer  *operatorauth.Signer
	granted *ecdsa.PublicKey
}

func newCommandGuest(t *testing.T) *commandGuest {
	t.Helper()
	g := &commandGuest{instance: newKey(t)}
	var err error
	if g.kem, err = hpke.MLKEM768X25519().GenerateKey(); err != nil {
		t.Fatal(err)
	}
	pair := newOneTimePair(t)
	pair.keys.KEM = g.kem.PublicKey().Bytes()
	g.ready = &session.ReadyTD{InstanceKey: &g.instance.PublicKey, OneTime: pair.keys}
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
func (g *commandGuest) bindFor(t *testing.T, instance *ecdsa.PrivateKey) *session.SignedBind {
	t.Helper()
	opts := bindOptions(t, newKey(t), instance)
	opts.Policy.Access.Exec = []string{keyPEM(t, &ecdsa.PrivateKey{PublicKey: *g.granted})}
	bind, err := session.NewBind(opts)
	if err != nil {
		t.Fatal(err)
	}
	return bind
}

// authorizes checks the token an opened command came with as the guest's
// exec route would: for this guest, that route and those bytes.
func (g *commandGuest) authorizes(t *testing.T, opened *session.OpenedFirstCommand, instance *ecdsa.PublicKey) error {
	t.Helper()
	audience, err := session.InstanceKeyDigest(instance)
	if err != nil {
		t.Fatal(err)
	}
	asked, err := http.NewRequest(http.MethodPost, session.PathExec, bytes.NewReader(opened.Exec))
	if err != nil {
		t.Fatal(err)
	}
	asked.Header.Set("Authorization", opened.Authorization)
	verifier := operatorauth.Verifier{Keys: []*ecdsa.PublicKey{g.granted}, ClockSkew: time.Minute, Audience: audience}
	_, err = verifier.AuthorizedBy(asked, opened.Exec)
	return err
}

func echo() session.ExecRequest {
	return session.ExecRequest{Argv: []string{"/bin/echo", "ready"}, Env: map[string]string{"MODE": "first"}, Stdin: []byte("input")}
}

func mustSeal(t *testing.T, g *commandGuest, bind *session.SignedBind) *session.FirstCommand {
	t.Helper()
	command, err := session.SealFirstCommand(g.ready, bind, g.signer, echo())
	if err != nil {
		t.Fatalf("SealFirstCommand: %v", err)
	}
	return command
}

// A first command opens in the guest whose one-time KEM key it was sealed
// to, under the bind it was sealed for, as the exec request its sender wrote
// and with a token the guest's exec route would take. Its answer opens at
// its sender, and nowhere else.
func TestFirstCommandOpensInItsGuestAndItsAnswerAtItsSender(t *testing.T) {
	g := newCommandGuest(t)
	command := mustSeal(t, g, g.bind)

	opened, err := session.OpenFirstCommand(g.kem, g.bind, command.Sealed)
	if err != nil {
		t.Fatalf("OpenFirstCommand: %v", err)
	}
	var req session.ExecRequest
	if err := json.Unmarshal(opened.Exec, &req); err != nil {
		t.Fatal(err)
	}
	want := echo()
	if strings.Join(req.Argv, " ") != strings.Join(want.Argv, " ") || req.Env["MODE"] != "first" || string(req.Stdin) != "input" {
		t.Fatalf("the guest opened %+v, want what was sealed", req)
	}
	// The sender drew the id the guest runs the command once under.
	if req.Validate() != nil {
		t.Fatalf("the opened request is not one the exec route takes: %v", req.Validate())
	}
	if err := g.authorizes(t, opened, &g.instance.PublicKey); err != nil {
		t.Fatalf("the token that came with the command: %v", err)
	}
	// The token names the guest it is for: another guest that grants the
	// same key does not take it.
	if err := g.authorizes(t, opened, &newKey(t).PublicKey); err == nil {
		t.Fatal("the command's token passes at another guest")
	}

	result := &session.ExecResponse{ExitCode: 3, Stdout: []byte("ready\n"), Stderr: []byte("warn"), DurationMillis: 2}
	answer, err := opened.Seal(result)
	if err != nil {
		t.Fatal(err)
	}
	got, err := command.Open(answer)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.ExitCode != 3 || string(got.Stdout) != "ready\n" || string(got.Stderr) != "warn" {
		t.Fatalf("the sender opened %+v", got)
	}
	// The host carries both ways, and reads neither.
	for name, carried := range map[string][]byte{"the command": command.Sealed, "the answer": answer} {
		for _, plain := range []string{"/bin/echo", "input", "ready", "Bearer", "warn"} {
			if bytes.Contains(carried, []byte(plain)) {
				t.Errorf("%s as it travels holds %q", name, plain)
			}
		}
	}

	// A second command sealed the same way is another, and neither answer
	// opens at the other's sender.
	other := mustSeal(t, g, g.bind)
	if bytes.Equal(other.Sealed, command.Sealed) {
		t.Fatal("two commands sealed alike are the same bytes")
	}
	if _, err := other.Open(answer); !isVerdict(err) {
		t.Fatalf("an answer opened at the sender of another command: %v", err)
	}
}

// A command opens under the bind it was sealed for alone, and with the key
// it was sealed to alone: the same guest under another bind does not open
// it, and neither does another guest under the same bind.
func TestFirstCommandOpensUnderItsBindAndItsKeyAlone(t *testing.T) {
	g := newCommandGuest(t)
	command := mustSeal(t, g, g.bind)

	if _, err := session.OpenFirstCommand(g.kem, g.bindFor(t, g.instance), command.Sealed); err == nil {
		t.Error("the command opened under another bind for the same guest")
	}
	stranger, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.OpenFirstCommand(stranger, g.bind, command.Sealed); err == nil {
		t.Error("the command opened with another guest's key")
	}
	// Any byte of it changed, it opens nowhere.
	for _, at := range []int{0, 31, 1087, 1088, 1119, 1120, len(command.Sealed) - 1} {
		changed := bytes.Clone(command.Sealed)
		changed[at] ^= 1
		if _, err := session.OpenFirstCommand(g.kem, g.bind, changed); err == nil {
			t.Errorf("the command opened with byte %d changed", at)
		}
	}
	for name, sealed := range map[string][]byte{
		"nothing":                    nil,
		"an encapsulated key alone":  command.Sealed[:1120],
		"less than one":              command.Sealed[:500],
		"more than a command may be": make([]byte, session.MaxFirstCommandBytes+1),
	} {
		if _, err := session.OpenFirstCommand(g.kem, g.bind, sealed); err == nil {
			t.Errorf("%s opened as a command", name)
		}
	}
}

// A binder seals a command only to keys its own check of the guest's
// evidence gave it, for a bind that names that guest, and only a request the
// exec route would take.
func TestFirstCommandIsSealedOnlyToAVerifiedGuest(t *testing.T) {
	g := newCommandGuest(t)
	long := echo()
	long.Stdin = make([]byte, session.MaxExecStdin+1)
	noKEM := *g.ready
	noKEM.OneTime = &session.OneTimeKeys{Signing: g.ready.OneTime.Signing, KEM: []byte("no key")}
	for name, tc := range map[string]struct {
		ready *session.ReadyTD
		bind  *session.SignedBind
		req   session.ExecRequest
	}{
		"no verdict on the guest":           {nil, g.bind, echo()},
		"a guest whose evidence binds none": {&session.ReadyTD{InstanceKey: &g.instance.PublicKey}, g.bind, echo()},
		"a key that is none":                {&noKEM, g.bind, echo()},
		"a bind for another guest":          {g.ready, g.bindFor(t, newKey(t)), echo()},
		"a request with no command":         {g.ready, g.bind, session.ExecRequest{}},
		"a request the exec route refuses":  {g.ready, g.bind, long},
		"an id of the sender's own making":  {g.ready, g.bind, session.ExecRequest{ID: "not an id", Argv: []string{"/bin/true"}}},
	} {
		if command, err := session.SealFirstCommand(tc.ready, tc.bind, g.signer, tc.req); err == nil {
			t.Errorf("%s: sealed %d bytes", name, len(command.Sealed))
		}
	}
}

// What is sealed to the guest's key under its bind and is no command opens,
// since it was sealed to this guest, and the guest's answer says so to its
// sender alone. The seal is HPKE in base mode over the hybrid KEM, with the
// bind's digest in its info.
func TestSealedBytesThatAreNoCommandAreAnsweredAsSuch(t *testing.T) {
	g := newCommandGuest(t)
	key, err := hpke.MLKEM768X25519().NewPublicKey(g.ready.OneTime.KEM)
	if err != nil {
		t.Fatal(err)
	}
	info := append([]byte("c8s-session first command/v1\x00"), session.DocumentDigest(g.bind.Raw)...)
	for name, plain := range map[string]string{
		"no JSON":           "run this",
		"another document":  `{"argv":["/bin/true"]}`,
		"a member more":     `{"authorization":"Bearer x","exec":{"id":"00"},"note":"x"}`,
		"no exec request":   `{"authorization":"Bearer x"}`,
		"an empty document": `{}`,
	} {
		enc, sender, err := hpke.NewSender(key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext, err := sender.Seal(nil, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		opened, err := session.OpenFirstCommand(g.kem, g.bind, append(enc, ciphertext...))
		if err != nil {
			t.Errorf("%s: sealed to this guest under this bind, and it did not open: %v", name, err)
			continue
		}
		if len(opened.Exec) != 0 || opened.Authorization != "" {
			t.Errorf("%s: opened as a command: %q", name, opened.Exec)
		}
		answer, err := opened.Refuse(session.FirstCommandInvalid)
		if err != nil {
			t.Errorf("%s: the guest cannot say so: %v", name, err)
			continue
		}
		// Its sender opens the answer as Oblivious HTTP opens a response:
		// under a key from the secret both ends export, salted with the
		// command's encapsulated key and the value the answer leads with.
		if got := openAnswer(t, sender, enc, answer); got != `{"error":"invalid"}` {
			t.Errorf("%s: the guest's answer holds %q", name, got)
		}
	}
	// The same bytes under an info that leaves the bind out do not open: the
	// bind is what the seal is for.
	enc, sender, err := hpke.NewSender(key, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("c8s-session first command/v1\x00"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sender.Seal(nil, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.OpenFirstCommand(g.kem, g.bind, append(enc, ciphertext...)); err == nil {
		t.Error("bytes sealed for no bind opened under one")
	}
}

// openAnswer opens a sealed answer with nothing of this package's: what
// another implementation of a binder would do with it.
func openAnswer(t *testing.T, sender *hpke.Sender, enc, answer []byte) string {
	t.Helper()
	secret, err := sender.Export("c8s-session first command/v1 answer", 32)
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

// A sender takes as its command's answer only what the guest that opened the
// command sealed: a refusal is told apart from a result, and bytes of anyone
// else's making are no answer.
func TestFirstCommandAnswerIsTheGuestsAlone(t *testing.T) {
	g := newCommandGuest(t)
	command := mustSeal(t, g, g.bind)
	opened, err := session.OpenFirstCommand(g.kem, g.bind, command.Sealed)
	if err != nil {
		t.Fatal(err)
	}

	for _, reason := range []string{session.FirstCommandUnauthorized, session.FirstCommandInvalid, session.FirstCommandFailed} {
		refusal, err := opened.Refuse(reason)
		if err != nil {
			t.Fatal(err)
		}
		_, err = command.Open(refusal)
		var refused *session.FirstCommandError
		if !errors.As(err, &refused) || refused.Reason != reason {
			t.Errorf("a command refused as %s reads: %v", reason, err)
		}
	}

	answer, err := opened.Seal(&session.ExecResponse{Stdout: []byte("out")})
	if err != nil {
		t.Fatal(err)
	}
	again, err := opened.Seal(&session.ExecResponse{Stdout: []byte("out")})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(answer, again) {
		t.Error("the same result sealed twice is the same bytes: the answer's nonce is not drawn anew")
	}
	for at := range answer {
		changed := bytes.Clone(answer)
		changed[at] ^= 1
		if _, err := command.Open(changed); !isVerdict(err) {
			t.Fatalf("an answer with byte %d changed: %v", at, err)
		}
	}
	for name, bytes := range map[string][]byte{
		"nothing":                    nil,
		"less than its nonce":        answer[:31],
		"its nonce alone":            answer[:32],
		"more than an answer may be": make([]byte, session.MaxFirstCommandAnswerBytes+1),
	} {
		if _, err := command.Open(bytes); !isVerdict(err) {
			t.Errorf("%s as an answer: %v", name, err)
		}
	}
	// A guest that opened another command of the same sender does not answer
	// this one.
	otherOpened, err := session.OpenFirstCommand(g.kem, g.bind, mustSeal(t, g, g.bind).Sealed)
	if err != nil {
		t.Fatal(err)
	}
	stray, err := otherOpened.Seal(&session.ExecResponse{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := command.Open(stray); !isVerdict(err) {
		t.Errorf("the answer to another command: %v", err)
	}
	// Once the guest forgets what it sealed answers under, it seals none.
	opened.Forget()
	if late, err := opened.Seal(&session.ExecResponse{}); err == nil {
		t.Errorf("the guest sealed %d bytes under a secret it forgot", len(late))
	}
}

// The largest result a command can have fits in an answer: both outputs at
// their bound, sealed, are within what a sender opens.
func TestLargestFirstCommandAnswerFits(t *testing.T) {
	g := newCommandGuest(t)
	command := mustSeal(t, g, g.bind)
	opened, err := session.OpenFirstCommand(g.kem, g.bind, command.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	full := &session.ExecResponse{
		ExitCode: 255, Stdout: bytes.Repeat([]byte{0xff}, session.MaxExecOutput), Stderr: bytes.Repeat([]byte{0xfe}, session.MaxExecOutput),
		StdoutTruncated: true, StderrTruncated: true, TimedOut: true, DurationMillis: 1 << 40,
	}
	answer, err := opened.Seal(full)
	if err != nil {
		t.Fatal(err)
	}
	if len(answer) > session.MaxFirstCommandAnswerBytes {
		t.Fatalf("the largest answer is %d bytes, and a sender opens at most %d", len(answer), session.MaxFirstCommandAnswerBytes)
	}
	got, err := command.Open(answer)
	if err != nil || len(got.Stdout) != session.MaxExecOutput || len(got.Stderr) != session.MaxExecOutput {
		t.Fatalf("the largest answer did not open whole: %v", err)
	}
	// And the largest request fits in a sealed command.
	req := session.ExecRequest{Argv: []string{"/bin/cat"}, Stdin: bytes.Repeat([]byte{0xff}, session.MaxExecStdin)}
	if _, err := session.SealFirstCommand(g.ready, g.bind, g.signer, req); err != nil {
		t.Fatalf("the largest request does not seal: %v", err)
	}
}
