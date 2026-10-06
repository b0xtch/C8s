package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// A binder that sends a guest its bind itself may send one sealed message
// with it: the session's first command, the credentials the binder holds
// that the bind says come from it, or both. The message is sealed to the
// one-time KEM key the guest's evidence bound while the guest was nobody's
// (OneTimeKeys). The guest keeps that key until its sandbox is about to run
// anything of the tenant, tries the first message that comes by then, and
// erases the key whatever came of it, so a message opens only in the guest it
// was sealed for and only while that guest takes its bind. The guest's host
// carries ciphertext both ways.
//
// The seal is HPKE in base mode, under a label and the bind's digest as the
// info, so a message opens under that bind alone. Base mode does not say who
// sealed, and anyone who has the guest's evidence can seal to its key, so
// each part carries the token its route would take over a connection to the
// guest: the command one of a key the bind lets run commands, each credential
// one of a key the bind lets release credentials, for this guest and over
// those bytes. The answer comes back sealed under a key exported from the
// same context, as an Oblivious HTTP response is (RFC 9458): the binder needs
// no key of its own.

const (
	// sealedInfo starts the HPKE info of a sealed message: the bind's digest
	// follows.
	sealedInfo = "c8s-session sealed with a bind/v1\x00"
	// sealedExport is the exporter context of the secret an answer is sealed
	// under.
	sealedExport = "c8s-session sealed with a bind/v1 answer"
	// sealedNonce is the size of the random value an answer leads with: the
	// larger of the AEAD's key and nonce sizes.
	sealedNonce = 32
	// MaxSealedBytes bounds a sealed message: the largest exec request, with
	// room beside it for some four hundred kilobytes of credentials. A
	// binder that holds more puts the rest over a connection to the guest.
	MaxSealedBytes = 2 << 20
	// MaxSealedAnswerBytes bounds a sealed answer: a command's bounded
	// result, what became of each credential, and what sealing adds.
	MaxSealedAnswerBytes = 4 << 20
)

func sealedSuite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.AES256GCM() }

// ErrNotForRelease refuses to seal on a verdict that lets no secret go: it
// rests on a root CA CRL the guest's host handed over, which is enough for a
// bind alone, or its time is up. The binder sends its bind without a sealed
// message, and what it would have sealed over a connection to the bound
// guest, whose own verdict is made for release.
var ErrNotForRelease = errors.New("nothing is sealed on this verdict on the guest: it rests on a root CA CRL the guest's host handed over, or its time is up")

// SealedParts is what a binder seals with a bind.
type SealedParts struct {
	// Command is the session's first command, or nil.
	Command *ExecRequest
	// Credentials are the credentials the binder holds, by the names the
	// bind says come from it (SourceBinder).
	Credentials map[string][]byte
}

// sealedPlain is what a sealed message holds.
type sealedPlain struct {
	Command     *sealedCommand     `json:"command,omitempty"`
	Credentials []sealedCredential `json:"credentials,omitempty"`
}

// wellFormed reports whether p is a message: a command, credentials or both,
// each credential under a name of its own.
func (p *sealedPlain) wellFormed() bool {
	if p.Command == nil && len(p.Credentials) == 0 || len(p.Credentials) > maxCredentials {
		return false
	}
	if p.Command != nil && len(p.Command.Exec) == 0 {
		return false
	}
	names := make(map[string]bool, len(p.Credentials))
	for _, c := range p.Credentials {
		if names[c.Name] || len(c.Put) == 0 {
			return false
		}
		names[c.Name] = true
	}
	return true
}

// sealedCommand is the exec request as it would travel to PathExec, and the
// token that authorizes it there.
type sealedCommand struct {
	Authorization string          `json:"authorization"`
	Exec          json.RawMessage `json:"exec"`
}

// sealedCredential is one credential as it would be put at PathCredentials
// under its name, and the token that authorizes that.
type sealedCredential struct {
	Name          string          `json:"name"`
	Authorization string          `json:"authorization"`
	Put           json.RawMessage `json:"put"`
}

// sealedAnswer is what a sealed answer holds: what became of each part, or
// that what was sealed was no message.
type sealedAnswer struct {
	Error       string                `json:"error,omitempty"`
	Command     *sealedCommandOutcome `json:"command,omitempty"`
	Credentials []CredentialOutcome   `json:"credentials,omitempty"`
}

type sealedCommandOutcome struct {
	Result *ExecResponse `json:"result,omitempty"`
	Error  string        `json:"error,omitempty"`
}

// CredentialOutcome is what became of one sealed credential: SealedHeld, or
// why the guest did not take it.
type CredentialOutcome struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// What became of a part of a sealed message the guest opened, as its sealed
// answer says it.
const (
	// SealedHeld: the guest has the credential in place.
	SealedHeld = "held"
	// SealedUnauthorized: no key the bind grants the part's route signed it.
	SealedUnauthorized = "unauthorized"
	// SealedUndeclared: the bind does not say the credential comes from the
	// binder.
	SealedUndeclared = "undeclared"
	// SealedInvalid: the part is not what its route takes, or what was
	// sealed is no message.
	SealedInvalid = "invalid"
	// SealedFailed: the guest could not do it.
	SealedFailed = "failed"
)

func sealedInfoFor(bind *SignedBind) []byte {
	return append([]byte(sealedInfo), DocumentDigest(bind.Raw)...)
}

// answerAEAD derives the AEAD and the nonce an answer is sealed under from
// the secret both ends export, the message's encapsulated key and the random
// value the answer leads with.
func answerAEAD(secret, enc, nonce []byte) (cipher.AEAD, []byte, error) {
	salt := append(bytes.Clone(enc), nonce...)
	prk, err := hkdf.Extract(sha256.New, secret, salt)
	if err != nil {
		return nil, nil, err
	}
	key, err := hkdf.Expand(sha256.New, prk, "key", 32)
	if err != nil {
		return nil, nil, err
	}
	iv, err := hkdf.Expand(sha256.New, prk, "nonce", 12)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return aead, iv, nil
}

// SealedMessage is a binder's end of a message it sealed with a bind: what
// travels, and what opens the answer.
type SealedMessage struct {
	// Sealed is the message as it travels with the bind.
	Sealed []byte
	// Command is the first command as it was sealed, under the id the guest
	// runs it once under, or nil. A binder that has no sealed answer when it
	// needs one sends this over a connection of its own: the guest answers
	// with the first run's result if the command did run, and runs it
	// otherwise. It puts its credentials again the same way.
	Command *ExecRequest

	// credentials are the names of the credentials the message carries, in
	// its order.
	credentials []string
	enc         []byte
	secret      []byte
}

// SealWithBind seals parts for the guest that ready describes, to be sent
// with bind. ready is the caller's own verdict on the guest's evidence, made
// as one that lets a secret go (VerifyReadyToRelease): a message is sealed
// only once that check has passed, since the key it is sealed to is taken
// from that evidence, and only while the verdict stands. auth signs each part
// as it would for the part's route, with a key the bind grants that route.
func SealWithBind(ready *ReadyTD, bind *SignedBind, auth operatorauth.AudienceAuthorizer, parts SealedParts) (*SealedMessage, error) {
	if ready == nil || ready.OneTime == nil {
		return nil, errors.New("a message is sealed to a guest whose evidence was verified, and to the keys that evidence binds")
	}
	if !time.Now().Before(ready.Until) {
		return nil, ErrNotForRelease
	}
	if err := ready.OneTime.Validate(); err != nil {
		return nil, err
	}
	if err := bind.Doc.Targets(ready.InstanceKey); err != nil {
		return nil, err
	}
	if parts.Command == nil && len(parts.Credentials) == 0 {
		return nil, errors.New("a sealed message holds a command, credentials, or both")
	}
	if len(parts.Credentials) > maxCredentials {
		return nil, fmt.Errorf("a sealed message holds at most %d credentials", maxCredentials)
	}
	audience, err := InstanceKeyDigest(ready.InstanceKey)
	if err != nil {
		return nil, err
	}
	var plain sealedPlain
	out := &SealedMessage{}
	if parts.Command != nil {
		req := *parts.Command
		if req.ID == "" {
			var id [16]byte
			if _, err := rand.Read(id[:]); err != nil {
				return nil, fmt.Errorf("exec id: %w", err)
			}
			req.ID = hex.EncodeToString(id[:])
		}
		if err := req.Validate(); err != nil {
			return nil, err
		}
		exec, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		authorization, err := auth.AuthorizationFor(audience, "POST", PathExec, exec)
		if err != nil {
			return nil, err
		}
		plain.Command, out.Command = &sealedCommand{Authorization: authorization, Exec: exec}, &req
	}
	// In name order, so that one set of parts is one plaintext.
	names := make([]string, 0, len(parts.Credentials))
	for name := range parts.Credentials {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		value := parts.Credentials[name]
		declared, ok := bind.Doc.Policy.Credential(name)
		switch {
		case !ok || declared.Source != SourceBinder:
			return nil, fmt.Errorf("the bind does not say credential %q comes from its binder", name)
		case len(value) == 0 || len(value) > declared.Limit():
			return nil, fmt.Errorf("credential %q is %d bytes, and the bind takes 1 to %d", name, len(value), declared.Limit())
		}
		put, err := json.Marshal(CredentialRequest{Value: value})
		if err != nil {
			return nil, err
		}
		authorization, err := auth.AuthorizationFor(audience, "PUT", PathCredentials+name, put)
		if err != nil {
			return nil, err
		}
		plain.Credentials = append(plain.Credentials, sealedCredential{Name: name, Authorization: authorization, Put: put})
		out.credentials = append(out.credentials, name)
	}
	text, err := json.Marshal(plain)
	if err != nil {
		return nil, err
	}
	key, err := oneTimeKEM().NewPublicKey(ready.OneTime.KEM)
	if err != nil {
		return nil, err
	}
	kdf, aead := sealedSuite()
	enc, sender, err := hpke.NewSender(key, kdf, aead, sealedInfoFor(bind))
	if err != nil {
		return nil, err
	}
	ciphertext, err := sender.Seal(nil, text)
	if err != nil {
		return nil, err
	}
	if out.secret, err = sender.Export(sealedExport, 32); err != nil {
		return nil, err
	}
	out.enc, out.Sealed = enc, append(bytes.Clone(enc), ciphertext...)
	if len(out.Sealed) > MaxSealedBytes {
		return nil, fmt.Errorf("the sealed message is %d bytes, and one is at most %d", len(out.Sealed), MaxSealedBytes)
	}
	return out, nil
}

// SealedAnswer is what a guest answered a sealed message with, as its binder
// opened it.
type SealedAnswer struct {
	// Command is the first command's result, or nil: the message held none,
	// or the guest opened it and did not run it, and CommandError says why.
	Command      *ExecResponse
	CommandError string
	// Credentials is what became of each sealed credential, by name:
	// SealedHeld, or why the guest did not take it.
	Credentials map[string]string
}

// Open opens the guest's sealed answer. An answer that opens came from
// whoever opened the message: the guest that held the one-time KEM key it
// was sealed to.
func (m *SealedMessage) Open(answer []byte) (*SealedAnswer, error) {
	if len(answer) > MaxSealedAnswerBytes {
		return nil, refuse("the sealed answer is larger than one is")
	}
	if len(answer) < sealedNonce {
		return nil, refuse("the sealed answer is no sealed answer")
	}
	aead, iv, err := answerAEAD(m.secret, m.enc, answer[:sealedNonce])
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, iv, answer[sealedNonce:], nil)
	if err != nil {
		return nil, refuse("the sealed answer does not open: it is not the answer of the guest the message was sealed to")
	}
	var said sealedAnswer
	if err := decodeOne(plain, &said); err != nil {
		return nil, refuse("the sealed answer does not parse: %v", err)
	}
	if said.Error != "" {
		return nil, fmt.Errorf("the guest opened the sealed message and could not read it: %s", said.Error)
	}
	out := &SealedAnswer{Credentials: map[string]string{}}
	if m.Command != nil {
		// A result, or the one word of why there is none.
		if said.Command == nil || (said.Command.Result == nil) == (said.Command.Error == "") {
			return nil, refuse("the sealed answer does not say what became of the command")
		}
		out.Command, out.CommandError = said.Command.Result, said.Command.Error
	}
	// One word on each credential the message carried, and on no other.
	if len(said.Credentials) != len(m.credentials) {
		return nil, refuse("the sealed answer does not say what became of each credential")
	}
	for i, c := range said.Credentials {
		if c.Name != m.credentials[i] || c.Status == "" {
			return nil, refuse("the sealed answer does not say what became of credential %q", m.credentials[i])
		}
		out.Credentials[c.Name] = c.Status
	}
	return out, nil
}

// OpenedSealed is a guest's end of a sealed message it opened: its parts,
// each with the token it came with, and what seals the answer.
type OpenedSealed struct {
	// Command is the first command, or nil.
	Command *OpenedCommand
	// Credentials are the credentials the message carries.
	Credentials []OpenedCredential
	// Malformed says what was sealed is no message: it opened, since it was
	// sealed to this guest under this bind, and holds nothing to act on.
	Malformed bool

	enc    []byte
	secret []byte
}

// OpenedCommand is a sealed command: the exec request, as the bytes its
// token covers, and that token.
type OpenedCommand struct {
	Authorization string
	Exec          []byte
}

// OpenedCredential is a sealed credential: what would be put under Name, as
// the bytes its token covers, and that token.
type OpenedCredential struct {
	Name          string
	Authorization string
	Put           []byte
}

// OpenSealed opens a sealed message with the guest's one-time KEM key, under
// bind. A message sealed to another key, or for another bind, does not open.
// The caller erases key, and holds what this returns no longer than it takes
// to act on it and answer.
func OpenSealed(key hpke.PrivateKey, bind *SignedBind, sealed []byte) (*OpenedSealed, error) {
	text, secret, err := OpenSealedWithKey(key, SealedInfo(bind), sealed)
	if err != nil {
		return nil, err
	}
	return OpenedSealedOf(sealed, text, secret), nil
}

// SealedInfo is what a message sealed with bind is sealed under, beside the
// guest's key: the bind's digest, so that it opens under no other bind.
func SealedInfo(bind *SignedBind) []byte { return sealedInfoFor(bind) }

// OpenSealedWithKey is the part of opening a sealed message that takes the
// guest's one-time KEM key: it gives what was sealed, and the secret the
// answer is sealed under, which is exported from the opening and is no key
// to the message. Whoever holds the key does this and nothing else of
// opening, so that the key can live where nothing else of a bind is read. A
// message sealed to another key, or under other info, does not open.
func OpenSealedWithKey(key hpke.PrivateKey, info, sealed []byte) (text, secret []byte, err error) {
	if len(sealed) > MaxSealedBytes {
		return nil, nil, errors.New("the sealed message is larger than one is")
	}
	// The hybrid KEM's encapsulated key leads the sealed message.
	if len(sealed) <= encapsulationSize {
		return nil, nil, errors.New("the sealed message is no sealed message")
	}
	enc, ciphertext := sealed[:encapsulationSize], sealed[encapsulationSize:]
	kdf, aead := sealedSuite()
	recipient, err := hpke.NewRecipient(enc, key, kdf, aead, info)
	if err != nil {
		return nil, nil, errors.New("the sealed message does not open: it was sealed to another guest's key")
	}
	if text, err = recipient.Open(nil, ciphertext); err != nil {
		return nil, nil, errors.New("the sealed message does not open: it was sealed to another key, or for another bind")
	}
	if secret, err = recipient.Export(sealedExport, 32); err != nil {
		return nil, nil, err
	}
	return text, secret, nil
}

// RehearseOneTime does once, with keys it makes and throws away, what a
// guest's one-time keys do at its bind: a signature, and the opening of a
// sealed message. A bind is every guest's first, so whatever that work sets
// up on first use, every start would pay for. It touches no key of the
// guest's and leaves nothing a bind could find.
func RehearseOneTime() error {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	word := []byte("a rehearsal")
	if !ed25519.Verify(public, word, ed25519.Sign(private, word)) {
		return errors.New("a signature made in rehearsal does not verify")
	}
	key, err := oneTimeKEM().GenerateKey()
	if err != nil {
		return err
	}
	kdf, aead := sealedSuite()
	info := []byte(sealedInfo + "a rehearsal")
	enc, sender, err := hpke.NewSender(key.PublicKey(), kdf, aead, info)
	if err != nil {
		return err
	}
	ciphertext, err := sender.Seal(nil, word)
	if err != nil {
		return err
	}
	text, _, err := OpenSealedWithKey(key, info, append(enc, ciphertext...))
	if err != nil {
		return err
	}
	if !bytes.Equal(text, word) {
		return errors.New("a message sealed in rehearsal opened to something else")
	}
	return nil
}

// OpenedSealedOf is what a guest acts on of a sealed message that opened to
// text, with the secret its answer is sealed under. It takes text and secret
// for its own.
func OpenedSealedOf(sealed, text, secret []byte) *OpenedSealed {
	out := &OpenedSealed{enc: bytes.Clone(sealed[:min(len(sealed), encapsulationSize)]), secret: secret}
	var plain sealedPlain
	if err := decodeOne(text, &plain); err != nil || !plain.wellFormed() {
		// It opened, so its sender gets a sealed answer, which says that
		// what it sealed is no message.
		out.Malformed = true
		return out
	}
	if plain.Command != nil {
		out.Command = &OpenedCommand{Authorization: plain.Command.Authorization, Exec: plain.Command.Exec}
	}
	for _, c := range plain.Credentials {
		out.Credentials = append(out.Credentials, OpenedCredential{Name: c.Name, Authorization: c.Authorization, Put: c.Put})
	}
	return out
}

// decodeOne reads text as exactly one JSON document with no member out does
// not know.
func decodeOne(text []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("more than one document")
	}
	return nil
}

// encapsulationSize is the size of the hybrid KEM's encapsulated key: an
// ML-KEM-768 ciphertext and an X25519 public key.
const encapsulationSize = 1088 + 32

// SealedOutcome is what a guest did with an opened message, for its answer.
type SealedOutcome struct {
	// Command is the command's result, or nil with CommandError for one the
	// guest did not run. Both are empty for a message with no command.
	Command      *ExecResponse
	CommandError string
	// Credentials is what became of each credential, in the message's order.
	Credentials []CredentialOutcome
}

// Seal seals what the guest did with the message as the answer its sender
// opens.
func (o *OpenedSealed) Seal(outcome SealedOutcome) ([]byte, error) {
	if len(o.secret) == 0 {
		return nil, errors.New("the secret this message's answer is sealed under is forgotten")
	}
	answer := sealedAnswer{Credentials: outcome.Credentials}
	switch {
	case o.Malformed:
		answer = sealedAnswer{Error: SealedInvalid}
	case o.Command != nil:
		answer.Command = &sealedCommandOutcome{Result: outcome.Command, Error: outcome.CommandError}
	}
	plain, err := json.Marshal(answer)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, sealedNonce)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aead, iv, err := answerAEAD(o.secret, o.enc, nonce)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, iv, plain, nil), nil
}

// Forget erases the secret an answer is sealed under, and the credentials
// the message carried.
func (o *OpenedSealed) Forget() {
	clear(o.secret)
	o.secret = nil
	for i := range o.Credentials {
		clear(o.Credentials[i].Put)
	}
	o.Credentials = nil
}
