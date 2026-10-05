package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// A binder that sends a guest its bind itself may send the session's first
// command with it: one exec request, authorized by a key the bind grants and
// sealed to the one-time KEM key the guest's evidence bound while it was
// nobody's (OneTimeKeys). The guest keeps that key until its sandbox is about
// to run anything of the tenant, opens a command that came by then, and
// erases the key, so a command opens only in the guest it was sealed for and
// only while that guest takes its bind. The guest's host carries ciphertext
// both ways.
//
// The command is sealed with HPKE in base mode, under the bind's digest as
// the info, so it opens under that bind alone. Its answer comes back sealed
// under a key exported from the same context, as an Oblivious HTTP response
// is (RFC 9458): the binder needs no key of its own.

const (
	// firstCommandInfo starts the HPKE info of a first command: the bind's
	// digest follows.
	firstCommandInfo = "c8s-session first command/v1\x00"
	// firstCommandExport is the exporter context of the secret an answer is
	// sealed under.
	firstCommandExport = "c8s-session first command/v1 answer"
	// firstCommandNonce is the size of the random value an answer leads
	// with: the larger of the AEAD's key and nonce sizes.
	firstCommandNonce = 32
	// MaxFirstCommandBytes bounds a sealed first command, and
	// MaxFirstCommandAnswerBytes its sealed answer: an exec request and its
	// bounded result, and what sealing adds.
	MaxFirstCommandBytes       = 2 << 20
	MaxFirstCommandAnswerBytes = 4 << 20
)

func firstCommandSuite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.AES256GCM() }

// firstCommandPlain is what a sealed first command holds: the exec request as
// it would travel to PathExec, and the token that authorizes it there.
type firstCommandPlain struct {
	Authorization string          `json:"authorization"`
	Exec          json.RawMessage `json:"exec"`
}

// firstCommandAnswer is what a sealed answer holds: the command's result, or
// the one word of why it did not run.
type firstCommandAnswer struct {
	Result *ExecResponse `json:"result,omitempty"`
	Error  string        `json:"error,omitempty"`
}

// Why a first command that was opened did not run, as its sealed answer says
// it.
const (
	// FirstCommandUnauthorized: no key the bind grants signed the command.
	FirstCommandUnauthorized = "unauthorized"
	// FirstCommandInvalid: what was sealed is no exec request.
	FirstCommandInvalid = "invalid"
	// FirstCommandFailed: the guest could not run it.
	FirstCommandFailed = "failed"
)

// FirstCommandError is a first command the guest opened and did not run.
type FirstCommandError struct{ Reason string }

func (e *FirstCommandError) Error() string {
	return "the guest opened the first command and did not run it: " + e.Reason
}

func firstCommandInfoFor(bind *SignedBind) []byte {
	return append([]byte(firstCommandInfo), DocumentDigest(bind.Raw)...)
}

// answerAEAD derives the AEAD and the nonce an answer is sealed under from
// the secret both ends export, the command's encapsulated key and the random
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

// FirstCommand is a binder's end of a first command it sealed: what opens
// the answer.
type FirstCommand struct {
	// Sealed is the command as it travels with the bind.
	Sealed []byte
	// Request is the command as it was sealed, under the id the guest runs
	// it once under. A sender that is not told the guest took its command
	// sends this over a connection of its own: the guest answers with the
	// first run's result if the command did run, and runs it otherwise.
	Request ExecRequest

	enc    []byte
	secret []byte
}

// SealFirstCommand seals req for the guest that ready describes, to be sent
// with bind. ready is the caller's own verdict on the guest's evidence
// (VerifyReady): a command is sealed only once that check has passed, since
// the key it is sealed to is taken from that evidence. auth signs the
// request, as it would for PathExec, with a key the bind grants.
func SealFirstCommand(ready *ReadyTD, bind *SignedBind, auth operatorauth.AudienceAuthorizer, req ExecRequest) (*FirstCommand, error) {
	if ready == nil || ready.OneTime == nil {
		return nil, errors.New("a first command is sealed to a guest whose evidence was verified, and to the keys that evidence binds")
	}
	if err := ready.OneTime.Validate(); err != nil {
		return nil, err
	}
	if err := bind.Doc.Targets(ready.InstanceKey); err != nil {
		return nil, err
	}
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
	audience, err := InstanceKeyDigest(ready.InstanceKey)
	if err != nil {
		return nil, err
	}
	authorization, err := auth.AuthorizationFor(audience, "POST", PathExec, exec)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(firstCommandPlain{Authorization: authorization, Exec: exec})
	if err != nil {
		return nil, err
	}
	key, err := oneTimeKEM().NewPublicKey(ready.OneTime.KEM)
	if err != nil {
		return nil, err
	}
	kdf, aead := firstCommandSuite()
	enc, sender, err := hpke.NewSender(key, kdf, aead, firstCommandInfoFor(bind))
	if err != nil {
		return nil, err
	}
	ciphertext, err := sender.Seal(nil, plain)
	if err != nil {
		return nil, err
	}
	secret, err := sender.Export(firstCommandExport, 32)
	if err != nil {
		return nil, err
	}
	sealed := append(bytes.Clone(enc), ciphertext...)
	if len(sealed) > MaxFirstCommandBytes {
		return nil, fmt.Errorf("the sealed first command is %d bytes, and one is at most %d", len(sealed), MaxFirstCommandBytes)
	}
	return &FirstCommand{Sealed: sealed, Request: req, enc: enc, secret: secret}, nil
}

// Open opens the guest's sealed answer to the command. An answer that opens
// came from whoever opened the command: the guest that held the one-time KEM
// key the command was sealed to.
func (c *FirstCommand) Open(answer []byte) (*ExecResponse, error) {
	if len(answer) > MaxFirstCommandAnswerBytes {
		return nil, refuse("the first command's answer is larger than one is")
	}
	if len(answer) < firstCommandNonce {
		return nil, refuse("the first command's answer is no sealed answer")
	}
	aead, iv, err := answerAEAD(c.secret, c.enc, answer[:firstCommandNonce])
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, iv, answer[firstCommandNonce:], nil)
	if err != nil {
		return nil, refuse("the first command's answer does not open: it is not the answer of the guest the command was sealed to")
	}
	var out firstCommandAnswer
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, refuse("the first command's answer does not parse: %v", err)
	}
	switch {
	case out.Error != "":
		return nil, &FirstCommandError{Reason: out.Error}
	case out.Result == nil:
		return nil, refuse("the first command's answer holds no result")
	}
	return out.Result, nil
}

// OpenedFirstCommand is a guest's end of a first command it opened: the
// request, the token that came with it, and what seals the answer.
type OpenedFirstCommand struct {
	// Authorization is the token the command came with, and Exec the exec
	// request it authorizes, as the bytes the token covers. Exec is empty
	// when what was sealed is no command.
	Authorization string
	Exec          []byte

	enc    []byte
	secret []byte
}

// OpenFirstCommand opens a sealed first command with the guest's one-time
// KEM key, under bind. A command sealed to another key, or for another bind,
// does not open. The caller erases key, and holds what this returns no longer
// than it takes to answer.
func OpenFirstCommand(key hpke.PrivateKey, bind *SignedBind, sealed []byte) (*OpenedFirstCommand, error) {
	if len(sealed) > MaxFirstCommandBytes {
		return nil, errors.New("the sealed first command is larger than one is")
	}
	// The hybrid KEM's encapsulated key leads the sealed command.
	if len(sealed) <= encapsulationSize {
		return nil, errors.New("the sealed first command is no sealed command")
	}
	enc, ciphertext := sealed[:encapsulationSize], sealed[encapsulationSize:]
	kdf, aead := firstCommandSuite()
	recipient, err := hpke.NewRecipient(enc, key, kdf, aead, firstCommandInfoFor(bind))
	if err != nil {
		return nil, errors.New("the first command does not open: it was sealed to another guest's key")
	}
	plain, err := recipient.Open(nil, ciphertext)
	if err != nil {
		return nil, errors.New("the first command does not open: it was sealed to another key, or for another bind")
	}
	secret, err := recipient.Export(firstCommandExport, 32)
	if err != nil {
		return nil, err
	}
	var command firstCommandPlain
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&command); err != nil || len(command.Exec) == 0 {
		// It opened, so its sender gets a sealed answer, which says that
		// what it sealed is no command: Exec stays empty.
		return &OpenedFirstCommand{enc: bytes.Clone(enc), secret: secret}, nil
	}
	return &OpenedFirstCommand{Authorization: command.Authorization, Exec: command.Exec, enc: bytes.Clone(enc), secret: secret}, nil
}

// encapsulationSize is the size of the hybrid KEM's encapsulated key: an
// ML-KEM-768 ciphertext and an X25519 public key.
const encapsulationSize = 1088 + 32

// Seal seals the command's result as the answer its sender opens.
func (c *OpenedFirstCommand) Seal(result *ExecResponse) ([]byte, error) {
	return c.seal(firstCommandAnswer{Result: result})
}

// Refuse seals the one word of why the command did not run.
func (c *OpenedFirstCommand) Refuse(reason string) ([]byte, error) {
	return c.seal(firstCommandAnswer{Error: reason})
}

func (c *OpenedFirstCommand) seal(answer firstCommandAnswer) ([]byte, error) {
	if len(c.secret) == 0 {
		return nil, errors.New("the secret this command's answer is sealed under is forgotten")
	}
	plain, err := json.Marshal(answer)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, firstCommandNonce)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aead, iv, err := answerAEAD(c.secret, c.enc, nonce)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, iv, plain, nil), nil
}

// Forget erases the secret an answer is sealed under.
func (c *OpenedFirstCommand) Forget() {
	clear(c.secret)
	c.secret = nil
}
