// Package disclosure is everything a session guest says in plaintext to a
// caller it has not authenticated: its host, the daemon, anyone
// (docs/session-disclosure.md). The schema lists each message and bounds
// every field of it to a code from a list, a flag, a counter, a digest, or a
// public document. No field holds text a session can choose, so a refusal is
// a code.
//
// One encoder writes them all, and it is driven by the schema: a value with a
// member the schema does not list, or one beyond its bound, is not encoded.
// The schema is the same definitions rendered as a document, which the image
// build puts on the verity root and publishes with the image's reference
// values.
package disclosure

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
)

// SchemaVersion names the schema document's format.
const SchemaVersion = "c8s-disclosure/v1"

// Code is a value from a list the schema fixes.
type Code string

// Why a guest will not do what a caller without a key asked. Each stands for
// a reason the caller could tell from its own request, or for the guest's
// state, and for nothing of a session's content.
const (
	// Busy: the guest has no place for the request now. Try again.
	Busy Code = "busy"
	// TooLarge: the request's body is larger than the route takes.
	TooLarge Code = "too_large"
	// Malformed: the request is not what the route takes.
	Malformed Code = "malformed"
	// Unauthorized: the route needs a token of a key the bind grants.
	Unauthorized Code = "unauthorized"
	// NotFound: the guest serves no such route.
	NotFound Code = "not_found"
	// MethodNotAllowed: the guest serves the route by another method.
	MethodNotAllowed Code = "method_not_allowed"
	// Fenced: the connection was opened before the guest's bind arrived.
	Fenced Code = "fenced"
	// NotReady: the guest takes no bind yet. Its key service has not judged
	// it. Try again.
	NotReady Code = "not_ready"
	// AlreadyBound: the guest is bound by another bind.
	AlreadyBound Code = "already_bound"
	// Retired: the guest takes no bind any more and is ending.
	Retired Code = "retired"
	// BindTooLate: the guest waited longer for a bind than its launch
	// document allows.
	BindTooLate Code = "bind_too_late"
	// BindClock: the guest's kernel left the clock its age limit is counted on.
	BindClock Code = "bind_clock"
	// BindInvalid: the bind is not a document this agent's bind schema takes.
	BindInvalid Code = "bind_invalid"
	// BindSignature: the bind is not signed by the authority it names.
	BindSignature Code = "bind_signature"
	// BindOtherGuest: the bind names another guest's instance key.
	BindOtherGuest Code = "bind_other_guest"
	// BindExpired: the bind is past its time.
	BindExpired Code = "bind_expired"
	// BindNoSandbox: the bind names no sandbox image, and this image runs a
	// session's code nowhere else.
	BindNoSandbox Code = "bind_no_sandbox"
	// BindKeyService: the bind trusts a key service the guest's launch
	// document does not pin.
	BindKeyService Code = "bind_key_service"
	// BindNoMember: the guest's session with its key service is with a
	// replica the bind does not name, and it reached none the bind names.
	BindNoMember Code = "bind_no_member"
	// BindNoMachine: the guest's launch document lists no machine the guest
	// may be, and the guest takes no bind under such a document.
	BindNoMachine Code = "bind_no_machine"
	// BindIncomplete: another request is still completing the bind.
	BindIncomplete Code = "bind_incomplete"
	// BindFailed: the guest took the bind and could not act on it. It is
	// ending.
	BindFailed Code = "bind_failed"
	// NoCollateral: the guest's host has handed it none of the vendor's
	// documents.
	NoCollateral Code = "no_collateral"
	// Internal: the guest could not answer.
	Internal Code = "internal"
)

// Refusals lists every refusal code, in the order the schema prints them.
var Refusals = []Code{
	Busy, TooLarge, Malformed, Unauthorized, NotFound, MethodNotAllowed, Fenced, NotReady, AlreadyBound, Retired,
	BindTooLate, BindClock, BindInvalid, BindSignature, BindOtherGuest, BindExpired,
	BindNoSandbox, BindKeyService, BindNoMember, BindNoMachine, BindIncomplete, BindFailed, NoCollateral, Internal,
}

// describe says each code in words, for whoever reads a refusal. The words
// never leave a guest: a client prints them.
var describe = map[Code]string{
	Busy:             "the guest has no place for the request right now",
	TooLarge:         "the request is larger than the guest takes",
	Malformed:        "the request is not what the guest takes there",
	Unauthorized:     "the request carries no token of a key the guest's bind grants",
	NotFound:         "the guest serves no such route",
	MethodNotAllowed: "the guest serves that route by another method",
	Fenced:           "the connection was opened before the guest's bind arrived, and the guest takes no bind from it",
	NotReady:         "the guest takes no bind yet: its key service has not judged it",
	AlreadyBound:     "the guest is already bound by another bind",
	Retired:          "the guest takes no bind any more and is shutting down",
	BindTooLate:      "the guest waited for a bind longer than its launch document allows",
	BindClock:        "the guest's kernel left the clock its age limit is counted on",
	BindInvalid:      "the bind is not a document this guest's bind schema takes",
	BindSignature:    "the bind is not signed by the authority it names",
	BindOtherGuest:   "the bind names another guest's instance key",
	BindExpired:      "the bind is past its time",
	BindNoSandbox:    "the bind names no sandbox image, and this guest runs a session's code inside one only",
	BindKeyService:   "the bind trusts a key service that the guest's launch document does not pin",
	BindNoMember:     "the guest reached no replica of its key service that the bind names",
	BindNoMachine:    "the guest's launch document lists no machine the guest may be, so the guest takes no bind",
	BindIncomplete:   "the bind is not complete yet",
	BindFailed:       "the guest took the bind, could not act on it, and is shutting down",
	NoCollateral:     "the guest's host has handed it none of the vendor's documents",
	Internal:         "the guest could not answer",
}

// Describe says a refusal code in words. A code this build does not know is
// printed as it came.
func Describe(code string) string {
	if text, ok := describe[Code(code)]; ok {
		return text
	}
	return "refused: " + code
}

// Kind is what a field may hold.
type Kind string

const (
	// KindCode is one of the field's Codes.
	KindCode Kind = "code"
	// KindFlag is true or false.
	KindFlag Kind = "flag"
	// KindCounter is a whole number from 0 to the field's Max.
	KindCounter Kind = "counter"
	// KindDigest is sha256:<64 lowercase hex>.
	KindDigest Kind = "digest"
	// KindPublic is a public document, key or signature of up to Max bytes:
	// one every verifier is handed anyway, or one the host itself handed in.
	KindPublic Kind = "public"
	// KindEvidence is the platform's evidence under one of the field's
	// platform tags, of up to Max bytes as rendered: public by design.
	KindEvidence Kind = "evidence"
	// KindSealed is up to Max bytes sealed to a key their reader holds and
	// the guest's host does not: the host learns their size and when they
	// came.
	KindSealed Kind = "sealed"
	// KindList is up to Max items, each as Item says.
	KindList Kind = "list"
	// KindMessage is another message of the schema, named by Message.
	KindMessage Kind = "message"
)

// Field is one member of a message.
type Field struct {
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
	// Codes lists the values of a KindCode field, and the platform tags of a
	// KindEvidence field.
	Codes []Code `json:"codes,omitempty"`
	// Max bounds a counter's value, a public document's or evidence's bytes,
	// and a list's items.
	Max int64 `json:"max,omitempty"`
	// Item is what a list holds.
	Item *Field `json:"item,omitempty"`
	// Message names the message a KindMessage field holds.
	Message string `json:"message,omitempty"`
	// Optional fields may be absent.
	Optional bool `json:"optional,omitempty"`
}

// Message is one thing a guest says.
type Message struct {
	Name string `json:"name"`
	// Says is when the guest says it, for whoever reads the schema.
	Says   string  `json:"says"`
	Fields []Field `json:"fields"`
}

// Names of the messages.
const (
	MessageState       = "state"
	MessageBound       = "bound"
	MessageAttestation = "attestation"
	MessageReceipt     = "receipt"
	MessageSealed      = "sealed"
	MessageStep        = "step"
	MessageRefusal     = "refusal"
	MessagePlatform    = "platform"
)

// The steps of admitting a sandbox, which a guest's answer to a bind times.
// The agent says what each one covers where it takes the time.
const (
	StepRegistryWait Code = "registry_wait"
	StepResolve      Code = "resolve"
	StepFetch        Code = "fetch"
	StepStore        Code = "store"
	StepPrestaged    Code = "prestaged"
	StepUnpack       Code = "unpack"
	StepOwn          Code = "own"
	StepClear        Code = "clear"
	StepChecks       Code = "checks"
	StepMeasure      Code = "measure"
	StepCredentials  Code = "credentials"
	StepStart        Code = "start"
)

// Steps lists every admission step, in the order they happen.
var Steps = []Code{
	StepRegistryWait, StepResolve, StepFetch, StepStore, StepPrestaged, StepUnpack, StepOwn, StepClear,
	StepChecks, StepMeasure, StepCredentials, StepStart,
}

// Where the quote a bound guest takes over its bind's nonce stands: still
// being tried, taken, or given up after the guest's last attempt at it.
const (
	QuoteTrying  Code = "trying"
	QuoteTaken   Code = "taken"
	QuoteGivenUp Code = "given_up"
)

// What became of a message sealed with a bind, or sent after it.
const (
	SealedTaken    Code = "taken"
	SealedUnopened Code = "unopened"
	SealedTooLate  Code = "too_late"
)

var (
	sealings   = []Code{SealedTaken, SealedUnopened, SealedTooLate}
	bindQuotes = []Code{QuoteTrying, QuoteTaken, QuoteGivenUp}
	phases     = []Code{"ready", "bound", "running"}
	// platforms are the tags a guest's evidence comes under.
	platforms = []Code{"tdx", "snp"}
)

// Bounds of the public documents a guest hands on.
const (
	maxKey       = 1024
	maxDocument  = 64 << 10
	maxBind      = 256 << 10
	maxSignature = 4096
	maxEvidence  = 256 << 10
	maxReceipt   = 8 << 10
	// The sealed answer to a sealed message: an exec result, a word on each
	// credential, and what sealing adds.
	maxSealedAnswer = 4 << 20
	// A certificate with a quote and the guest's one-time keys in it.
	maxCertificate = 32 << 10
	maxEvents      = 8
	// An admission step takes an hour at most, in microseconds.
	maxMicros = 3600 * 1000 * 1000
)

// measured are the documents a guest measured and its events, which a state
// and an attestation both carry.
func measured() []Field {
	return []Field{
		{Name: "phase", Kind: KindCode, Codes: phases},
		{Name: "launch", Kind: KindPublic, Max: maxDocument},
		{Name: "signature", Kind: KindPublic, Max: maxSignature},
		{Name: "events", Kind: KindList, Max: maxEvents, Item: &Field{Kind: KindDigest}},
		{Name: "bind", Kind: KindPublic, Max: maxBind, Optional: true},
		{Name: "bind_signature", Kind: KindPublic, Max: maxSignature, Optional: true},
	}
}

// Schema is every message of this build's guests, and the bounds of each
// field. Health is the three bytes "ok\n", and what a host handed in over its
// own channel is handed back as it came: neither is the guest's word. A
// request that is no well-formed HTTP is answered by the HTTP library before
// the agent sees it, with a status and a fixed text of the library's own.
var Schema = []Message{
	{Name: MessageState, Says: "to anyone who asks what the guest is", Fields: append(append([]Field{
		{Name: "instance_key", Kind: KindPublic, Max: maxKey},
		{Name: "prepared", Kind: KindFlag, Optional: true},
	}, measured()...),
		Field{Name: "ready_certificate", Kind: KindPublic, Max: maxCertificate, Optional: true},
		Field{Name: "bind_quote", Kind: KindCode, Codes: bindQuotes, Optional: true},
		Field{Name: "attestation", Kind: KindMessage, Message: MessageAttestation, Optional: true})},
	{Name: MessageBound, Says: "to whoever handed it its bind", Fields: []Field{
		{Name: "phase", Kind: KindCode, Codes: phases},
		{Name: "replayed", Kind: KindFlag, Optional: true},
		{Name: "sealed", Kind: KindCode, Codes: sealings, Optional: true},
		{Name: "admission", Kind: KindList, Max: 16, Optional: true, Item: &Field{Kind: KindMessage, Message: MessageStep}},
		{Name: "receipt", Kind: KindMessage, Message: MessageReceipt, Optional: true},
		{Name: "attestation", Kind: KindMessage, Message: MessageAttestation, Optional: true},
	}},
	{Name: MessageSealed, Says: "after its answer to a bind that came with a sealed message, and to one sent just after: whether it took the message, and its answer sealed to the message's sender", Fields: []Field{
		{Name: "sealed", Kind: KindCode, Codes: sealings},
		{Name: "answer", Kind: KindSealed, Max: maxSealedAnswer, Optional: true},
	}},
	{Name: MessageReceipt, Says: "with its answer to a bind: its own word on the bind, signed by its one-time key over the bind's nonce", Fields: []Field{
		{Name: "receipt", Kind: KindPublic, Max: maxReceipt},
		{Name: "signature", Kind: KindPublic, Max: maxSignature},
	}},
	{Name: MessageAttestation, Says: "with its answer to a bind, and with its state from then on: evidence over the bind's nonce", Fields: append([]Field{
		{Name: "evidence", Kind: KindEvidence, Codes: platforms, Max: maxEvidence},
	}, measured()...)},
	{Name: MessageStep, Says: "in its answer to a bind: one step of admitting the sandbox, and how long it took", Fields: []Field{
		{Name: "name", Kind: KindCode, Codes: Steps},
		{Name: "us", Kind: KindCounter, Max: maxMicros},
	}},
	{Name: MessageRefusal, Says: "to a caller without a key whose request it will not serve", Fields: []Field{
		{Name: "error", Kind: KindCode, Codes: Refusals},
	}},
	{Name: MessagePlatform, Says: "to its host, which fetches the vendor's documents for that platform", Fields: []Field{
		{Name: "fmspc", Kind: KindPublic, Max: 12},
		{Name: "ca", Kind: KindCode, Codes: []Code{"platform", "processor"}},
	}},
}

// Document is the schema as it is published and as it sits on an image's
// verity root.
func Document() []byte {
	doc, err := json.MarshalIndent(struct {
		SchemaVersion string    `json:"schemaVersion"`
		Messages      []Message `json:"messages"`
	}{SchemaVersion, Schema}, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(doc, '\n')
}

func message(name string) (*Message, error) {
	for i := range Schema {
		if Schema[i].Name == name {
			return &Schema[i], nil
		}
	}
	return nil, fmt.Errorf("the schema has no message %q", name)
}

// Encode renders v as the message named name. It fails if v says anything
// the schema does not let that message say: a member the message does not
// list, a code outside its list, a number or a document beyond its bound.
// Nothing of v is in the error.
func Encode(name string, v any) ([]byte, error) {
	msg, err := message(name)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, errors.New("the value does not render")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, errors.New("the value does not render")
	}
	if err := checkMessage(msg, tree); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return append(raw, '\n'), nil
}

func checkMessage(msg *Message, tree any) error {
	members, ok := tree.(map[string]any)
	if !ok {
		return errors.New("not an object")
	}
	for name := range members {
		if !slices.ContainsFunc(msg.Fields, func(f Field) bool { return f.Name == name }) {
			return fmt.Errorf("member %q is not in the schema", name)
		}
	}
	for i := range msg.Fields {
		field := &msg.Fields[i]
		value, present := members[field.Name]
		if !present || value == nil {
			if !field.Optional {
				return fmt.Errorf("member %q is missing", field.Name)
			}
			continue
		}
		if err := checkField(field, value); err != nil {
			return fmt.Errorf("member %q: %w", field.Name, err)
		}
	}
	return nil
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func checkField(field *Field, value any) error {
	switch field.Kind {
	case KindCode:
		text, ok := value.(string)
		if !ok || !slices.Contains(field.Codes, Code(text)) {
			return errors.New("not a code of the list")
		}
	case KindFlag:
		if _, ok := value.(bool); !ok {
			return errors.New("not a flag")
		}
	case KindCounter:
		number, ok := value.(json.Number)
		if !ok {
			return errors.New("not a counter")
		}
		n, err := number.Int64()
		if err != nil || n < 0 || n > field.Max {
			return errors.New("a counter beyond its bound")
		}
	case KindDigest:
		text, ok := value.(string)
		if !ok || !digestRE.MatchString(text) {
			return errors.New("not a digest")
		}
	case KindPublic:
		text, ok := value.(string)
		if !ok {
			return errors.New("not a document")
		}
		// A document travels as base64 of its bytes, a signature or a key in
		// PEM as its own text: either way the bound is on what it decodes to
		// at most.
		size := int64(len(text))
		if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
			size = int64(len(decoded))
		}
		if size > field.Max {
			return errors.New("a document beyond its bound")
		}
	case KindSealed:
		// Ciphertext travels as base64 of its bytes, and is nothing else.
		text, ok := value.(string)
		if !ok {
			return errors.New("not sealed bytes")
		}
		sealed, err := base64.StdEncoding.DecodeString(text)
		if err != nil || int64(len(sealed)) > field.Max {
			return errors.New("sealed bytes beyond their bound")
		}
	case KindEvidence:
		// The envelope the verifiers take: a platform tag and that
		// platform's own statement, which is theirs to read.
		envelope, ok := value.(map[string]any)
		if !ok || len(envelope) != 2 {
			return errors.New("not evidence")
		}
		platform, tagged := envelope["platform"].(string)
		if _, stated := envelope["evidence"].(map[string]any); !tagged || !stated || !slices.Contains(field.Codes, Code(platform)) {
			return errors.New("not evidence")
		}
		raw, err := json.Marshal(value)
		if err != nil || int64(len(raw)) > field.Max {
			return errors.New("evidence beyond its bound")
		}
	case KindList:
		items, ok := value.([]any)
		if !ok || int64(len(items)) > field.Max {
			return errors.New("a list beyond its bound")
		}
		for _, item := range items {
			if err := checkField(field.Item, item); err != nil {
				return err
			}
		}
	case KindMessage:
		msg, err := message(field.Message)
		if err != nil {
			return err
		}
		return checkMessage(msg, value)
	default:
		return fmt.Errorf("kind %q is not one the encoder knows", field.Kind)
	}
	return nil
}

// Refusal is the one thing a guest says when it will not serve a caller
// without a key.
type Refusal struct {
	Error Code `json:"error"`
}
