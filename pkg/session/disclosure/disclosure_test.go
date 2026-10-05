package disclosure_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

var update = flag.Bool("update", false, "rewrite testdata/disclosure-schema.json from the definitions")

const digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func evidence() teetypes.AttestationEvidence {
	return teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{"quote":"AAAA"}`)}
}

func attestation() *session.AttestResponse {
	return &session.AttestResponse{
		Evidence: evidence(), Launch: []byte("launch"), Signature: "c2ln", Events: []string{digest, digest},
		Phase: session.PhaseRunning, Bind: []byte("bind"), BindSignature: "c2ln",
	}
}

// Every answer a guest gives a caller without a key, at its fullest, is one
// the schema lets it give, and the encoder changes none of it.
func TestEncodeTakesWhatAGuestSays(t *testing.T) {
	var steps []session.AdmissionStep
	for _, step := range disclosure.Steps {
		steps = append(steps, session.AdmissionStep{Name: string(step), Micros: 1500})
	}
	for name, tc := range map[string]struct {
		message string
		value   any
	}{
		"an unbound guest's state": {disclosure.MessageState, session.StateResponse{
			Phase: session.PhaseReady, InstanceKey: []byte("key"), Prepared: true,
			Launch: []byte("launch"), Signature: "c2ln", Events: []string{digest},
		}},
		"a bound guest's state": {disclosure.MessageState, session.StateResponse{
			Phase: session.PhaseRunning, InstanceKey: []byte("key"), Launch: []byte("launch"), Signature: "c2ln",
			Events: []string{digest, digest}, Bind: []byte("bind"), BindSignature: "c2ln",
		}},
		"a guest with no event yet": {disclosure.MessageState, session.StateResponse{
			Phase: session.PhaseReady, InstanceKey: []byte("key"), Launch: []byte("launch"), Signature: "c2ln", Events: []string{},
		}},
		"a bind's answer":   {disclosure.MessageBound, session.BindResponse{Phase: session.PhaseRunning, Admission: steps, Attestation: attestation()}},
		"a bind sent again": {disclosure.MessageBound, session.BindResponse{Phase: session.PhaseRunning, Replayed: true}},
		"a bind that came with a command": {disclosure.MessageBound, session.BindResponse{
			Phase: session.PhaseRunning, Command: session.CommandTaken, Admission: steps, Attestation: attestation(),
		}},
		"a command's sealed answer":    {disclosure.MessageCommand, session.CommandAnswer{Command: session.CommandTaken, Answer: []byte("ciphertext")}},
		"a command that came too late": {disclosure.MessageCommand, session.CommandAnswer{Command: session.CommandTooLate}},
		"the platform":                 {disclosure.MessagePlatform, session.CollateralPlatform{FMSPC: "00806f050000", CA: "platform"}},
	} {
		want, err := json.Marshal(tc.value)
		if err != nil {
			t.Fatal(err)
		}
		got, err := disclosure.Encode(tc.message, tc.value)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !bytes.Equal(bytes.TrimSuffix(got, []byte("\n")), want) {
			t.Errorf("%s: encoded %s, want %s", name, got, want)
		}
	}
	for _, code := range disclosure.Refusals {
		got, err := disclosure.Encode(disclosure.MessageRefusal, disclosure.Refusal{Error: code})
		if err != nil || string(got) != `{"error":"`+string(code)+`"}`+"\n" {
			t.Errorf("refusal %s: %s, %v", code, got, err)
		}
	}
}

// What the schema does not let a message say is not encoded, and the error
// repeats none of it.
func TestEncodeHoldsBackWhatTheSchemaDoesNotList(t *testing.T) {
	const secret = "tenant-secret-text"
	long := strings.Repeat("x", 300<<10)
	for name, tc := range map[string]struct {
		message string
		value   any
	}{
		"a refusal in words":         {disclosure.MessageRefusal, map[string]any{"error": "malformed", "message": secret}},
		"a code outside the list":    {disclosure.MessageRefusal, map[string]any{"error": secret}},
		"a code that is no text":     {disclosure.MessageRefusal, map[string]any{"error": 7}},
		"no code at all":             {disclosure.MessageRefusal, map[string]any{}},
		"a null code":                {disclosure.MessageRefusal, map[string]any{"error": nil}},
		"a list for a message":       {disclosure.MessageRefusal, []string{secret}},
		"a message of no schema":     {"log", map[string]any{"line": secret}},
		"a phase outside the list":   {disclosure.MessageBound, map[string]any{"phase": secret}},
		"a negative counter":         {disclosure.MessageStep, map[string]any{"name": "start", "us": -1}},
		"a counter beyond its bound": {disclosure.MessageStep, map[string]any{"name": "start", "us": 1 << 40}},
		"a counter with a fraction":  {disclosure.MessageStep, map[string]any{"name": "start", "us": 1.5}},
		"a counter as text":          {disclosure.MessageStep, map[string]any{"name": "start", "us": secret}},
		"a flag as text":             {disclosure.MessageBound, map[string]any{"phase": "running", "replayed": secret}},
		"a step outside the list": {disclosure.MessageBound, session.BindResponse{
			Phase: session.PhaseRunning, Admission: []session.AdmissionStep{{Name: secret, Micros: 1}},
		}},
		"a step that took too long": {disclosure.MessageBound, session.BindResponse{
			Phase: session.PhaseRunning, Admission: []session.AdmissionStep{{Name: "start", Micros: 1 << 40}},
		}},
		"a step with a member more": {disclosure.MessageBound, map[string]any{
			"phase": "running", "admission": []any{map[string]any{"name": "start", "us": 1, "detail": secret}},
		}},
		"more steps than the bound": {disclosure.MessageBound, session.BindResponse{
			Phase: session.PhaseRunning, Admission: make([]session.AdmissionStep, 17),
		}},
		"an event that is no digest": {disclosure.MessageState, session.StateResponse{
			Phase: session.PhaseReady, InstanceKey: []byte("key"), Launch: []byte("launch"), Signature: "c2ln", Events: []string{secret},
		}},
		"more events than the bound": {disclosure.MessageState, session.StateResponse{
			Phase: session.PhaseReady, InstanceKey: []byte("key"), Launch: []byte("launch"), Signature: "c2ln", Events: make([]string, 9),
		}},
		"a document beyond its bound": {disclosure.MessageState, session.StateResponse{
			Phase: session.PhaseReady, InstanceKey: []byte("key"), Launch: []byte(long), Signature: "c2ln", Events: []string{},
		}},
		"a signature beyond its bound": {disclosure.MessageState, session.StateResponse{
			Phase: session.PhaseReady, InstanceKey: []byte("key"), Launch: []byte("launch"), Signature: long, Events: []string{},
		}},
		"a state with a member more": {disclosure.MessageState, map[string]any{
			"phase": "ready", "instance_key": "a2V5", "launch": "bGF1bmNo", "signature": "c2ln", "events": []string{}, "hostname": secret,
		}},
		"evidence under no platform": {disclosure.MessageAttestation, map[string]any{
			"evidence": map[string]any{"evidence": map[string]any{}}, "phase": "running", "launch": "bGF1bmNo", "signature": "c2ln", "events": []string{},
		}},
		"evidence under another platform's tag": {disclosure.MessageAttestation, map[string]any{
			"evidence": map[string]any{"platform": secret, "evidence": map[string]any{}}, "phase": "running", "launch": "bGF1bmNo", "signature": "c2ln", "events": []string{},
		}},
		"evidence with a member more": {disclosure.MessageAttestation, map[string]any{
			"evidence": map[string]any{"platform": "tdx", "evidence": map[string]any{}, "note": secret}, "phase": "running", "launch": "bGF1bmNo", "signature": "c2ln", "events": []string{},
		}},
		"evidence beyond its bound": {disclosure.MessageAttestation, map[string]any{
			"evidence": map[string]any{"platform": "tdx", "evidence": map[string]any{"quote": long}}, "phase": "running", "launch": "bGF1bmNo", "signature": "c2ln", "events": []string{},
		}},
		"a platform CA outside the list":  {disclosure.MessagePlatform, session.CollateralPlatform{FMSPC: "00806f050000", CA: secret}},
		"a command's fate in words":       {disclosure.MessageCommand, map[string]any{"command": secret}},
		"a command's answer in the clear": {disclosure.MessageCommand, map[string]any{"command": "taken", "answer": secret + " !"}},
		"a command's answer with its result beside it": {disclosure.MessageCommand, map[string]any{
			"command": "taken", "answer": "AAAA", "stdout": secret,
		}},
		"a command's answer beyond its bound": {disclosure.MessageCommand, session.CommandAnswer{
			Command: session.CommandTaken, Answer: make([]byte, 4<<20+1),
		}},
		"a command's fate in a bind's answer, in words": {disclosure.MessageBound, map[string]any{"phase": "running", "command": secret}},
		"a value that does not render":                  {disclosure.MessageRefusal, map[string]any{"error": make(chan int)}},
	} {
		got, err := disclosure.Encode(tc.message, tc.value)
		if err == nil {
			t.Errorf("%s: encoded %s", name, got)
			continue
		}
		if got != nil {
			t.Errorf("%s: an error came with %d bytes", name, len(got))
		}
		if strings.Contains(err.Error(), secret) || len(err.Error()) > 200 {
			t.Errorf("%s: the error repeats the value: %v", name, err)
		}
	}
}

// The published schema lists every message, every refusal has its words, and
// two builds of the same definitions publish the same bytes.
func TestSchemaDocument(t *testing.T) {
	doc := disclosure.Document()
	if !bytes.Equal(doc, disclosure.Document()) {
		t.Fatal("the schema document differs between two renderings")
	}
	// The published schema is a file in the repository, so a change to what
	// a guest may say shows up as a change to that file.
	const path = "testdata/disclosure-schema.json"
	if *update {
		if err := os.WriteFile(path, doc, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	published, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(doc, published) {
		t.Fatalf("the disclosure schema is not %s: run go test ./pkg/session/disclosure -run TestSchemaDocument -update, and review what a guest may now say", path)
	}
	var parsed struct {
		SchemaVersion string
		Messages      []disclosure.Message
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.SchemaVersion != disclosure.SchemaVersion || len(parsed.Messages) != len(disclosure.Schema) {
		t.Fatalf("schema %q with %d messages", parsed.SchemaVersion, len(parsed.Messages))
	}
	seen := map[string]bool{}
	for _, msg := range parsed.Messages {
		if seen[msg.Name] || msg.Says == "" || len(msg.Fields) == 0 {
			t.Errorf("message %q: listed twice, or says nothing", msg.Name)
		}
		seen[msg.Name] = true
		for _, field := range msg.Fields {
			checkField(t, msg.Name, &field, parsed.Messages)
		}
	}
	codes := map[disclosure.Code]bool{}
	for _, code := range disclosure.Refusals {
		if codes[code] {
			t.Errorf("refusal %q is listed twice", code)
		}
		codes[code] = true
		if strings.HasPrefix(disclosure.Describe(string(code)), "refused: ") {
			t.Errorf("refusal %q has no words", code)
		}
	}
	if got := disclosure.Describe("no_such_code"); got != "refused: no_such_code" {
		t.Errorf("an unknown code reads %q", got)
	}
}

// checkField holds one field of the schema to its kind: a kind the encoder
// knows, with the bound or the list that kind needs.
func checkField(t *testing.T, message string, field *disclosure.Field, messages []disclosure.Message) {
	t.Helper()
	at := message + "." + field.Name
	switch field.Kind {
	case disclosure.KindCode:
		if len(field.Codes) == 0 {
			t.Errorf("%s: a code with no list", at)
		}
	case disclosure.KindFlag, disclosure.KindDigest:
	case disclosure.KindCounter, disclosure.KindPublic, disclosure.KindSealed:
		if field.Max <= 0 {
			t.Errorf("%s: no bound", at)
		}
	case disclosure.KindEvidence:
		if field.Max <= 0 || len(field.Codes) == 0 {
			t.Errorf("%s: evidence with no bound or no platform", at)
		}
	case disclosure.KindList:
		if field.Max <= 0 || field.Item == nil {
			t.Errorf("%s: a list with no bound or no item", at)
			return
		}
		checkField(t, at, field.Item, messages)
	case disclosure.KindMessage:
		found := false
		for _, msg := range messages {
			found = found || msg.Name == field.Message
		}
		if !found {
			t.Errorf("%s: holds message %q, which the schema lacks", at, field.Message)
		}
	default:
		t.Errorf("%s: kind %q", at, field.Kind)
	}
}
