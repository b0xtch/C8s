package session_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// The rehearsal meets every document type and returns: an empty document
// that a type refuses is no failure of it, and it leaves a bind decoded
// after it as it was before.
func TestRehearsalOfDocumentsLeavesThemAsTheyWere(t *testing.T) {
	g := newSealedGuest(t)
	before, err := session.ParseBind(g.bind.Raw)
	if err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	session.RehearseDocuments(&struct {
		When  time.Time
		Inner *struct{ Names map[string][]int }
	}{})
	first := time.Since(began)
	began = time.Now()
	session.RehearseDocuments()
	if again := time.Since(began); again > first && again > 50*time.Millisecond {
		t.Errorf("a second rehearsal took %s, and the first %s", again, first)
	}
	after, err := session.ParseBind(g.bind.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("a bind reads differently after the rehearsal")
	}
	if err := session.RehearseOneTime(); err != nil {
		t.Fatalf("the rehearsal of the one-time keys' work: %v", err)
	}
}
