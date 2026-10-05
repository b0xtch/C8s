package session_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/sessiontest"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/sessionsim"
)

// vendorDocuments is what an engine says of the vendor's documents under its
// verdicts: when the oldest was fetched, and what asking for newer ones did.
type vendorDocuments struct {
	mu      sync.Mutex
	fetched time.Time
	// judged counts the verdicts made, and renewed the requests to fetch
	// anew. down is what such a request fails with. With it unset, a request
	// fetches at now.
	judged, renewed int
	down            error
	now             func() time.Time
}

func (d *vendorDocuments) engine() session.Engine {
	return sessionsim.EngineWithDocuments(func() time.Time {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.judged++
		return d.fetched
	}, func(context.Context) error {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.renewed++
		if d.down == nil {
			d.fetched = d.now()
		}
		return d.down
	})
}

func (d *vendorDocuments) counts() (judged, renewed int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.judged, d.renewed
}

func (d *vendorDocuments) set(change func(*vendorDocuments)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	change(d)
}

// A client's verdict on its guest stands for an hour from when the client
// fetched the oldest of the vendor's documents under it, however lately it
// judged. Past that nothing is sent, and that says nothing of the guest:
// with the documents fetched anew, the next command goes.
func TestNothingIsSentOnDocumentsPastTheirHour(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	documents := &vendorDocuments{}
	client, now := clientFor(t, "https://"+s.addr, s, documents.engine())
	documents.set(func(d *vendorDocuments) { d.now, d.fetched = now.Now, now.Now().Add(-20*time.Minute) })

	if _, err := client.Attest(within(t)); err != nil {
		t.Fatal(err)
	}
	// Forty minutes are left of the documents' hour.
	now.advance(40*time.Minute - time.Second)
	client.Close()
	run(t, client)
	now.advance(time.Second)
	client.Close()
	resp, err := client.Exec(within(t), session.ExecRequest{Argv: []string{"true"}})
	if !errors.Is(err, session.ErrStaleDocuments) || isVerdict(err) || resp != nil {
		t.Fatalf("a command on documents an hour old: %+v, %v", resp, err)
	}
	if _, err := client.PutCredential(within(t), "api-token", []byte("s3cr3t")); !errors.Is(err, session.ErrStaleDocuments) {
		t.Fatalf("a credential on documents an hour old: %v", err)
	}
	documents.set(func(d *vendorDocuments) { d.fetched = now.Now() })
	run(t, client)
}

// A client that holds its guest between commands fetches the vendor's
// documents anew within five minutes of its verdict's end and judges the
// guest's certificate on them, so that no command waits for the vendor. A
// fetch that fails leaves the verdict to end at its time.
func TestRenewKeepsTheVerdictStandingBetweenCommands(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	documents := &vendorDocuments{}
	client, now := clientFor(t, "https://"+s.addr, s, documents.engine())
	documents.set(func(d *vendorDocuments) { d.now, d.fetched = now.Now, now.Now() })
	if _, err := client.Attest(within(t)); err != nil {
		t.Fatal(err)
	}

	// Earlier than that it asks nobody for anything.
	now.advance(session.ServingVerdictTTL - session.RenewAhead - time.Second)
	if err := client.Renew(within(t)); err != nil {
		t.Fatal(err)
	}
	if _, renewed := documents.counts(); renewed != 0 {
		t.Fatalf("a renewal more than five minutes before the verdict's end had the documents fetched %d times", renewed)
	}
	now.advance(time.Second)
	judged, _ := documents.counts()
	if err := client.Renew(within(t)); err != nil {
		t.Fatal(err)
	}
	if after, renewed := documents.counts(); renewed != 1 || after != judged+1 {
		t.Fatalf("a renewal five minutes before the verdict's end: the documents fetched %d times, the guest judged %d times", renewed, after-judged)
	}
	// Past the first verdict's hour a command goes, and judges nothing.
	now.advance(30 * time.Minute)
	judged, _ = documents.counts()
	client.Close()
	run(t, client)
	if after, _ := documents.counts(); after != judged {
		t.Fatalf("a command on a renewed verdict judged the guest %d times", after-judged)
	}

	// The vendor cannot be asked: the renewal says so, and the verdict ends
	// at its time.
	documents.set(func(d *vendorDocuments) { d.down = errors.New("no route to the vendor") })
	now.advance(session.ServingVerdictTTL - 30*time.Minute - time.Minute)
	if err := client.Renew(within(t)); err == nil {
		t.Fatal("a renewal with the vendor out of reach succeeded")
	}
	client.Close()
	run(t, client)
	now.advance(time.Minute)
	client.Close()
	if _, err := client.Exec(within(t), session.ExecRequest{Argv: []string{"true"}}); !errors.Is(err, session.ErrStaleDocuments) {
		t.Fatalf("a command past the verdict's end, the vendor out of reach: %v", err)
	}
}

// A judgment that rests on a document somebody handed over pins no guest:
// what follows a pin is sent on the vendor's documents as the client fetched
// them, and an engine that says otherwise is not taken at its word.
func TestGuestIsNotPinnedOnHandedOverDocuments(t *testing.T) {
	s := serve(t, sessiontest.NewTD(), nil)
	finding := &session.CollateralFinding{Stapled: true, Fetched: time.Now(), Expires: time.Now().Add(time.Hour)}
	client, _ := clientFor(t, "https://"+s.addr, s, resting{sessiontest.Engine{}, finding})
	att, err := client.Attest(within(t))
	if err == nil || isVerdict(err) || att != nil || client.Pinned() {
		t.Fatalf("an attestation on handed-over documents: %+v, %v, pinned %t", att, err, client.Pinned())
	}
	if _, err := client.Exec(within(t), session.ExecRequest{Argv: []string{"true"}}); err == nil {
		t.Fatal("a command went to a guest that no judgment pinned")
	}
}
