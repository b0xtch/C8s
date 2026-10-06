package sessiond

import (
	"encoding/json"
	"testing"
	"time"
)

// A snapshot of a record is its own copy: what the daemon changes in the
// record afterwards, under its lock, is not in a snapshot that is being
// written without it.
func TestSnapshotIsItsOwnCopy(t *testing.T) {
	td := &td{rec: record{
		ID: "td-1", State: StateBound,
		Claim:    &claim{RequestID: "claim-1", Session: "s1"},
		Bind:     &bound{RequestID: "bind-1", Digest: "d1"},
		Released: []released{{Claim: "claim-0", Session: "s0"}},
	}}
	first := td.snapshot()
	before, err := json.Marshal(&first.rec)
	if err != nil {
		t.Fatal(err)
	}
	td.rec.Bind.Answer = []byte("an answer")
	td.rec.Claim.Session = "another"
	td.rec.Released[0].Session = "another"
	td.rec.Released = append(td.rec.Released, released{Claim: "claim-2"})
	td.rec.State = StateEnded
	td.rec.Ended = &ended{At: time.Unix(1, 0), Reason: "ended"}
	second := td.snapshot()
	td.rec.Ended.Reason = "another"
	after, err := json.Marshal(&first.rec)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("a snapshot changed with its record:\n%s\n%s", before, after)
	}
	if second.rec.Ended.Reason != "ended" || string(second.rec.Bind.Answer) != "an answer" {
		t.Fatalf("the second snapshot is %+v, %+v", second.rec.Ended, second.rec.Bind)
	}
	if first.n != 1 || second.n != 2 {
		t.Fatalf("the saves are numbered %d and %d", first.n, second.n)
	}
}
