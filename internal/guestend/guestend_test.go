package guestend_test

import (
	"net"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/guestend"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// The port is the one the host's file names, whatever else the file holds,
// and none when the file names none or is not the host's.
func TestPortIsTheOneTheHostNames(t *testing.T) {
	for file, want := range map[string]uint32{
		`{"end_port": 20007, "collateral_port": 20003, "network": {"address": "10.0.0.2/30"}}`: 20007,
		`{"collateral_port": 20003}`: 0,
		`{"end_port": 4294967295}`:   0,
		`{"end_port": "20007"}`:      0,
		`not the host's file`:        0,
		``:                           0,
	} {
		if got := guestend.Port([]byte(file)); got != want {
			t.Errorf("%s: port %d, want %d", file, got, want)
		}
	}
}

// A service's phase is one it may write. Anything else, and nothing at all,
// is a service that had started and was not ready.
func TestPhaseIsOneAServiceMayWrite(t *testing.T) {
	for written, want := range map[string]disclosure.Code{
		"ready\n": "ready", "bound": "bound", "running\n": "running",
		"": disclosure.EndedStarting, "boot": disclosure.EndedStarting, "sealing a secret of the tenant's, at length": disclosure.EndedStarting,
	} {
		if got := guestend.Phase([]byte(written)); got != want {
			t.Errorf("%q: phase %q, want %q", written, got, want)
		}
	}
}

// What a guest sends is what its launcher receives.
func TestWordSentIsTheWordReceived(t *testing.T) {
	guest, launcher := net.Pipe()
	status := 3
	sent := make(chan error, 1)
	go func() {
		sent <- guestend.Send(guest, disclosure.End{Phase: "ready", Code: disclosure.EndExited, Status: &status}, time.Second)
	}()
	end, err := guestend.Receive(launcher, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if end.Phase != "ready" || end.Code != disclosure.EndExited || end.Status == nil || *end.Status != 3 {
		t.Fatalf("received %+v", end)
	}
	if err := <-sent; err != nil {
		t.Fatalf("send: %v", err)
	}
}

// Neither side waits on the other for longer than it said: a launcher that
// takes nothing does not hold a guest's end up, and a guest that says
// nothing, or more than a word, gives its launcher none.
func TestNeitherSideIsHeldUpByTheOther(t *testing.T) {
	guest, launcher := net.Pipe()
	defer launcher.Close()
	began := time.Now()
	if err := guestend.Send(guest, disclosure.End{Phase: "running", Code: disclosure.EndProcess}, 100*time.Millisecond); err == nil {
		t.Fatal("a word nobody took was sent")
	}
	if waited := time.Since(began); waited > 2*time.Second {
		t.Fatalf("a guest waited %s on a launcher that took nothing", waited)
	}

	guest, launcher = net.Pipe()
	defer guest.Close()
	began = time.Now()
	if end, err := guestend.Receive(launcher, 100*time.Millisecond); err == nil {
		t.Fatalf("a guest that said nothing gave %+v", end)
	}
	if waited := time.Since(began); waited > 2*time.Second {
		t.Fatalf("a launcher waited %s on a guest that said nothing", waited)
	}

	guest, launcher = net.Pipe()
	go func() {
		defer guest.Close()
		_, _ = guest.Write([]byte(`{"phase":"running","code":"process_ended","note":"more than a word"}` + "\n"))
	}()
	if end, err := guestend.Receive(launcher, time.Second); err == nil {
		t.Fatalf("a word beyond the schema was received as %+v", end)
	}
}
