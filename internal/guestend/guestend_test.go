package guestend_test

import (
	"errors"
	"net"
	"sync/atomic"
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

// streams is a stream between a guest and its launcher, over TCP where
// theirs is over vsock.
func streams(t *testing.T) (guest *net.TCPConn, launcher net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	launcher, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dialed.Close(); _ = launcher.Close() })
	return dialed.(*net.TCPConn), launcher
}

// What a guest sends is what its launcher receives, as soon as the guest
// has ended its writing, and the guest's send returns once the launcher has
// closed.
func TestWordSentIsTheWordReceived(t *testing.T) {
	guest, launcher := streams(t)
	status := 3
	sent := make(chan error, 1)
	go func() {
		sent <- guestend.Send(guest, disclosure.End{Phase: "ready", Code: disclosure.EndExited, Status: &status}, 10*time.Second)
	}()
	began := time.Now()
	end, err := guestend.Receive(launcher, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if end.Phase != "ready" || end.Code != disclosure.EndExited || end.Status == nil || *end.Status != 3 {
		t.Fatalf("received %+v", end)
	}
	if waited := time.Since(began); waited > 2*time.Second {
		t.Fatalf("the launcher read for %s after a word that had arrived whole", waited)
	}
	_ = launcher.Close()
	if err := <-sent; err != nil {
		t.Fatalf("send: %v", err)
	}
}

// A guest's send returns only once its launcher has closed, which a launcher
// does when it has kept the word: a guest that powered off on its own write
// could take the word with it.
func TestGuestWaitsForItsLauncherToHaveTakenTheWord(t *testing.T) {
	guest, launcher := streams(t)
	var kept atomic.Bool
	go func() {
		if _, err := guestend.Receive(launcher, time.Second); err != nil {
			return
		}
		// What a launcher does with a word takes it a while.
		time.Sleep(150 * time.Millisecond)
		kept.Store(true)
		_ = launcher.Close()
	}()
	if err := guestend.Send(guest, disclosure.End{Phase: "running", Code: disclosure.EndProcess}, 5*time.Second); err != nil {
		t.Fatalf("send: %v", err)
	}
	if !kept.Load() {
		t.Fatal("the guest's send returned before its launcher had kept the word")
	}
}

// A word that arrived whole is taken though its stream failed after it, as
// the stream of a guest that is gone does. Part of a word is none.
func TestWordThatArrivedWholeIsTakenThoughItsStreamFailed(t *testing.T) {
	whole := `{"phase":"running","code":"process_ended"}`
	for name, tc := range map[string]struct {
		arrived string
		taken   bool
	}{
		"the whole word":   {whole, true},
		"part of the word": {whole[:len(whole)-9], false},
		"nothing":          {"", false},
	} {
		_, launcher := streams(t)
		end, err := guestend.Receive(&failing{Conn: launcher, arrived: []byte(tc.arrived)}, time.Second)
		if tc.taken != (err == nil) {
			t.Errorf("%s arrived before the stream failed: received %+v, %v", name, end, err)
		}
		if tc.taken && (end == nil || end.Code != disclosure.EndProcess || end.Phase != "running") {
			t.Errorf("%s arrived before the stream failed: received %+v", name, end)
		}
	}
}

// failing is a stream that delivers what arrived and then fails, as one
// does whose far end is gone without having closed.
type failing struct {
	net.Conn
	arrived []byte
}

func (f *failing) Read(b []byte) (int, error) {
	if len(f.arrived) == 0 {
		return 0, errors.New("connection reset by peer")
	}
	n := copy(b, f.arrived)
	f.arrived = f.arrived[n:]
	return n, nil
}

// Neither side waits on the other for longer than it said: a launcher that
// takes nothing does not hold a guest's end up, and a guest that says
// nothing, or more than a word, gives its launcher none.
func TestNeitherSideIsHeldUpByTheOther(t *testing.T) {
	guest, _ := streams(t)
	began := time.Now()
	if err := guestend.Send(guest, disclosure.End{Phase: "running", Code: disclosure.EndProcess}, 100*time.Millisecond); err == nil {
		t.Fatal("a word nobody took was sent")
	}
	if waited := time.Since(began); waited > 2*time.Second {
		t.Fatalf("a guest waited %s on a launcher that took nothing", waited)
	}

	_, launcher := streams(t)
	began = time.Now()
	if end, err := guestend.Receive(launcher, 100*time.Millisecond); err == nil {
		t.Fatalf("a guest that said nothing gave %+v", end)
	}
	if waited := time.Since(began); waited > 2*time.Second {
		t.Fatalf("a launcher waited %s on a guest that said nothing", waited)
	}

	guest, launcher = streams(t)
	go func() {
		_, _ = guest.Write([]byte(`{"phase":"running","code":"process_ended","note":"more than a word"}` + "\n"))
		_ = guest.CloseWrite()
	}()
	if end, err := guestend.Receive(launcher, time.Second); err == nil {
		t.Fatalf("a word beyond the schema was received as %+v", end)
	}
}
