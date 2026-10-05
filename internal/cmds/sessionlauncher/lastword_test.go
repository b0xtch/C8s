package sessionlauncher

import (
	"bytes"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/guestend"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

// listening is a launcher that takes its guest's last word over TCP, where
// the guest's would come over vsock, and writes its log to the buffer.
func listening(t *testing.T, own func(net.Conn) bool) (*lastWord, string, *bytes.Buffer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	w := &lastWord{ln: ln, own: own, file: filepath.Join(t.TempDir(), "end.json"), log: slog.New(slog.NewJSONHandler(&logged, nil))}
	done := make(chan struct{})
	go func() { defer close(done); w.serve() }()
	t.Cleanup(func() { _ = w.Close(); <-done })
	return w, ln.Addr().String(), &logged
}

// say sends bytes to a launcher as a guest's init would its word.
func say(t *testing.T, addr string, word []byte) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(word); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

// wordKept waits for the launcher to have written a word and returns it.
func wordKept(t *testing.T, w *lastWord) *disclosure.End {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if data, err := os.ReadFile(w.file); err == nil {
			end, err := disclosure.ParseEnd(bytes.TrimSpace(data))
			if err != nil {
				t.Fatalf("the launcher kept %q: %v", data, err)
			}
			return end
		}
	}
	return nil
}

// A launcher keeps the word its guest says as it ends: in its log, and in
// the file whoever started it named. It keeps the first: a guest has one.
func TestLauncherKeepsItsGuestsLastWord(t *testing.T) {
	w, addr, logged := listening(t, func(net.Conn) bool { return true })
	signal := 9
	first, err := disclosure.Encode(disclosure.MessageEnd, disclosure.End{Phase: "running", Code: disclosure.EndKilled, Signal: &signal, Memory: true})
	if err != nil {
		t.Fatal(err)
	}
	say(t, addr, first)
	end := wordKept(t, w)
	if end == nil || end.Phase != "running" || end.Code != disclosure.EndKilled || end.Signal == nil || *end.Signal != 9 || !end.Memory {
		t.Fatalf("the launcher kept %+v", end)
	}
	if !strings.Contains(logged.String(), `"msg":"the guest said why it ends"`) || !strings.Contains(logged.String(), `"code":"service_killed"`) {
		t.Fatalf("the launcher logged %s", logged.String())
	}
	second, err := disclosure.Encode(disclosure.MessageEnd, disclosure.End{Phase: "ready", Code: disclosure.EndProcess})
	if err != nil {
		t.Fatal(err)
	}
	say(t, addr, second)
	// The second is read and dropped: a third connection is taken after it.
	say(t, addr, second)
	time.Sleep(50 * time.Millisecond)
	if end := wordKept(t, w); end == nil || end.Code != disclosure.EndKilled {
		t.Fatalf("a second word replaced the first: %+v", end)
	}
}

// A word is taken from the launcher's own guest only, and only as the
// schema allows one: whatever else is said to the port leaves no word.
func TestLauncherTakesNoWordThatIsNotItsGuestsOrTheSchemas(t *testing.T) {
	word, err := disclosure.Encode(disclosure.MessageEnd, disclosure.End{Phase: "running", Code: disclosure.EndProcess})
	if err != nil {
		t.Fatal(err)
	}
	w, addr, _ := listening(t, func(net.Conn) bool { return false })
	say(t, addr, word)
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(w.file); !os.IsNotExist(err) {
		t.Fatalf("a word from another than the launcher's guest was kept (%v)", err)
	}

	w, addr, logged := listening(t, func(net.Conn) bool { return true })
	say(t, addr, []byte(`{"phase":"running","code":"process_ended","note":"the tenant's secret"}`+"\n"))
	say(t, addr, bytes.Repeat([]byte("x"), 4*disclosure.MaxEnd))
	for deadline := time.Now().Add(5 * time.Second); strings.Count(logged.String(), "none the disclosure schema allows") < 2; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the launcher did not refuse both words: %s", logged.String())
		}
	}
	if _, err := os.Stat(w.file); !os.IsNotExist(err) {
		t.Fatalf("a word beyond the schema was kept (%v)", err)
	}
	if strings.Contains(logged.String(), "secret") {
		t.Fatalf("what a guest said beyond the schema is in the launcher's log: %s", logged.String())
	}
	// The guest's own word after those is still taken.
	say(t, addr, word)
	if end := wordKept(t, w); end == nil || end.Code != disclosure.EndProcess {
		t.Fatalf("the word that followed was kept as %+v", end)
	}
}

// A guest that says nothing does not hold its launcher: the connection is
// given up after the time a word may take.
func TestLauncherWaitsForNoWordLongerThanOneMayTake(t *testing.T) {
	_, addr, logged := listening(t, func(net.Conn) bool { return true })
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for deadline := time.Now().Add(3 * guestend.Wait); !strings.Contains(logged.String(), "none the disclosure schema allows"); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the launcher still waits for a guest that says nothing")
		}
	}
}
