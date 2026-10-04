package sessionlauncher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/vsock"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

var askedPlatform = session.CollateralPlatform{FMSPC: "b0c06f000000", CA: "platform"}

// asks is the stock's port as a test reaches it: every connection is one end
// of a pipe.
type asks struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newAsks() *asks { return &asks{conns: make(chan net.Conn), closed: make(chan struct{})} }

func (a *asks) Accept() (net.Conn, error) {
	select {
	case conn := <-a.conns:
		return conn, nil
	case <-a.closed:
		return nil, net.ErrClosed
	}
}

func (a *asks) Close() error   { a.once.Do(func() { close(a.closed) }); return nil }
func (a *asks) Addr() net.Addr { return vsock.Addr{} }

// ask is one connection of a guest's: its line, and what it was answered
// with once the launcher was done.
func (a *asks) ask(t *testing.T, line string) []byte {
	t.Helper()
	guest, host := net.Pipe()
	defer guest.Close()
	select {
	case a.conns <- host:
	case <-time.After(5 * time.Second):
		t.Fatal("the launcher took no connection")
	}
	// A launcher that stops reading ends the write when it hangs up.
	go func() { _, _ = io.WriteString(guest, line) }()
	_ = guest.SetReadDeadline(time.Now().Add(10 * time.Second))
	answer, err := io.ReadAll(guest)
	if err != nil {
		t.Fatalf("the launcher's answer: %v", err)
	}
	return answer
}

func platformLine(t *testing.T, p session.CollateralPlatform) string {
	t.Helper()
	line, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(line) + "\n"
}

// fetched is Intel's service as a launcher asks it.
type fetched struct {
	mu    sync.Mutex
	asked []session.CollateralPlatform
	docs  []session.CollateralDocument
	err   error
	// slow, when set, is waited for before each answer.
	slow chan struct{}
}

func (f *fetched) fetch(ctx context.Context, p session.CollateralPlatform) ([]session.CollateralDocument, error) {
	f.mu.Lock()
	f.asked = append(f.asked, p)
	slow := f.slow
	f.mu.Unlock()
	if slow != nil {
		select {
		case <-slow:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.docs, f.err
}

func (f *fetched) questions() []session.CollateralPlatform {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.asked)
}

func (f *fetched) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func fourDocuments() []session.CollateralDocument {
	return []session.CollateralDocument{
		{URL: "https://pcs.example/tcb", Header: map[string][]string{"Tcb-Info-Issuer-Chain": {"chain"}}, Body: []byte("tcb info")},
		{URL: "https://pcs.example/qe", Body: []byte("identity")},
		{URL: "https://pcs.example/pckcrl", Body: []byte{0x30, 0x00}},
		{URL: "https://pcs.example/root", Body: []byte{0x30, 0x01}},
	}
}

func mustJSON(t *testing.T, docs []session.CollateralDocument) []byte {
	t.Helper()
	blob, err := json.Marshal(session.CollateralResponse{Documents: docs})
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// logged collects what the launcher says.
type logged struct {
	mu    sync.Mutex
	lines []string
}

func (l *logged) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var record struct {
		Level string `json:"level"`
		Msg   string `json:"msg"`
	}
	if json.Unmarshal(p, &record) == nil {
		l.lines = append(l.lines, record.Level+" "+record.Msg)
	}
	return len(p), nil
}

func (l *logged) said() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.lines)
}

// clock is a clock a test moves.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock { return &clock{now: time.Unix(1_700_000_000, 0)} }

func (c *clock) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

var testPace = stockPace{
	fresh: 10 * time.Minute, retry: 30 * time.Second, fetch: 5 * time.Second, hold: 5 * time.Second,
	line: 100 * time.Millisecond, answer: 5 * time.Second,
}

// running is a launcher's stock that takes connections until its test ends.
type running struct {
	*stock
	port *asks
	out  *logged
}

func runStock(t *testing.T, dir string, intel *fetched, at *clock) *running {
	t.Helper()
	port, out := newAsks(), &logged{}
	s := &stock{
		ln: port, own: func(net.Conn) bool { return true }, fetch: intel.fetch, dir: dir, pace: testPace,
		log: slog.New(slog.NewJSONHandler(out, nil)), now: at.read,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the stock went on after its launcher ended")
		}
	})
	return &running{stock: s, port: port, out: out}
}

// A guest says which platform it is and is answered with Intel's documents
// for it on the same connection. The launcher fetches them once, and keeps
// them for the host's other launchers.
func TestStockAnswersAGuestWithItsPlatformsDocuments(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "collateral")
	intel := &fetched{docs: fourDocuments()}
	s := runStock(t, dir, intel, newClock())
	line := platformLine(t, askedPlatform)

	blob := s.port.ask(t, line)
	var answer session.CollateralResponse
	if err := json.Unmarshal(blob, &answer); err != nil || len(answer.Documents) != 4 {
		t.Fatalf("the guest was answered with %q, %v", blob, err)
	}
	for i, doc := range answer.Documents {
		want := intel.docs[i]
		if doc.URL != want.URL || !bytes.Equal(doc.Body, want.Body) || len(doc.Header) != len(want.Header) {
			t.Errorf("document %d: %+v, want %+v", i, doc, want)
		}
	}
	// The next ask is answered with the same bytes, and Intel is not asked.
	if again := s.port.ask(t, line); !bytes.Equal(again, blob) {
		t.Fatalf("the second answer differs: %q", again)
	}
	if got := intel.questions(); !slices.Equal(got, []session.CollateralPlatform{askedPlatform}) {
		t.Fatalf("Intel was asked for %+v", got)
	}
	keptFile := filepath.Join(dir, "b0c06f000000-platform.json")
	onDisk, err := os.ReadFile(keptFile)
	if err != nil || !bytes.Equal(onDisk, blob) {
		t.Fatalf("kept for the host's launchers: %q, %v", onDisk, err)
	}
	if info, err := os.Stat(keptFile); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the kept set's mode: %v, %v", info.Mode(), err)
	}
	if said := s.out.said(); !slices.Equal(said, []string{"INFO answered the guest with Intel's collateral for its platform"}) {
		t.Fatalf("the launcher said %q", said)
	}
}

// What a guest says decides what its host asks Intel for. A line that is not
// the two values of a fixed shape gets nothing fetched and nothing answered.
func TestStockFetchesOnlyForAPlatformOfTheFixedShape(t *testing.T) {
	for name, line := range map[string]string{
		"not JSON":             "tdx\n",
		"another host":         `{"fmspc":"evil.example/x?","ca":"platform"}` + "\n",
		"a path":               `{"fmspc":"../../../../x","ca":"platform"}` + "\n",
		"uppercase":            `{"fmspc":"B0C06F000000","ca":"platform"}` + "\n",
		"too short":            `{"fmspc":"b0c06f00000","ca":"platform"}` + "\n",
		"a query in the CA":    `{"fmspc":"b0c06f000000","ca":"platform&x=y"}` + "\n",
		"no CA":                `{"fmspc":"b0c06f000000"}` + "\n",
		"a line with no end":   `{"fmspc":"b0c06f000000","ca":"platform"}`,
		"a line that is long":  `{"fmspc":"b0c06f000000","ca":"platform","pad":"` + strings.Repeat("a", maxPlatformLine) + `"}` + "\n",
		"nothing":              "",
		"an empty line":        "\n",
		"a platform and a URL": `{"fmspc":"b0c06f000000","ca":"platform","url":"https://evil.example/"}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			intel := &fetched{docs: fourDocuments()}
			s := runStock(t, dir, intel, newClock())
			if answer := s.port.ask(t, line); len(answer) != 0 {
				t.Fatalf("the guest was answered with %d bytes", len(answer))
			}
			if asked := intel.questions(); len(asked) != 0 {
				t.Fatalf("Intel was asked for %+v", asked)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("the line left %d files behind", len(entries))
			}
		})
	}
}

// One host's guests name one platform, and one fetch serves them all: a
// launcher answers its guest with what another guest's launcher fetched.
func TestStockAnswersWithWhatAnotherLauncherFetched(t *testing.T) {
	dir, at := t.TempDir(), newClock()
	first := runStock(t, dir, &fetched{docs: fourDocuments()}, at)
	line := platformLine(t, askedPlatform)
	blob := first.port.ask(t, line)

	at.add(testPace.fresh - time.Second)
	intel := &fetched{err: errors.New("this launcher asks Intel for nothing")}
	second := runStock(t, dir, intel, at)
	if answer := second.port.ask(t, line); !bytes.Equal(answer, blob) {
		t.Fatalf("the second launcher's guest was answered with %q", answer)
	}
	if asked := intel.questions(); len(asked) != 0 {
		t.Fatalf("the second launcher asked Intel for %+v", asked)
	}
}

// A set is answered with for ten minutes and fetched anew at the first ask
// after that. While Intel is out of reach the old set is what a guest gets,
// Intel is asked again no sooner than the retry time, and the launcher says
// so once.
func TestStockFetchesAnewWhenItsSetIsOld(t *testing.T) {
	dir, at := t.TempDir(), newClock()
	intel := &fetched{docs: fourDocuments()}
	s := runStock(t, dir, intel, at)
	line := platformLine(t, askedPlatform)
	old := s.port.ask(t, line)

	at.add(testPace.fresh)
	intel.fail(errors.New("no route to Intel"))
	for range 3 {
		if answer := s.port.ask(t, line); !bytes.Equal(answer, old) {
			t.Fatalf("with Intel out of reach the guest was answered with %q", answer)
		}
	}
	if asked := len(intel.questions()); asked != 2 {
		t.Fatalf("Intel was asked %d times, want once for the first set and once after it aged", asked)
	}
	at.add(testPace.retry)
	if answer := s.port.ask(t, line); !bytes.Equal(answer, old) {
		t.Fatalf("the guest was answered with %q", answer)
	}
	if asked := len(intel.questions()); asked != 3 {
		t.Fatalf("Intel was asked %d times, want a third after the retry time", asked)
	}

	// Intel is back with newer documents.
	at.add(testPace.retry)
	intel.mu.Lock()
	intel.err, intel.docs = nil, fourDocuments()[:2]
	intel.mu.Unlock()
	fresh := s.port.ask(t, line)
	var answer session.CollateralResponse
	if err := json.Unmarshal(fresh, &answer); err != nil || len(answer.Documents) != 2 {
		t.Fatalf("after Intel came back the guest was answered with %q, %v", fresh, err)
	}
	want := []string{
		"INFO answered the guest with Intel's collateral for its platform",
		"WARN the guest goes without fresh collateral from Intel for now, and its verifiers ask Intel",
	}
	if said := s.out.said(); !slices.Equal(said, want) {
		t.Fatalf("the launcher said %q\nwant %q", said, want)
	}
}

// A guest's quotes come from one platform. A guest that names a second one
// is answered with nothing, and Intel is not asked for it.
func TestStockKeepsToThePlatformItsGuestNamedFirst(t *testing.T) {
	intel := &fetched{docs: fourDocuments()}
	s := runStock(t, t.TempDir(), intel, newClock())
	if answer := s.port.ask(t, platformLine(t, askedPlatform)); len(answer) == 0 {
		t.Fatal("the first platform was answered with nothing")
	}
	other := session.CollateralPlatform{FMSPC: "00906ed50000", CA: "processor"}
	if answer := s.port.ask(t, platformLine(t, other)); len(answer) != 0 {
		t.Fatalf("a second platform was answered with %d bytes", len(answer))
	}
	if got := intel.questions(); !slices.Equal(got, []session.CollateralPlatform{askedPlatform}) {
		t.Fatalf("Intel was asked for %+v", got)
	}
	if answer := s.port.ask(t, platformLine(t, askedPlatform)); len(answer) == 0 {
		t.Fatal("the first platform is answered with nothing after a second was named")
	}
}

// The port is the host's, and every guest on the host reaches it. Only the
// launcher's own guest is read and answered.
func TestStockTakesOnlyItsOwnGuest(t *testing.T) {
	intel := &fetched{docs: fourDocuments()}
	s := runStock(t, t.TempDir(), intel, newClock())
	s.own = func(net.Conn) bool { return false }
	if answer := s.port.ask(t, platformLine(t, askedPlatform)); len(answer) != 0 {
		t.Fatalf("another guest was answered with %d bytes", len(answer))
	}
	if asked := intel.questions(); len(asked) != 0 {
		t.Fatalf("Intel was asked for %+v at another guest's word", asked)
	}
}

// A launcher with nothing to answer with answers with nothing, and leaves
// nothing behind for a platform it could not fetch.
func TestStockThatHasNothing(t *testing.T) {
	huge := []session.CollateralDocument{{URL: "https://pcs.example/tcb", Body: make([]byte, session.MaxCollateralBytes)}}
	for name, intel := range map[string]*fetched{
		"Intel out of reach":      {err: errors.New("no route")},
		"more than a guest takes": {docs: huge},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s := runStock(t, dir, intel, newClock())
			if answer := s.port.ask(t, platformLine(t, askedPlatform)); len(answer) != 0 {
				t.Fatalf("the guest was answered with %d bytes", len(answer))
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				t.Errorf("%s was left behind", entry.Name())
			}
		})
	}

	// The most a guest takes is kept and answered with.
	largest := []session.CollateralDocument{{URL: "u", Body: make([]byte, session.MaxCollateralBytes*3/4-64)}}
	for len(mustJSON(t, largest)) > session.MaxCollateralBytes {
		largest[0].Body = largest[0].Body[:len(largest[0].Body)-1]
	}
	for len(mustJSON(t, largest)) < session.MaxCollateralBytes-4 {
		largest[0].Body = append(largest[0].Body, 0)
	}
	if n := len(mustJSON(t, largest)); n > session.MaxCollateralBytes || n < session.MaxCollateralBytes-4 {
		t.Fatalf("fixture: the blob is %d bytes", n)
	}
	s := runStock(t, t.TempDir(), &fetched{docs: largest}, newClock())
	if answer := s.port.ask(t, platformLine(t, askedPlatform)); len(answer) != len(mustJSON(t, largest)) {
		t.Fatalf("a blob of %d bytes was answered with %d", len(mustJSON(t, largest)), len(answer))
	}
}

// A launcher looks for the host's last set as it starts, ahead of its
// guest's first ask, which then waits for no fetch.
func TestStockFetchesAheadOfItsGuest(t *testing.T) {
	dir, at := t.TempDir(), newClock()
	if err := writeKept(dir, &kept{platform: askedPlatform, blob: []byte("an old set"), at: at.read().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// Files that name no platform are not read as one.
	for _, name := range []string{"notes.json", "b0c06f000000-other.json", "B0C06F000000-platform.json", "b0c06f000000-platform.lock.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	intel := &fetched{docs: fourDocuments()}
	s := runStock(t, dir, intel, at)
	deadline := time.Now().Add(5 * time.Second)
	for len(intel.questions()) == 0 || readKept(dir, askedPlatform) == nil || string(readKept(dir, askedPlatform).blob) == "an old set" {
		if time.Now().After(deadline) {
			t.Fatalf("the launcher did not fetch ahead: asked Intel for %+v", intel.questions())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if answer := s.port.ask(t, platformLine(t, askedPlatform)); !bytes.Equal(answer, mustJSON(t, fourDocuments())) {
		t.Fatalf("the guest was answered with %q", answer)
	}
	if got := intel.questions(); !slices.Equal(got, []session.CollateralPlatform{askedPlatform}) {
		t.Fatalf("Intel was asked for %+v", got)
	}
}

// An ask waits for a fetch no longer than the launcher holds it, and the
// next ask finds what the fetch brought.
func TestStockHoldsAnAskNoLongerThanItsLimit(t *testing.T) {
	intel := &fetched{docs: fourDocuments(), slow: make(chan struct{})}
	s := runStock(t, t.TempDir(), intel, newClock())
	s.pace.hold = 50 * time.Millisecond
	line := platformLine(t, askedPlatform)
	began := time.Now()
	if answer := s.port.ask(t, line); len(answer) != 0 {
		t.Fatalf("answered with %d bytes before Intel answered", len(answer))
	}
	if waited := time.Since(began); waited > 2*time.Second {
		t.Fatalf("the ask was held for %s", waited)
	}
	close(intel.slow)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if answer := s.port.ask(t, line); len(answer) != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fetch's documents never reached the guest")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if asked := len(intel.questions()); asked != 1 {
		t.Fatalf("Intel was asked %d times", asked)
	}
}

// The launchers of one host fetch a platform's documents one at a time, and
// whoever waited takes what the first one brought.
func TestLaunchersFetchOneAtATime(t *testing.T) {
	dir, at := t.TempDir(), newClock()
	intel := &fetched{docs: fourDocuments(), slow: make(chan struct{})}
	line := platformLine(t, askedPlatform)
	const launchers = 4
	answers := make(chan []byte, launchers)
	for range launchers {
		s := runStock(t, dir, intel, at)
		go func() { answers <- s.port.ask(t, line) }()
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(intel.questions()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no launcher asked Intel")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The others wait on the first one's lock while it fetches.
	time.Sleep(4 * lockPoll)
	close(intel.slow)
	for range launchers {
		if answer := <-answers; !bytes.Equal(answer, mustJSON(t, fourDocuments())) {
			t.Fatalf("a guest was answered with %q", answer)
		}
	}
	if asked := len(intel.questions()); asked != 1 {
		t.Fatalf("Intel was asked %d times by %d launchers", asked, launchers)
	}
}

// A launcher with no directory keeps its own set, and reads none.
func TestStockWithoutADirectory(t *testing.T) {
	at := newClock()
	intel := &fetched{docs: fourDocuments()}
	s := runStock(t, "", intel, at)
	line := platformLine(t, askedPlatform)
	blob := s.port.ask(t, line)
	if len(blob) == 0 || !bytes.Equal(s.port.ask(t, line), blob) {
		t.Fatalf("answered with %q", blob)
	}
	at.add(testPace.fresh)
	if answer := s.port.ask(t, line); !bytes.Equal(answer, blob) {
		t.Fatalf("answered with %q", answer)
	}
	if asked := len(intel.questions()); asked != 2 {
		t.Fatalf("Intel was asked %d times", asked)
	}
}

// What the launchers keep is read with the bounds a guest's answer has, and
// a set dated ahead of the clock is fetched anew.
func TestKeptSets(t *testing.T) {
	dir, at := t.TempDir(), newClock()
	path := filepath.Join(dir, keptName(askedPlatform)+keptSuffix)
	for name, content := range map[string][]byte{"empty": nil, "too large": make([]byte, session.MaxCollateralBytes+1)} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if set := readKept(dir, askedPlatform); set != nil {
			t.Errorf("%s: read as a set of %d bytes", name, len(set.blob))
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if set := readKept(dir, askedPlatform); set != nil {
		t.Error("a directory was read as a set")
	}
	if _, ok := newestKept(dir); ok {
		t.Error("a directory was taken for the host's last set")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := newestKept(filepath.Join(dir, "absent")); ok {
		t.Error("a directory that is not there named a platform")
	}

	// Of two sets, the one written last names the host's platform.
	other := session.CollateralPlatform{FMSPC: "00906ed50000", CA: "processor"}
	for platform, age := range map[session.CollateralPlatform]time.Duration{askedPlatform: time.Hour, other: time.Minute} {
		if err := writeKept(dir, &kept{platform: platform, blob: []byte("set"), at: at.read().Add(-age)}); err != nil {
			t.Fatal(err)
		}
	}
	if newest, ok := newestKept(dir); !ok || newest != other {
		t.Fatalf("the host's last set is %+v, %v", newest, ok)
	}

	if err := writeKept(dir, &kept{platform: askedPlatform, blob: []byte("from the future"), at: at.read().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	intel := &fetched{docs: fourDocuments()}
	s := &stock{fetch: intel.fetch, dir: dir, pace: testPace, log: slog.New(slog.DiscardHandler), now: at.read}
	if blob, fresh := s.look(askedPlatform); fresh || string(blob) != "from the future" {
		t.Fatalf("a set dated ahead of the clock: %q, fresh %v", blob, fresh)
	}
	if blob := s.current(context.Background(), askedPlatform); !bytes.Equal(blob, mustJSON(t, fourDocuments())) {
		t.Fatalf("answered with %q", blob)
	}
}
