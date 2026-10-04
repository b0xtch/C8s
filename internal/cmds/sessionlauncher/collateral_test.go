package sessionlauncher

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

var fedPlatform = session.CollateralPlatform{FMSPC: "b0c06f000000", CA: "platform"}

// fedGuest is a guest's hand-in port as a launcher finds it: every connection
// is told one line, and what the launcher sends on it is kept.
type fedGuest struct {
	mu sync.Mutex
	// lines are what the guest says on its first connection, its second, and
	// so on; the last holds for every later one. An empty line says nothing.
	lines []string
	// down refuses every connection.
	down bool
	// taken is what each connection was sent before the launcher closed it.
	taken [][]byte
	done  sync.WaitGroup
}

func (g *fedGuest) dial() (io.ReadWriteCloser, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.down {
		return nil, errors.New("connection refused")
	}
	n := len(g.taken)
	g.taken = append(g.taken, nil)
	line := g.lines[min(n, len(g.lines)-1)]
	host, guest := net.Pipe()
	g.done.Add(1)
	go func() {
		defer g.done.Done()
		defer guest.Close()
		if line == "" {
			return
		}
		if _, err := io.WriteString(guest, line); err != nil {
			return
		}
		// A guest that ends mid-line is gone. On a real connection one that
		// stays and says no more runs into the launcher's read deadline.
		if !strings.HasSuffix(line, "\n") {
			return
		}
		sent, _ := io.ReadAll(guest)
		g.mu.Lock()
		g.taken[n] = sent
		g.mu.Unlock()
	}()
	return host, nil
}

// handed is what each connection was sent, once the guest has read them all.
func (g *fedGuest) handed() [][]byte {
	g.done.Wait()
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.taken)
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
}

func (f *fetched) fetch(_ context.Context, p session.CollateralPlatform) ([]session.CollateralDocument, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, p)
	return f.docs, f.err
}

func (f *fetched) questions() []session.CollateralPlatform {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.asked)
}

func fourDocuments() []session.CollateralDocument {
	return []session.CollateralDocument{
		{URL: "https://pcs.example/tcb", Header: map[string][]string{"Tcb-Info-Issuer-Chain": {"chain"}}, Body: []byte("tcb info")},
		{URL: "https://pcs.example/qe", Body: []byte("identity")},
		{URL: "https://pcs.example/pckcrl", Body: []byte{0x30, 0x00}},
		{URL: "https://pcs.example/root", Body: []byte{0x30, 0x01}},
	}
}

// A round asks the guest which platform it is, fetches Intel's documents for
// that platform, and hands them in on a second connection, so that the guest
// waits for no fetch.
func TestFeederHandsAGuestItsPlatformsDocuments(t *testing.T) {
	guest := &fedGuest{lines: []string{platformLine(t, fedPlatform)}}
	intel := &fetched{docs: fourDocuments()}
	f := &feeder{dial: guest.dial, fetch: intel.fetch, pace: collateralPace, log: slog.New(slog.DiscardHandler)}
	if err := f.round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := intel.questions(); !slices.Equal(got, []session.CollateralPlatform{fedPlatform}) {
		t.Fatalf("Intel was asked for %+v", got)
	}
	handed := guest.handed()
	if len(handed) != 2 || len(handed[0]) != 0 {
		t.Fatalf("%d connections, the first sent %d bytes: want two, and nothing on the one that only asks", len(handed), len(handed[0]))
	}
	var answer session.CollateralResponse
	if err := json.Unmarshal(handed[1], &answer); err != nil || len(answer.Documents) != 4 {
		t.Fatalf("the guest was handed %q, %v", handed[1], err)
	}
	for i, doc := range answer.Documents {
		want := intel.docs[i]
		if doc.URL != want.URL || !bytes.Equal(doc.Body, want.Body) || len(doc.Header) != len(want.Header) {
			t.Errorf("document %d: %+v, want %+v", i, doc, want)
		}
	}
}

// What a guest says decides what its host asks Intel for. A line that is not
// the two values of a fixed shape gets nothing fetched at all.
func TestFeederFetchesOnlyForAPlatformOfTheFixedShape(t *testing.T) {
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
			guest := &fedGuest{lines: []string{line}}
			intel := &fetched{docs: fourDocuments()}
			f := &feeder{dial: guest.dial, fetch: intel.fetch, pace: collateralPace, log: slog.New(slog.DiscardHandler)}
			err := f.round(context.Background())
			// A field the launcher does not know changes nothing: the URLs are
			// built from the two it does.
			if name == "a platform and a URL" {
				if err != nil || !slices.Equal(intel.questions(), []session.CollateralPlatform{fedPlatform}) {
					t.Fatalf("%v, after asking Intel for %+v", err, intel.questions())
				}
				return
			}
			if err == nil || len(intel.questions()) != 0 {
				t.Fatalf("round = %v, after asking Intel for %+v", err, intel.questions())
			}
			for i, sent := range guest.handed() {
				if len(sent) != 0 {
					t.Errorf("connection %d was sent %d bytes", i, len(sent))
				}
			}
			// A guest that names nothing is one to ask again soon. One that
			// names something else is not asked again any sooner for it.
			if quiet := name == "nothing"; errors.Is(err, errNoAnswer) != quiet {
				t.Errorf("round = %v: read as a guest that does not answer: %v, want %v", err, !quiet, quiet)
			}
		})
	}
}

func TestFeederRoundThatHandsNothing(t *testing.T) {
	line := platformLine(t, fedPlatform)
	other := platformLine(t, session.CollateralPlatform{FMSPC: "00906ed50000", CA: "processor"})
	huge := []session.CollateralDocument{{URL: "https://pcs.example/tcb", Body: make([]byte, session.MaxCollateralBytes)}}
	for name, tc := range map[string]struct {
		guest    *fedGuest
		intel    *fetched
		noAnswer bool
	}{
		"a guest that takes no connection":          {&fedGuest{lines: []string{line}, down: true}, &fetched{docs: fourDocuments()}, true},
		"Intel out of reach":                        {&fedGuest{lines: []string{line}}, &fetched{err: errors.New("no route")}, false},
		"more than a guest takes":                   {&fedGuest{lines: []string{line}}, &fetched{docs: huge}, false},
		"another platform on the second asking":     {&fedGuest{lines: []string{line, other}}, &fetched{docs: fourDocuments()}, false},
		"a guest gone quiet by the second asking":   {&fedGuest{lines: []string{line, ""}}, &fetched{docs: fourDocuments()}, true},
		"a guest gone strange by the second asking": {&fedGuest{lines: []string{line, "x\n"}}, &fetched{docs: fourDocuments()}, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := &feeder{dial: tc.guest.dial, fetch: tc.intel.fetch, pace: collateralPace, log: slog.New(slog.DiscardHandler)}
			err := f.round(context.Background())
			if err == nil || errors.Is(err, errNoAnswer) != tc.noAnswer {
				t.Fatalf("round = %v, want an error, of a guest that does not answer: %v", err, tc.noAnswer)
			}
			for i, sent := range tc.guest.handed() {
				if len(sent) != 0 {
					t.Errorf("connection %d was sent %d bytes", i, len(sent))
				}
			}
		})
	}
	// The most a guest takes is taken.
	largest := []session.CollateralDocument{{URL: "u", Body: make([]byte, 0)}}
	for {
		blob, _ := json.Marshal(session.CollateralResponse{Documents: largest})
		if len(blob) >= session.MaxCollateralBytes {
			break
		}
		largest[0].Body = append(largest[0].Body, make([]byte, max(1, (session.MaxCollateralBytes-len(blob))*3/4-2))...)
	}
	for len(mustJSON(t, largest)) > session.MaxCollateralBytes {
		largest[0].Body = largest[0].Body[:len(largest[0].Body)-1]
	}
	if n := len(mustJSON(t, largest)); n > session.MaxCollateralBytes || n < session.MaxCollateralBytes-4 {
		t.Fatalf("fixture: the blob is %d bytes", n)
	}
	guest := &fedGuest{lines: []string{line}}
	f := &feeder{dial: guest.dial, fetch: (&fetched{docs: largest}).fetch, pace: collateralPace, log: slog.New(slog.DiscardHandler)}
	if err := f.round(context.Background()); err != nil {
		t.Fatalf("a blob of %d bytes: %v", len(mustJSON(t, largest)), err)
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

// The launcher knocks about every second while its guest can still be
// booting and backs off after that, hands in every twenty minutes once that
// works, comes back in half a minute when a round fails, and says each change
// of state once.
func TestFeederPace(t *testing.T) {
	guest := &fedGuest{lines: []string{platformLine(t, fedPlatform)}, down: true}
	intel := &fetched{docs: fourDocuments()}
	pace := feedPace{
		every: 20 * time.Minute, knock: 250 * time.Millisecond, booting: time.Second, boot: 4 * time.Second,
		retry: 30 * time.Second, fetch: time.Second,
	}
	out := &logged{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits []time.Duration
	// What happens before each round, by how many came before it.
	before := map[int]func(){
		10: func() { guest.mu.Lock(); guest.down = false; guest.mu.Unlock() },
		12: func() { intel.mu.Lock(); intel.err = errors.New("no route to Intel"); intel.mu.Unlock() },
		14: func() { intel.mu.Lock(); intel.err = nil; intel.mu.Unlock() },
		15: func() { guest.mu.Lock(); guest.down = true; guest.mu.Unlock() },
	}
	now := time.Unix(1_700_000_000, 0)
	f := &feeder{dial: guest.dial, fetch: intel.fetch, pace: pace, log: slog.New(slog.NewJSONHandler(out, nil)), now: func() time.Time { return now }}
	f.wait = func(_ context.Context, d time.Duration) bool {
		waits = append(waits, d)
		now = now.Add(d)
		if change := before[len(waits)]; change != nil {
			change()
		}
		if len(waits) == 18 {
			cancel()
			return false
		}
		return true
	}
	f.run(ctx)
	ms := time.Millisecond
	want := []time.Duration{
		// A guest that can still be booting, for four seconds: sooner at
		// first, and then once a second.
		250 * ms, 500 * ms, 1000 * ms, 1000 * ms, 1000 * ms, 1000 * ms,
		// It did not come up in that time: slower from here.
		1000 * ms, 2000 * ms, 4000 * ms, 8000 * ms,
		// It answers: two rounds that work.
		pace.every, pace.every,
		// Intel out of reach for two rounds, then back.
		pace.retry, pace.retry, pace.every,
		// The guest stops answering: knocking starts over, and it is long
		// past booting.
		250 * ms, 500 * ms, 1000 * ms,
	}
	if !slices.Equal(waits, want) {
		t.Fatalf("waits %v\n want %v", waits, want)
	}
	out.mu.Lock()
	defer out.mu.Unlock()
	wantLines := []string{
		"INFO handed the guest Intel's collateral for its platform",
		"WARN the guest goes without Intel's collateral for now, and its verifiers ask Intel",
		"INFO handed the guest Intel's collateral for its platform",
	}
	if !slices.Equal(out.lines, wantLines) {
		t.Fatalf("the launcher said %q\n want %q", out.lines, wantLines)
	}

	// One that never answers is asked every half minute at the most.
	guest = &fedGuest{lines: []string{platformLine(t, fedPlatform)}, down: true}
	waits, now = nil, time.Unix(1_700_000_000, 0)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	f = &feeder{dial: guest.dial, fetch: intel.fetch, pace: pace, log: slog.New(slog.DiscardHandler), now: func() time.Time { return now }}
	f.wait = func(_ context.Context, d time.Duration) bool {
		waits = append(waits, d)
		now = now.Add(d)
		if len(waits) == 14 {
			cancel()
			return false
		}
		return true
	}
	f.run(ctx)
	if tail := waits[10:]; !slices.Equal(tail, []time.Duration{16000 * ms, 30000 * ms, 30000 * ms, 30000 * ms}) {
		t.Fatalf("a guest that never answers is asked after %v", waits)
	}
}

// Between rounds the launcher waits on the clock, and stops when its guest
// is gone.
func TestFeederStopsWithItsGuest(t *testing.T) {
	guest := &fedGuest{lines: []string{platformLine(t, fedPlatform)}}
	f := &feeder{
		dial: guest.dial, fetch: (&fetched{docs: fourDocuments()}).fetch, log: slog.New(slog.DiscardHandler),
		pace: feedPace{every: time.Millisecond, knock: time.Millisecond, booting: time.Millisecond, retry: time.Millisecond, fetch: time.Second},
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { f.run(ctx); close(stopped) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		guest.mu.Lock()
		connections := len(guest.taken)
		guest.mu.Unlock()
		// Two rounds of two connections: it came back after its wait.
		if connections >= 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connections in five seconds", connections)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the feeder outlived its guest")
	}
}

// The line is read from a connection that may say more: what follows it is
// not read, and a reader that stops there does not block the guest.
func TestFeederReadsOneLine(t *testing.T) {
	host, guest := net.Pipe()
	go func() {
		w := bufio.NewWriter(guest)
		_, _ = w.WriteString(platformLine(t, fedPlatform))
		_ = w.Flush()
	}()
	f := &feeder{dial: func() (io.ReadWriteCloser, error) { return host, nil }}
	platform, conn, err := f.ask()
	if err != nil || platform != fedPlatform {
		t.Fatalf("ask = %+v, %v", platform, err)
	}
	_ = conn.Close()
	_ = guest.Close()
}

// A guest is handed Intel's documents when it is a TD its launcher can reach
// over vsock, unless the launcher was told otherwise. It is told to by default.
func TestWhichGuestsAreFed(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	fed := Config{Platform: "tdx", Collateral: true, VsockCID: 1042}
	if fed.feeder(log) == nil {
		t.Fatal("a TD with a vsock device is handed nothing")
	}
	reserved := Config{Platform: "tdx", Collateral: true, vsock: &vsockDevice{cid: 70000, fd: 5}}
	if reserved.guestCID() != 70000 || reserved.feeder(log) == nil {
		t.Fatalf("a TD whose context id the kernel picked (%d) is handed nothing", reserved.guestCID())
	}
	for name, change := range map[string]func(*Config){
		"told not to":     func(c *Config) { c.Collateral = false },
		"no TD":           func(c *Config) { c.Platform = "snp" },
		"no vsock device": func(c *Config) { c.VsockCID = 0 },
	} {
		cfg := fed
		change(&cfg)
		if cfg.feeder(log) != nil {
			t.Errorf("%s: the guest is handed Intel's documents", name)
		}
	}
	if flag := newRunCmd().Flags().Lookup("collateral"); flag == nil || flag.DefValue != "true" {
		t.Fatalf("--collateral: %+v", flag)
	}
}

// A launcher that feeds its guest stops as cleanly as one that does not, with
// a guest that never answers.
func TestRunStopsWithItsFeeder(t *testing.T) {
	qemu, _ := fakeQEMU(t, "exec sleep 30")
	cfg := launchConfig(t, qemu)
	cfg.Collateral, cfg.VsockCID = true, 1042
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, slog.New(slog.DiscardHandler)) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the launcher did not stop")
	}
}
