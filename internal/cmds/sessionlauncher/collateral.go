package sessionlauncher

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/internal/vsock"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// stockPace is how a launcher keeps Intel's documents for its guest.
type stockPace struct {
	// fresh is how long a set is answered with before it is fetched anew.
	// Intel signs the documents anew about once an hour and a verifier takes
	// one for two hours from Intel's date on it. A guest asks every ten
	// minutes, so a set kept for ten is served for eighty at most.
	fresh time.Duration
	// retry is how soon Intel is asked again after a fetch that failed.
	retry time.Duration
	// fetch bounds one fetch from Intel, the wait for another launcher's
	// included.
	fetch time.Duration
	// hold bounds how long a guest's ask waits for a fetch. It is shorter
	// than the guest's own limit, so the guest is always answered.
	hold time.Duration
	// line bounds the wait for a guest's line, and answer the write of what
	// it is answered with.
	line, answer time.Duration
}

var collateralPace = stockPace{
	fresh: 10 * time.Minute, retry: 30 * time.Second, fetch: 30 * time.Second, hold: 10 * time.Second,
	line: 2 * time.Second, answer: 10 * time.Second,
}

const (
	// maxPlatformLine bounds the one line a guest sends its host.
	maxPlatformLine = 256
	// asked is the backlog of a guest's asks: one at a time is answered.
	asked = 4
	// stockPause is how long the stock waits after an accept that failed.
	stockPause = time.Second
	// lockPoll is how often a launcher looks whether another is done fetching.
	lockPoll = 50 * time.Millisecond
)

// kept is one set of Intel's documents: a session.CollateralResponse as a
// guest is answered with it, and when it was fetched.
type kept struct {
	platform session.CollateralPlatform
	blob     []byte
	at       time.Time
}

// stock answers one guest's asks for Intel's documents for its platform: see
// session.HostConfig. Nothing a guest or a verifier trusts rests on it. A
// verifier checks Intel's signature on each document and Intel's own date in
// it, so a launcher that answers with nothing, or with anything else, costs a
// verifier a fetch from Intel.
type stock struct {
	ln net.Listener
	// own reports whether a connection came from this launcher's guest.
	own func(net.Conn) bool
	// fetch asks Intel for a platform's documents.
	fetch func(context.Context, session.CollateralPlatform) ([]session.CollateralDocument, error)
	// dir is where the launchers of one host keep what they fetched, so that
	// a guest is answered with what another guest's launcher fetched. Empty
	// keeps this launcher's own set in memory alone.
	dir  string
	pace stockPace
	log  *slog.Logger
	// now, when set, stands in for the clock.
	now func() time.Time

	mu sync.Mutex
	// named is the platform this launcher's guest named first. A guest's
	// quotes come from one platform, and whoever names a second has its host
	// fetch for nothing.
	named *session.CollateralPlatform
	// held is the newest set this launcher read or fetched.
	held *kept
	// tried is when this launcher last asked Intel.
	tried time.Time
	// flight is a fetch under way, closed when it ends.
	flight chan struct{}
	// answered and failing say what was last logged.
	answered, failing bool
}

func (s *stock) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// run answers the guest's asks until ctx ends.
func (s *stock) run(ctx context.Context) {
	stop := context.AfterFunc(ctx, func() { _ = s.ln.Close() })
	defer stop()
	go s.warm(ctx)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			s.log.Warn("the guest's ask for Intel's collateral was not taken", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(stockPause):
			}
			continue
		}
		// The port is the host's, and every guest on the host reaches it.
		if !s.own(conn) {
			_ = conn.Close()
			continue
		}
		// One at a time: a guest has one asker.
		s.answer(ctx, conn)
	}
}

// warm fetches anew the set the host's last guest was answered with, so that
// this guest's first ask finds it: the guests of one host name one platform.
func (s *stock) warm(ctx context.Context) {
	platform, ok := newestKept(s.dir)
	if !ok {
		return
	}
	if _, fresh := s.look(platform); !fresh {
		<-s.refresh(ctx, platform)
	}
}

// answer takes one connection of the guest's: its line, then the documents
// for the platform it names, or nothing when the launcher has none.
func (s *stock) answer(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetReadDeadline(time.Now().Add(s.pace.line))
	platform, err := readPlatform(conn)
	if err != nil {
		s.log.Debug("the guest's ask named no platform", "error", err)
		return
	}
	if !s.adopt(platform) {
		return
	}
	blob := s.current(ctx, platform)
	if len(blob) == 0 {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(s.pace.answer))
	if _, err := conn.Write(blob); err != nil {
		return
	}
	s.mu.Lock()
	first := !s.answered
	s.answered = true
	s.mu.Unlock()
	if first {
		s.log.Info("answered the guest with Intel's collateral for its platform")
	}
}

// readPlatform reads which platform the guest says it is. What a guest says
// decides what its host fetches, so it is held to the two values of a fixed
// shape that Intel's URLs are built from.
func readPlatform(conn io.Reader) (session.CollateralPlatform, error) {
	var platform session.CollateralPlatform
	line, err := bufio.NewReaderSize(io.LimitReader(conn, maxPlatformLine), maxPlatformLine).ReadBytes('\n')
	if err != nil {
		return platform, fmt.Errorf("a line of %d bytes and no end", len(line))
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&platform); err != nil {
		return platform, err
	}
	if _, err := platform.URLs(); err != nil {
		return platform, err
	}
	return platform, nil
}

// adopt reports whether platform is the one this guest named first.
func (s *stock) adopt(platform session.CollateralPlatform) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.named == nil {
		s.named = &platform
		return true
	}
	return *s.named == platform
}

// current is the set a guest's ask is answered with: the one held while it
// is fresh, or else what a fetch brings within the time an ask waits, or
// else the one held although it is old. A verifier holds each document to
// Intel's date on it, so an old set costs at most what none does.
func (s *stock) current(ctx context.Context, platform session.CollateralPlatform) []byte {
	if blob, fresh := s.look(platform); fresh {
		return blob
	}
	select {
	case <-s.refresh(ctx, platform):
	case <-time.After(s.pace.hold):
	case <-ctx.Done():
	}
	blob, _ := s.look(platform)
	return blob
}

// look returns the newest set for platform that this launcher holds or the
// host's launchers keep, and whether it is fresh.
func (s *stock) look(platform session.CollateralPlatform) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	fresh := func(k *kept) bool {
		if k == nil || k.platform != platform {
			return false
		}
		// A set dated ahead of the clock says nothing of its age.
		age := now.Sub(k.at)
		return age >= 0 && age < s.pace.fresh
	}
	if !fresh(s.held) {
		if other := readKept(s.dir, platform); other != nil &&
			(s.held == nil || s.held.platform != platform || other.at.After(s.held.at)) {
			s.held = other
		}
	}
	if s.held == nil || s.held.platform != platform {
		return nil, false
	}
	return s.held.blob, fresh(s.held)
}

// refresh starts a fetch for platform unless one is under way, and returns
// what closes when it ends.
func (s *stock) refresh(ctx context.Context, platform session.CollateralPlatform) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flight != nil {
		return s.flight
	}
	done := make(chan struct{})
	s.flight = done
	go func() {
		defer func() {
			s.mu.Lock()
			s.flight = nil
			s.mu.Unlock()
			close(done)
		}()
		// A fetch outlives the ask that started it: the next ask finds what
		// it brought.
		fetching, cancel := context.WithTimeout(ctx, s.pace.fetch)
		defer cancel()
		err := s.fetchAnew(fetching, platform)
		s.mu.Lock()
		was := s.failing
		s.failing = err != nil
		s.mu.Unlock()
		if err != nil && !was && ctx.Err() == nil {
			s.log.Warn("the guest goes without fresh collateral from Intel for now, and its verifiers ask Intel", "error", err)
		}
	}()
	return done
}

// fetchAnew asks Intel for platform's documents and keeps them, unless
// another launcher of the host did so meanwhile.
func (s *stock) fetchAnew(ctx context.Context, platform session.CollateralPlatform) (err error) {
	unlock, err := lockKept(ctx, s.dir, platform)
	if err != nil {
		return err
	}
	defer unlock()
	if _, fresh := s.look(platform); fresh {
		return nil
	}
	defer func() {
		if err != nil {
			forgetLock(s.dir, platform)
		}
	}()
	s.mu.Lock()
	now := s.clock()
	soon := !s.tried.IsZero() && now.Sub(s.tried) < s.pace.retry
	if !soon {
		s.tried = now
	}
	s.mu.Unlock()
	if soon {
		return errors.New("this launcher asked Intel a moment ago")
	}
	docs, err := s.fetch(ctx, platform)
	if err != nil {
		return fmt.Errorf("fetch Intel's collateral: %w", err)
	}
	blob, err := json.Marshal(session.CollateralResponse{Documents: docs})
	if err != nil {
		return err
	}
	if len(blob) > session.MaxCollateralBytes {
		return fmt.Errorf("the collateral is %d bytes, and a guest takes %d", len(blob), session.MaxCollateralBytes)
	}
	set := &kept{platform: platform, blob: blob, at: s.clock()}
	if err := writeKept(s.dir, set); err != nil {
		// This launcher's guest is still answered from memory.
		s.log.Warn("Intel's collateral was not kept for the host's other launchers", "error", err)
	}
	s.mu.Lock()
	s.held = set
	s.mu.Unlock()
	return nil
}

// keptName is the file name of a platform's set. URLs holds both values to a
// fixed shape, so the name leaves the directory by no path.
func keptName(platform session.CollateralPlatform) string {
	return platform.FMSPC + "-" + platform.CA
}

const keptSuffix, lockSuffix = ".json", ".lock"

// readKept reads the set the host's launchers keep for platform, dated by
// when it was written. Nil is none.
func readKept(dir string, platform session.CollateralPlatform) *kept {
	if dir == "" {
		return nil
	}
	f, err := os.Open(filepath.Join(dir, keptName(platform)+keptSuffix))
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	blob, err := readutil.ReadAll(f, session.MaxCollateralBytes)
	if err != nil || len(blob) == 0 {
		return nil
	}
	return &kept{platform: platform, blob: blob, at: info.ModTime()}
}

// writeKept keeps a set for the host's other launchers.
func writeKept(dir string, set *kept) error {
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, keptName(set.platform)+keptSuffix)
	if err := fileutil.WriteAtomic(path, set.blob, 0o600); err != nil {
		return err
	}
	return os.Chtimes(path, set.at, set.at)
}

// newestKept is the platform of the set the host's launchers wrote last.
func newestKept(dir string) (session.CollateralPlatform, bool) {
	var newest session.CollateralPlatform
	if dir == "" {
		return newest, false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return newest, false
	}
	var at time.Time
	found := false
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), keptSuffix)
		if !ok {
			continue
		}
		fmspc, ca, ok := strings.Cut(name, "-")
		if !ok {
			continue
		}
		platform := session.CollateralPlatform{FMSPC: fmspc, CA: ca}
		if _, err := platform.URLs(); err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if !found || info.ModTime().After(at) {
			newest, at, found = platform, info.ModTime(), true
		}
	}
	return newest, found
}

// lockKept makes this launcher the one of its host that fetches platform's
// documents, and returns what lets the next one in. It waits for another
// launcher that holds the place until ctx ends.
func lockKept(ctx context.Context, dir string, platform session.CollateralPlatform) (func(), error) {
	if dir == "" {
		return func() {}, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, keptName(platform)+lockSuffix), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		held, err := tryLock(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		if held {
			return func() { f.Close() }, nil
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("another launcher is still fetching: %w", ctx.Err())
		case <-time.After(lockPoll):
		}
	}
}

// forgetLock removes the lock file of a platform no set is kept for, so that
// a guest that names a platform Intel knows nothing of leaves no file behind.
// Whoever waits on the removed file may fetch beside whoever makes it anew:
// that costs Intel a second question and nothing else.
func forgetLock(dir string, platform session.CollateralPlatform) {
	if dir == "" {
		return
	}
	if _, err := os.Stat(filepath.Join(dir, keptName(platform)+keptSuffix)); errors.Is(err, fs.ErrNotExist) {
		_ = os.Remove(filepath.Join(dir, keptName(platform)+lockSuffix))
	}
}

// collateralStock listens for this launcher's guest and answers its asks.
// The port it returns is what the guest dials.
func collateralStock(cfg *Config, cid uint32, log *slog.Logger) (*stock, uint32, error) {
	ln, err := vsock.Listen(vsock.AnyPort, asked)
	if err != nil {
		return nil, 0, err
	}
	return &stock{
		ln:    ln,
		own:   func(conn net.Conn) bool { peer, ok := conn.(*vsock.Conn); return ok && peer.Peer() == cid },
		fetch: cfg.sim.fetcher(), dir: cfg.sim.stockDir(cfg.CollateralCache), pace: collateralPace, log: log,
	}, ln.Port(), nil
}
