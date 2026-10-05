package keyservice

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// Members keeps a binder's verdict on the replicas of the key service it
// pins, made ahead of its binds, so that naming them costs a bind nothing.
//
// A bind that names a key service names the replicas its binder judged
// (session.BindKeyService), and its guest then deals with no other. The
// binder judges a replica as it judges a guest it seals a secret to: on the
// vendor's documents as its engine fetched them from the vendor within the
// last hour. Such a verdict stands for an hour from that fetch, and only
// while the engine holds no newer document, so the binder judges again as
// the documents are replaced: see KeepCurrent.
//
// A key service of milestone 1 is one replica, so what is kept is the
// replica that answered last.
type Members struct {
	client *Client
	engine session.Engine
	now    func() time.Time

	// judging makes one judgment at a time.
	judging sync.Mutex
	mu      sync.Mutex
	kept    *Member
	// documents is the engine's count of the vendor's documents when kept
	// was made.
	documents uint64
}

// NewMembers returns a keeper of verdicts on the replicas of opts.Pin. The
// options are a binder's: it presents no certificate, and judges under no
// context that lets in a document somebody handed over.
func NewMembers(opts Options) (*Members, error) {
	if opts.Certificate != nil || opts.Judging != nil {
		return nil, errors.New("a binder judges a key service's replicas as itself, on the vendor's documents as it fetched them")
	}
	client, err := NewClient(opts)
	if err != nil {
		return nil, err
	}
	return &Members{client: client, engine: opts.Engine, now: client.opts.Now}, nil
}

// Close ends the keeper's connection.
func (m *Members) Close() { m.client.Close() }

// counted is the engine's count of the vendor's documents it came to hold.
// An engine that counts none judges by none.
func (m *Members) counted() uint64 {
	if counter, ok := m.engine.(session.DocumentCounter); ok {
		return counter.Documents()
	}
	return 0
}

// Judge reaches the key service over a new connection, judges the replica
// that answers, and keeps the verdict in place of the one before. A replica
// that is refused leaves the binder with no verdict. One that could not be
// reached or judged, for want of a document, leaves the verdict before for
// what is left of its time.
func (m *Members) Judge(ctx context.Context) (*Member, error) {
	m.judging.Lock()
	defer m.judging.Unlock()
	var member *Member
	var documents uint64
	// A verdict made while the engine was still taking documents in rests on
	// one or another of them, so it is made once more.
	for range 2 {
		before := m.counted()
		judged, err := m.client.Member(ctx)
		if err != nil {
			var refused *session.VerificationError
			if errors.As(err, &refused) {
				m.mu.Lock()
				m.kept = nil
				m.mu.Unlock()
			}
			return nil, err
		}
		member, documents = judged, m.counted()
		if documents == before {
			break
		}
	}
	m.mu.Lock()
	m.kept, m.documents = member, documents
	m.mu.Unlock()
	return member, nil
}

// stands is the kept verdict if it still stands: within its time, and made
// on the newest documents the engine holds.
func (m *Members) stands() *Member {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.kept == nil || !m.now().Before(m.kept.Until) || m.documents != m.counted() {
		return nil
	}
	return m.kept
}

// Named is what a bind names as its key service's replicas: the instance
// keys of those the binder holds a verdict on that stands. With none, it
// judges now, on the path of its caller.
func (m *Members) Named(ctx context.Context) ([]string, error) {
	if kept := m.stands(); kept != nil {
		return []string{kept.Key}, nil
	}
	member, err := m.Judge(ctx)
	if err != nil {
		return nil, err
	}
	return []string{member.Key}, nil
}

// KeepCurrent judges the key service's replica again every
// session.RefreshEvery until ctx ends, off the path of any bind: what a
// binder runs beside its binds. Each judgment is over a new connection, so a
// replica that came back under another key is learned of within that time.
// judged, when set, is told of each judgment that failed.
func (m *Members) KeepCurrent(ctx context.Context, judged func(took time.Duration, err error)) {
	tick := time.NewTicker(session.RefreshEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		began := time.Now()
		_, err := m.Judge(ctx)
		if judged != nil && err != nil && ctx.Err() == nil {
			judged(time.Since(began), err)
		}
	}
}
