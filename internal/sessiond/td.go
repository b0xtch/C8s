package sessiond

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// State is where a TD is in its life. A TD moves forward only, except that a
// claim nobody binds returns it to ready, and every end is final.
type State string

const (
	StateBooting State = "booting"
	StateReady   State = "ready"
	StateClaimed State = "claimed"
	// StateBound is a TD that was sent a bind whose answer is not known yet.
	StateBound   State = "bound"
	StateRunning State = "running"
	StateEnded   State = "ended"
)

const (
	recordFile = "td.json"
	// maxRecordBytes bounds a record: two kept answers, each with a quote and
	// the vendor's documents.
	maxRecordBytes = 4 << 20
	// keptReleases is how many claims that ended unbound a TD remembers, to
	// tell a repeat of one, or of the request that gave it back, what became
	// of it.
	keptReleases = 8
)

// record is what the daemon keeps of a TD on disk, so that a daemon started
// later finds the TD and answers a repeated request as the first was
// answered.
type record struct {
	ID      string    `json:"id"`
	Pool    string    `json:"pool"`
	State   State     `json:"state"`
	Slot    int       `json:"slot"`
	Created time.Time `json:"created"`
	Handle  Handle    `json:"handle"`
	Address string    `json:"address,omitempty"`
	Claim   *claim    `json:"claim,omitempty"`
	// Released are the claims that ended unbound, after which the TD
	// returned to its pool.
	Released []released `json:"released,omitempty"`
	Bind     *bound     `json:"bind,omitempty"`
	Ended    *ended     `json:"ended,omitempty"`
}

// released is a claim that ended with no bind sent: its grace ran out, or
// its session was destroyed.
type released struct {
	// Claim is the request that made the claim, and Destroy the request that
	// gave it back, or empty for one that lapsed.
	Claim   string `json:"claim"`
	Destroy string `json:"destroy,omitempty"`
	Session string `json:"session"`
}

type claim struct {
	RequestID string    `json:"requestId"`
	Session   string    `json:"session"`
	BindBy    time.Time `json:"bindBy"`
	// Answer is the first answer, which a repeat of the request gets.
	Answer []byte `json:"answer,omitempty"`
	// ByBind says a bind made the claim, with no Claim before it and no
	// grace: RequestID is then that bind's. Binder is the key of the binder
	// that sent it, as its pool names it, or empty for an orchestrator.
	ByBind bool   `json:"byBind,omitempty"`
	Binder string `json:"binder,omitempty"`
}

type bound struct {
	RequestID string `json:"requestId"`
	// Digest names the bind and the signature the request carried.
	Digest string `json:"digest"`
	Answer []byte `json:"answer,omitempty"`
}

type ended struct {
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
	// RequestID is the Destroy that ended the TD, if one did.
	RequestID string `json:"requestId,omitempty"`
}

// td is a TD as the running daemon holds it. The daemon's lock guards it.
type td struct {
	rec  record
	inst Instance
	// ctx ends with the TD, and its streams with it.
	ctx    context.Context
	cancel context.CancelFunc
	lapse  *time.Timer
	// busy marks a call that is talking to the guest about a claim or a bind.
	busy bool
	// gone is set once the TD's process is no more: its slot and its share of
	// the host's capacity are free.
	gone bool
	// guests is how the daemon talks to this TD's guest, over connections
	// of this TD's own. The next TD in its slot has its address, and a
	// connection kept from one guest must never carry a request to another:
	// it would wait on a guest that is gone until the kernel gave up on it.
	guests *guestClient
	// offered is what the guest said of itself when it became ready, leaf
	// the certificate it said it under, and collateral the vendor's
	// documents as it last handed them over. A claim relays all three as
	// they are kept and asks the guest nothing: what a ready guest says of
	// itself does not change before a bind. None outlives the daemon.
	offered    *session.StateResponse
	leaf       []byte
	collateral []byte
	// instanceKey is the digest of the key leaf carries: what a bind names
	// its TD by.
	instanceKey string
	// asking is the request for the guest's evidence that is in flight, and
	// asksNext the one that waits for it to end: see asked. Either is nil
	// when there is none.
	asking, asksNext *asked
}

// serves notes what a ready guest said of itself, and the certificate it
// said it under. The caller holds the daemon's lock.
func (t *td) serves(offered *session.StateResponse, leaf []byte) {
	t.offered, t.leaf, t.instanceKey = offered, leaf, ""
	if cert, err := x509.ParseCertificate(leaf); err == nil {
		t.instanceKey, _ = session.InstanceKeyDigest(cert.PublicKey)
	}
}

// session is the session the TD serves or served, or "".
func (t *td) session() string {
	if t.rec.Claim == nil {
		return ""
	}
	return t.rec.Claim.Session
}

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	// Unguessable: whoever names a TD was told its name.
	return "td-" + hex.EncodeToString(raw[:]), nil
}

func (d *Daemon) dir(id string) string { return filepath.Join(d.cfg.StateDir, "tds", id) }

// save writes the TD's record. The caller holds the lock.
func (d *Daemon) save(t *td) error {
	data, err := json.Marshal(&t.rec)
	if err != nil {
		return err
	}
	if err := fileutil.WriteAtomic(filepath.Join(d.dir(t.rec.ID), recordFile), data, 0o600); err != nil {
		return fmt.Errorf("keep the record of %s: %w", t.rec.ID, err)
	}
	return nil
}

// load reads the records an earlier daemon left.
func (d *Daemon) load() ([]record, error) {
	root := filepath.Join(d.cfg.StateDir, "tds")
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []record
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		data, err := session.ReadBounded(filepath.Join(root, entry.Name(), recordFile), maxRecordBytes)
		if err != nil {
			// A directory without a record is a boot that never got that far.
			d.log.Warn("a TD directory holds no usable record and is removed", "td", entry.Name(), "error", err)
			_ = os.RemoveAll(filepath.Join(root, entry.Name()))
			continue
		}
		var rec record
		if err := json.Unmarshal(data, &rec); err != nil || rec.ID != entry.Name() {
			d.log.Warn("a TD's record does not parse and is removed", "td", entry.Name(), "error", err)
			_ = os.RemoveAll(filepath.Join(root, entry.Name()))
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}
