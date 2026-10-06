package sessiond

import (
	"crypto"
	"os"
	"path/filepath"
	"sync"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// MaxWatchers is how many streams the daemon lets watch its pools at once.
const MaxWatchers = maxWatchers

// MaxEventWatchers is how many streams the daemon lets watch its TDs at once.
const MaxEventWatchers = maxEventWatchers

// HoldEvidenceRelays takes every place the daemon has for the evidence
// requests of the caller that presents a certificate of key, as that many
// requests of its own in flight would, until the returned function is
// called.
func (d *Daemon) HoldEvidenceRelays(key crypto.PublicKey) (release func()) {
	name, err := session.InstanceKeyDigest(key)
	if err != nil {
		panic(err)
	}
	var held []func()
	for range maxCallerRelays {
		leave := d.relays.enter("key " + name)
		if leave == nil {
			panic("the caller's places were taken before the test took them")
		}
		held = append(held, leave)
	}
	return func() {
		for _, leave := range held {
			leave()
		}
	}
}

// KeepCollateral has the daemon keep documents as the vendor's documents
// that td's guest last handed over.
func (d *Daemon) KeepCollateral(td string, documents []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tds[td].collateral = documents
}

// HoldRecords has every write of td's record wait, as a slow disk would hold
// it. reached is sent to each time a write of that record comes to the disk
// and waits, next lets the one that waits through, and release lets every
// write through from then on.
func (d *Daemon) HoldRecords(td string) (reached <-chan struct{}, next, release func()) {
	waiting, pass, open := make(chan struct{}, 16), make(chan struct{}), make(chan struct{})
	write := func(path string, data []byte, mode os.FileMode) error {
		if filepath.Base(filepath.Dir(path)) == td {
			select {
			case <-open:
			default:
				waiting <- struct{}{}
				select {
				case <-pass:
				case <-open:
				}
			}
		}
		return fileutil.WriteAtomic(path, data, mode)
	}
	d.writeFile.Store(&write)
	return waiting, func() { pass <- struct{}{} }, sync.OnceFunc(func() { close(open) })
}

// SaveOutOfOrder asks for two saves of td's record, the second after its
// state was set to later, and writes the second before the first, as two
// calls might reach the disk. It returns the state the record's file names.
func (d *Daemon) SaveOutOfOrder(td string, later State) (State, error) {
	d.mu.Lock()
	t := d.tds[td]
	was := t.rec.State
	first := t.snapshot()
	t.rec.State = later
	second := t.snapshot()
	t.rec.State = was
	d.mu.Unlock()
	for _, k := range []kept{second, first} {
		if err := d.write(t, k); err != nil {
			return "", err
		}
	}
	records, err := d.load()
	if err != nil {
		return "", err
	}
	for _, rec := range records {
		if rec.ID == td {
			return rec.State, nil
		}
	}
	return "", os.ErrNotExist
}

// StateOf is the state the daemon holds td in, or "" for a TD it does not
// hold.
func (d *Daemon) StateOf(td string) State {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.tds[td]; ok {
		return t.rec.State
	}
	return ""
}
