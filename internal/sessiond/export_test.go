package sessiond

import (
	"crypto"

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
