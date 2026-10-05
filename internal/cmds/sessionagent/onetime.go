package sessionagent

import (
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"errors"
	"runtime"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// oneTime holds the private halves of the two keys a guest makes for its one
// bind (session.OneTimeKeys), from boot until the bind has used them. Each is
// kept in one place, which is zeroed when the key is erased, and is worked
// with in the runtime's secret mode where the build has it: the registers
// and the stack the work used are erased as it returns, and what it
// allocated is erased when it is collected, which collect sees to.
//
// Code that breaks out of the session's sandbox can read this process. By
// then both keys are gone: the signing key before the guest takes anything
// for the tenant, the KEM key before the sandbox runs, and what either left
// on the heap before the sandbox is started.
type oneTime struct {
	// public are the public halves, which the guest serves for as long as
	// it lives.
	public session.OneTimeKeys

	mu sync.Mutex
	// signing is the Ed25519 private key, nil once erased.
	signing []byte
	// kem is the seed of the hybrid KEM key, nil once erased.
	kem []byte
	// used says work on a key has left something on the heap since the last
	// collection.
	used bool
}

// spentKey is an Ed25519 key that is no secret: the one of the all-zero
// seed. See sign.
var spentKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

// kemSeedSize is the size of the hybrid KEM's private key as it is kept: the
// seed its two halves are derived from.
const kemSeedSize = 32

// newOneTime makes the two keys.
func newOneTime() (*oneTime, error) {
	o := &oneTime{
		signing: make([]byte, ed25519.PrivateKeySize),
		kem:     make([]byte, kemSeedSize),
	}
	o.public.Signing = make([]byte, ed25519.PublicKeySize)
	var err error
	inSecret(func() {
		public, private, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			err = e
			return
		}
		copy(o.public.Signing, public)
		copy(o.signing, private)
		clear(private)
		key, e := hpke.MLKEM768X25519().GenerateKey()
		if e != nil {
			err = e
			return
		}
		seed, e := key.Bytes()
		if e != nil || len(seed) != len(o.kem) {
			err = errors.Join(errors.New("the hybrid KEM key has no seed of the size its KEM names"), e)
			return
		}
		copy(o.kem, seed)
		clear(seed)
		o.public.KEM = key.PublicKey().Bytes()
	})
	if err != nil {
		return nil, err
	}
	// What making the keys left on the heap is erased when it is collected,
	// and a boot has the time to see to that now.
	o.used = true
	o.collect()
	if err := o.public.Validate(); err != nil {
		return nil, err
	}
	return o, nil
}

// collect has the runtime erase what work on the keys left on the heap since
// it last did: that memory is erased when the collector finds it
// unreachable, and a collection is what makes it look. It returns when that
// is done, at once if nothing was left.
func (o *oneTime) collect() {
	o.mu.Lock()
	due := o.used
	o.used = false
	o.mu.Unlock()
	if due {
		runtime.GC()
	}
}

// sign signs message with the one-time signing key and erases the key. It
// signs once: a second call finds no key.
func (o *oneTime) sign(message []byte) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.signing == nil {
		return nil, errors.New("the guest's one-time signing key is gone: it signed its one receipt")
	}
	signature := make([]byte, ed25519.SignatureSize)
	inSecret(func() {
		copy(signature, ed25519.Sign(o.signing, message))
		// The library keeps what it derived from a key for as long as the
		// bytes it was handed live, by where they are. A signature from the
		// same place under a key that is no secret takes that entry over, so
		// what was derived from the one-time key is garbage as of now, and is
		// erased with the rest at the next collection.
		copy(o.signing, spentKey)
		_ = ed25519.Sign(o.signing, nil)
	})
	clear(o.signing)
	o.signing, o.used = nil, true
	return signature, nil
}

// eraseKEM erases the one-time KEM key.
func (o *oneTime) eraseKEM() {
	o.mu.Lock()
	defer o.mu.Unlock()
	clear(o.kem)
	o.kem = nil
}

// gone reports whether both keys are erased.
func (o *oneTime) gone() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.signing == nil && o.kem == nil
}
