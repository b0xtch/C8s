package podagent

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// chain is the guest's measured event chain: the launch-key seed, then one
// extend per event, in an order fixed by the signed launch document.
//
// The chain is a pure function of the launch key and the document, so the
// register itself records how far along it is. Reading it before every extend
// makes each extend exactly-once across agent restarts with no journal file.
type chain struct {
	mu     sync.Mutex
	reg    runtimemeasure.Register
	seed   [runtimemeasure.Size]byte
	events []string
}

func newChain(reg runtimemeasure.Register, launchPubPEM []byte, events []string) *chain {
	return &chain{reg: reg, seed: runtimemeasure.Seed(launchPubPEM), events: events}
}

// position returns how many events the register has absorbed. A register that
// sits on no prefix of the chain was extended by something else and can never
// match a verifier again, so that is fatal.
func (c *chain) position() (int, error) {
	current, err := c.reg.Extension()
	if err != nil {
		return 0, err
	}
	want := c.seed
	for n := 0; ; n++ {
		if bytes.Equal(current, want[:]) {
			return n, nil
		}
		if n == len(c.events) {
			break
		}
		want = runtimemeasure.Extend(want, runtimemeasure.Event(c.events[n]))
	}
	return 0, fmt.Errorf("%w: register %x is on no prefix of this launch's chain", runtimemeasure.ErrRegisterDiverged, current)
}

// advance extends the register until it has absorbed the first n events, and
// confirms the result by reading it back.
func (c *chain) advance(n int) error {
	if n < 0 || n > len(c.events) {
		return fmt.Errorf("chain has %d events, cannot advance to %d", len(c.events), n)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	at, err := c.position()
	if err != nil {
		return err
	}
	for ; at < n; at++ {
		event := runtimemeasure.Event(c.events[at])
		if err := c.reg.Extend(event[:]); err != nil {
			return fmt.Errorf("extend %s: %w", c.events[at], err)
		}
	}
	got, err := c.position()
	if err != nil {
		return err
	}
	if got < n {
		return errors.New("register did not absorb the extend")
	}
	return nil
}
