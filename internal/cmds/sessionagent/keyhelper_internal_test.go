package sessionagent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// served is a key helper at the other end of a pipe, with what it returned
// once it has.
type servedKeys struct {
	conn net.Conn
	done chan error
}

func serveKeysOnAPipe(t *testing.T) *servedKeys {
	t.Helper()
	ours, theirs := net.Pipe()
	s := &servedKeys{conn: ours, done: make(chan error, 1)}
	go func() {
		err := serveKeys(theirs)
		_ = theirs.Close()
		s.done <- err
	}()
	t.Cleanup(func() { _ = ours.Close() })
	_ = ours.SetDeadline(time.Now().Add(30 * time.Second))
	return s
}

// ended is what the helper returned, which it must have by now.
func (s *servedKeys) ended(t *testing.T) error {
	t.Helper()
	select {
	case err := <-s.done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the key helper did not return")
		return nil
	}
}

// keys reads the helper's first word.
func (s *servedKeys) keys(t *testing.T) session.OneTimeKeys {
	t.Helper()
	tag, payload, err := readFrame(s.conn, 16<<10)
	if err != nil || tag != helperKeys || len(payload) <= ed25519.PublicKeySize {
		t.Fatalf("the helper's first word: tag %q, %d bytes, %v", tag, len(payload), err)
	}
	keys := session.OneTimeKeys{Signing: payload[:ed25519.PublicKeySize], KEM: payload[ed25519.PublicKeySize:]}
	if err := keys.Validate(); err != nil {
		t.Fatal(err)
	}
	return keys
}

// sealedTo seals text to the helper's KEM key under info, as a binder seals
// a message, and returns what the helper is sent to open.
func sealedTo(t *testing.T, keys session.OneTimeKeys, info, text []byte) []byte {
	t.Helper()
	key, err := hpke.MLKEM768X25519().NewPublicKey(keys.KEM)
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := hpke.NewSender(key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sender.Seal(nil, text)
	if err != nil {
		t.Fatal(err)
	}
	return append(enc, ciphertext...)
}

func openRequest(info, sealed []byte) [][]byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(info)))
	return [][]byte{size[:], info, sealed}
}

// The helper makes the keys, signs one message and opens one sealed message
// for its agent, and returns once it has done both: its caller exits then.
func TestKeyHelperSignsOnceAndOpensOnce(t *testing.T) {
	ours, theirs := net.Pipe()
	done := make(chan error, 1)
	go func() {
		err := serveKeys(theirs)
		_ = theirs.Close()
		done <- err
	}()
	h := newKeyHelper(ours, func() error { return <-done })
	keys, err := h.keys()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Validate(); err != nil {
		t.Fatal(err)
	}
	message := []byte("the one receipt")
	signature, err := h.sign(message)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(keys.Signing, message, signature) {
		t.Fatal("the helper's signature does not verify under the key it named")
	}
	if h.gone() || h.kemGone() {
		t.Fatal("the helper is done before it was asked to open anything")
	}
	if _, err := h.sign(message); err == nil {
		t.Fatal("the helper's agent asked it to sign twice")
	}
	info, text := []byte("under this bind"), []byte(`{"command":null}`)
	opened, secret, err := h.open(info, sealedTo(t, keys, info, text))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, text) || len(secret) != 32 || bytes.Equal(secret, make([]byte, 32)) {
		t.Fatalf("opened %q with a secret of %d bytes", opened, len(secret))
	}
	if _, _, err := h.open(info, sealedTo(t, keys, info, text)); !errors.Is(err, errKEMGone) {
		t.Fatalf("a second message: %v", err)
	}
	// Both done: the helper ends by itself, and that is no surprise.
	died := make(chan error, 1)
	h.onDeath(func(err error) { died <- err })
	if err := h.finish(); err != nil {
		t.Fatalf("the helper went badly: %v", err)
	}
	if !h.gone() {
		t.Fatal("finish returned before the helper was gone")
	}
	select {
	case err := <-died:
		t.Fatalf("the agent was told its helper died: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
}

// A sealed message that does not open is said not to, and uses the key up
// as one that opens does: the helper tries one message or none.
func TestKeyHelperSaysWhatDoesNotOpen(t *testing.T) {
	h, err := pipeKeyHelper()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := h.keys()
	if err != nil {
		t.Fatal(err)
	}
	info := []byte("under this bind")
	if _, _, err := h.open([]byte("under another"), sealedTo(t, keys, info, []byte("{}"))); !errors.Is(err, errHelperUnopened) {
		t.Fatalf("a message sealed under other info: %v", err)
	}
	if !h.kemGone() {
		t.Fatal("the KEM key outlived the message it was tried on")
	}
	if _, _, err := h.open(info, sealedTo(t, keys, info, []byte("{}"))); !errors.Is(err, errKEMGone) {
		t.Fatalf("a second message: %v", err)
	}
	// It still signs its receipt.
	if _, err := h.sign([]byte("the one receipt")); err != nil {
		t.Fatal(err)
	}
	if err := h.finish(); err != nil {
		t.Fatal(err)
	}
}

// Asked for either a second time, or for anything else, the helper answers
// nothing and returns an error, for its caller to exit on.
func TestKeyHelperDoesNothingElse(t *testing.T) {
	info := []byte("under this bind")
	for name, ask := range map[string]func(t *testing.T, s *servedKeys, keys session.OneTimeKeys){
		"a second signature": func(t *testing.T, s *servedKeys, _ session.OneTimeKeys) {
			if err := writeFrame(s.conn, helperSign, []byte("one")); err != nil {
				t.Fatal(err)
			}
			if tag, _, err := readFrame(s.conn, 64); err != nil || tag != helperSigned {
				t.Fatalf("the first signature: %q, %v", tag, err)
			}
			_ = writeFrame(s.conn, helperSign, []byte("two"))
		},
		"a second message": func(t *testing.T, s *servedKeys, keys session.OneTimeKeys) {
			for i := range 2 {
				if err := writeFrame(s.conn, helperOpen, openRequest(info, sealedTo(t, keys, info, []byte("{}")))...); err != nil && i == 0 {
					t.Fatal(err)
				}
				if i == 0 {
					if tag, _, err := readFrame(s.conn, 1<<20); err != nil || tag != helperOpened {
						t.Fatalf("the first message: %q, %v", tag, err)
					}
				}
			}
		},
		"something it does not do": func(_ *testing.T, s *servedKeys, _ session.OneTimeKeys) {
			_ = writeFrame(s.conn, 'E', []byte("export the keys"))
		},
		"more to sign than a receipt": func(_ *testing.T, s *servedKeys, _ session.OneTimeKeys) {
			_ = writeFrame(s.conn, helperSign, make([]byte, maxHelperSign+1))
		},
		"a message with no info": func(_ *testing.T, s *servedKeys, _ session.OneTimeKeys) {
			_ = writeFrame(s.conn, helperOpen, []byte{0, 0})
		},
		"a frame cut short": func(_ *testing.T, s *servedKeys, _ session.OneTimeKeys) {
			_, _ = s.conn.Write([]byte{helperSign, 0, 0, 0, 9, 'c', 'u', 't'})
			_ = s.conn.Close()
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := serveKeysOnAPipe(t)
			keys := s.keys(t)
			ask(t, s, keys)
			if err := s.ended(t); err == nil {
				t.Fatal("the helper returned as if it had been asked for nothing else")
			}
			// It said nothing more.
			if tag, payload, err := readFrame(s.conn, 1<<20); err == nil {
				t.Fatalf("the helper answered with %q and %d bytes", tag, len(payload))
			}
		})
	}
}

// An agent that is done with its helper closes its end, and the helper
// returns with nothing wrong: whether it was asked for both, one or neither.
func TestKeyHelperEndsWhenItsAgentIsDone(t *testing.T) {
	for name, ask := range map[string]func(h *keyHelper) error{
		"neither": func(*keyHelper) error { return nil },
		"a signature alone": func(h *keyHelper) error {
			_, err := h.sign([]byte("the one receipt"))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, err := pipeKeyHelper()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.keys(); err != nil {
				t.Fatal(err)
			}
			died := make(chan error, 1)
			h.onDeath(func(err error) { died <- err })
			if err := ask(h); err != nil {
				t.Fatal(err)
			}
			if h.gone() {
				t.Fatal("the helper is gone while its agent may still send it a sealed message")
			}
			if err := h.finish(); err != nil {
				t.Fatal(err)
			}
			if !h.gone() {
				t.Fatal("finish returned before the helper was gone")
			}
			if _, err := h.sign([]byte("late")); err == nil {
				t.Fatal("a helper that is gone signed")
			}
			select {
			case err := <-died:
				t.Fatalf("the agent was told its helper died: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

// A helper that ends before its agent has ended it is one that died: the
// agent is told, and gets nothing more of it.
func TestKeyHelperThatDiesIsNoticed(t *testing.T) {
	ours, theirs := net.Pipe()
	died := make(chan error, 1)
	stop := make(chan struct{})
	h := newKeyHelper(ours, func() error {
		<-stop
		_ = theirs.Close()
		return errors.New("signal: killed")
	})
	h.onDeath(func(err error) { died <- err })
	close(stop)
	select {
	case err := <-died:
		if err == nil {
			t.Fatal("a helper that died was said to have ended well")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the agent was not told its helper died")
	}
	if _, err := h.sign([]byte("the one receipt")); err == nil {
		t.Fatal("a dead helper signed")
	}
	if err := h.finish(); err == nil {
		t.Fatal("a helper that died is said to have gone well")
	}
}

// What the helper is asked travels in frames, and one larger than a frame
// may be is refused before its bytes are read.
func TestKeyHelperFramesAreBounded(t *testing.T) {
	var sent bytes.Buffer
	if err := writeFrame(&sent, helperSign, []byte("ab"), []byte("cd")); err != nil {
		t.Fatal(err)
	}
	tag, payload, err := readFrame(bytes.NewReader(sent.Bytes()), 4)
	if err != nil || tag != helperSign || string(payload) != "abcd" {
		t.Fatalf("a frame read back: %q %q %v", tag, payload, err)
	}
	if _, _, err := readFrame(bytes.NewReader(sent.Bytes()), 3); err == nil {
		t.Fatal("a frame over the limit was read")
	}
	if _, _, err := readFrame(bytes.NewReader(nil), 4); !errors.Is(err, io.EOF) {
		t.Fatalf("no frame at all: %v", err)
	}
	if _, _, err := readFrame(bytes.NewReader(sent.Bytes()[:3]), 4); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("a frame cut in its head: %v", err)
	}
}

// The kernel's line on the memory it zeroes is the kernel's own record that
// begins as that line does, and it says the kernel zeroes what it frees only
// where it ends so.
func TestKernelLineOnFreedMemory(t *testing.T) {
	const on, off = "mem auto-init: stack:all(zero), heap alloc:off, heap free:on", "mem auto-init: stack:all(zero), heap alloc:on, heap free:off"
	for record, want := range map[string]string{
		"6,187,412033,-;" + on + "\n":                                                  on,
		"6,187,412033,-;" + off + "\n":                                                 off,
		"6,187,412033,-,caller=T0;" + on + "\n SUBSYSTEM=x\n":                          on,
		"6,188,412040,-;mem auto-init: clearing system memory may take some time...\n": "",
		// What a program writes has a facility of its own, here 1.
		"14,902,1491693,-;" + on + "\n":      "",
		"6,3,0,-;Command line: " + on + "\n": "",
		"x,3,0,-;" + on + "\n":               "",
		on + "\n":                            "",
		"":                                   "",
	} {
		if got := freedMemoryRecord(record); got != want {
			t.Errorf("%q: %q, want %q", record, got, want)
		}
	}
	for line, want := range map[string]bool{
		on:  true,
		off: false,
		"mem auto-init: stack:off, heap alloc:off, heap free:on":        true,
		"mem auto-init: stack:all(zero), heap alloc:on, heap free:on x": false,
		"heap free:on": false,
		"":             false,
	} {
		if got := zeroesFreedMemory(line); got != want {
			t.Errorf("%q: %v, want %v", line, got, want)
		}
	}
}
