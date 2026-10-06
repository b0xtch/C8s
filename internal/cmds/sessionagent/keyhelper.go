package sessionagent

import (
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// The guest's key helper holds the private halves of the two one-time keys
// in a process of its own, which the agent starts at boot. It makes the
// keys, says their public halves, signs one message and opens one sealed
// message for the agent, and exits. The agent never holds either private
// half, and erasing both is the helper's exit: the kernel zeroes every page
// it frees. The two talk over one connection, in frames of a tag, a length
// and that many bytes.
const (
	// The helper's first word: the signing key's public half, then the
	// KEM's.
	helperKeys = 'K'
	// A message to sign, and its signature.
	helperSign   = 'S'
	helperSigned = 's'
	// A sealed message to open, led by the length of the info it is opened
	// under and that info. Opened, it comes back as the length of the
	// secret its answer is sealed under, that secret, and what was sealed.
	// One that does not open is said so, with nothing else.
	helperOpen     = 'O'
	helperOpened   = 'o'
	helperUnopened = 'x'

	// What the helper signs is a receipt, and what it opens under is a
	// label and a digest.
	maxHelperSign = 64 << 10
	maxHelperInfo = 1 << 10
	// helperWait bounds an answer of the helper's: it computes, and waits
	// for nothing.
	helperWait = 10 * time.Second
)

func writeFrame(w io.Writer, tag byte, parts ...[]byte) error {
	n := 0
	for _, part := range parts {
		n += len(part)
	}
	frame := make([]byte, 5, 5+n)
	frame[0] = tag
	binary.BigEndian.PutUint32(frame[1:], uint32(n))
	for _, part := range parts {
		frame = append(frame, part...)
	}
	_, err := w.Write(frame)
	clear(frame)
	return err
}

// readFrame reads one frame of at most limit bytes. The other end closing
// before a frame begins is io.EOF.
func readFrame(r io.Reader, limit int) (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, nil, errors.New("a frame ended in its head")
		}
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(head[1:]))
	if n > limit {
		return 0, nil, fmt.Errorf("a frame of %d bytes, where one is at most %d", n, limit)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, errors.New("a frame ended in its bytes")
	}
	return head[0], payload, nil
}

// serveKeys is the helper. It makes the two keys and says their public
// halves on conn, then signs one message and opens one sealed message for
// whoever holds the other end, each once and in either order. It returns
// when both are done or the other end is closed. Asked for anything else,
// or for either a second time, it returns an error and has answered nothing:
// its caller exits, which is what erases the keys.
func serveKeys(conn io.ReadWriter) error {
	// What a bind uses for the first time is used once here, with keys made
	// for that and thrown away, so that the bind does not pay for it.
	if err := session.RehearseOneTime(); err != nil {
		return fmt.Errorf("rehearse the one-time keys' work: %w", err)
	}
	signing, kem := make([]byte, ed25519.PrivateKeySize), make([]byte, kemSeedSize)
	defer clear(signing)
	defer clear(kem)
	var public session.OneTimeKeys
	var err error
	inSecret(func() {
		pub, private, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			err = e
			return
		}
		public.Signing = pub
		copy(signing, private)
		clear(private)
		key, e := hpke.MLKEM768X25519().GenerateKey()
		if e != nil {
			err = e
			return
		}
		seed, e := key.Bytes()
		if e != nil || len(seed) != len(kem) {
			err = errors.Join(errors.New("the hybrid KEM key has no seed of the size its KEM names"), e)
			return
		}
		copy(kem, seed)
		clear(seed)
		public.KEM = key.PublicKey().Bytes()
	})
	if err != nil {
		return err
	}
	if err := writeFrame(conn, helperKeys, public.Signing, public.KEM); err != nil {
		return err
	}
	signed, opened := false, false
	for !signed || !opened {
		tag, payload, err := readFrame(conn, 4+maxHelperInfo+session.MaxSealedBytes)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch {
		case tag == helperSign && !signed && len(payload) <= maxHelperSign:
			signed = true
			signature := make([]byte, ed25519.SignatureSize)
			inSecret(func() { copy(signature, ed25519.Sign(signing, payload)) })
			clear(signing)
			if err := writeFrame(conn, helperSigned, signature); err != nil {
				return err
			}
		case tag == helperOpen && !opened:
			opened = true
			if len(payload) < 4 || int(binary.BigEndian.Uint32(payload)) > min(maxHelperInfo, len(payload)-4) {
				return errors.New("the key helper was sent a sealed message with no info to open it under")
			}
			info := payload[4 : 4+binary.BigEndian.Uint32(payload)]
			sealed := payload[4+len(info):]
			var text, secret []byte
			var failed error
			inSecret(func() {
				key, e := hpke.MLKEM768X25519().NewPrivateKey(kem)
				if e != nil {
					failed = e
					return
				}
				text, secret, failed = session.OpenSealedWithKey(key, info, sealed)
			})
			clear(kem)
			if failed != nil {
				err = writeFrame(conn, helperUnopened)
			} else {
				var size [4]byte
				binary.BigEndian.PutUint32(size[:], uint32(len(secret)))
				err = writeFrame(conn, helperOpened, size[:], secret, text)
				clear(text)
				clear(secret)
			}
			if err != nil {
				return err
			}
		default:
			return errors.New("the key helper was asked for what it does not do")
		}
	}
	return nil
}

// keyHelper is the agent's end of the helper.
type keyHelper struct {
	mu   sync.Mutex
	conn helperConn
	// signed and opened say the helper was asked for each, or that the time
	// for it is over: it does neither twice.
	signed, opened bool
	// leaving says the agent has ended the helper, so that its end is no
	// surprise. ended is closed once it is gone: reaped, its memory freed.
	leaving bool
	ended   chan struct{}
	// err is how it ended, once it has.
	err error
	// pid is the helper's process, where it is one.
	pid int
	// died, when set, is told of an end the agent did not ask for.
	died func(error)
}

// helperConn is the connection to the helper: bytes both ways, with a
// deadline on each exchange.
type helperConn interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

// errHelperUnopened is a sealed message the helper could not open.
var errHelperUnopened = errors.New("the sealed message does not open")

// newKeyHelper is the agent's end of a helper it reaches over conn. wait
// returns once the helper is gone, with how it went.
func newKeyHelper(conn helperConn, wait func() error) *keyHelper {
	h := &keyHelper{conn: conn, ended: make(chan struct{})}
	go func() {
		err := wait()
		h.mu.Lock()
		h.err = err
		expected := h.leaving || h.signed && h.opened
		died := h.died
		h.mu.Unlock()
		close(h.ended)
		if (!expected || err != nil) && died != nil {
			if err == nil {
				err = errors.New("it exited")
			}
			died(err)
		}
	}()
	return h
}

// onDeath has died told when the helper ends without the agent having ended
// it, or ends badly.
func (h *keyHelper) onDeath(died func(error)) {
	h.mu.Lock()
	h.died = died
	h.mu.Unlock()
}

// keys reads the helper's first word: the public halves of the keys it made.
func (h *keyHelper) keys() (session.OneTimeKeys, error) {
	var public session.OneTimeKeys
	payload, err := h.exchange(0, nil, helperKeys, 16<<10)
	if err != nil {
		return public, err
	}
	if len(payload) <= ed25519.PublicKeySize {
		return public, errors.New("the key helper named no keys")
	}
	public.Signing, public.KEM = payload[:ed25519.PublicKeySize], payload[ed25519.PublicKeySize:]
	return public, nil
}

// exchange sends a frame, unless ask is zero, and reads the helper's answer,
// which must carry the tag want. The caller holds no lock: the helper
// answers one request at a time, and mu orders them.
func (h *keyHelper) exchange(ask byte, parts [][]byte, want byte, limit int) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conn == nil {
		return nil, errors.New("the key helper is gone")
	}
	_ = h.conn.SetDeadline(time.Now().Add(helperWait))
	if ask != 0 {
		if err := writeFrame(h.conn, ask, parts...); err != nil {
			return nil, fmt.Errorf("ask the key helper: %w", err)
		}
	}
	tag, payload, err := readFrame(h.conn, limit)
	switch {
	case err != nil:
		return nil, fmt.Errorf("the key helper did not answer: %w", err)
	case tag == helperUnopened && want == helperOpened:
		return nil, errHelperUnopened
	case tag != want:
		return nil, errors.New("the key helper answered something else")
	}
	return payload, nil
}

// sign has the helper sign message with the one-time signing key, which it
// then erases. It signs once.
func (h *keyHelper) sign(message []byte) ([]byte, error) {
	h.mu.Lock()
	was := h.signed
	h.signed = true
	h.mu.Unlock()
	if was {
		return nil, errors.New("the guest's one-time signing key is gone: it signed its one receipt")
	}
	signature, err := h.exchange(helperSign, [][]byte{message}, helperSigned, ed25519.SignatureSize)
	if err == nil && len(signature) != ed25519.SignatureSize {
		err = errors.New("the key helper's signature is none")
	}
	h.release()
	return signature, err
}

// open has the helper open sealed under info with the one-time KEM key,
// which it then erases, and gives what was sealed and the secret the answer
// is sealed under. It opens one message, or none.
func (h *keyHelper) open(info, sealed []byte) (text, secret []byte, err error) {
	h.mu.Lock()
	was := h.opened
	h.opened = true
	h.mu.Unlock()
	if was {
		return nil, nil, errKEMGone
	}
	defer h.release()
	if len(info) > maxHelperInfo || len(sealed) > session.MaxSealedBytes {
		return nil, nil, errHelperUnopened
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(info)))
	payload, err := h.exchange(helperOpen, [][]byte{size[:], info, sealed}, helperOpened, 4+64+session.MaxSealedBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(payload) < 4 || int(binary.BigEndian.Uint32(payload)) > len(payload)-4 {
		return nil, nil, errors.New("the key helper's answer is cut short")
	}
	n := int(binary.BigEndian.Uint32(payload))
	return payload[4+n:], payload[4 : 4+n], nil
}

// noMoreOpens ends the time in which a sealed message is opened: the KEM
// key is used no more.
func (h *keyHelper) noMoreOpens() {
	h.mu.Lock()
	h.opened = true
	h.mu.Unlock()
	h.release()
}

// kemGone reports whether the KEM key is used no more.
func (h *keyHelper) kemGone() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.opened
}

// release closes the connection once the helper has nothing left to do for
// the agent, which is what ends it.
func (h *keyHelper) release() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.signed && h.opened && h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
	}
}

// finish ends the helper, if it has not ended, and returns once it is gone:
// reaped, so that every thread of it has exited and its memory is freed. It
// returns how the helper went: one that was asked for what it does not do,
// or that died, went badly, and nothing of a tenant's runs after it.
func (h *keyHelper) finish() error {
	h.mu.Lock()
	h.leaving, h.signed, h.opened = true, true, true
	if h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
	}
	h.mu.Unlock()
	select {
	case <-h.ended:
	case <-time.After(helperWait):
		return errors.New("the key helper did not end")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}

// gone reports whether the helper has been reaped.
func (h *keyHelper) gone() bool {
	select {
	case <-h.ended:
		return true
	default:
		return false
	}
}
