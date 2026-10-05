//go:build goexperiment.runtimesecret && linux && (amd64 || arm64)

package sessionagent

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// mask hides a needle from the scan that looks for it: the test keeps what it
// searches for under this byte, so that the only place the bytes themselves
// can be found is where the code under test left them.
const mask = 0x5a

// needle is a byte string to look for in this process's memory, kept masked.
type needle struct {
	name   string
	masked []byte
}

// masks copies secret into a needle. It runs in secret mode, so the copy it
// reads from leaves nothing behind either.
func masks(name string, secret []byte) needle {
	n := needle{name: name, masked: make([]byte, len(secret))}
	for i, b := range secret {
		n.masked[i] = b ^ mask
	}
	return n
}

// found scans every readable private mapping of this process for each
// needle and returns the names of those it finds.
func found(t *testing.T, needles []needle) []string {
	t.Helper()
	maps, err := os.Open("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	defer maps.Close()
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()
	const chunk = 1 << 20
	longest := 0
	for _, n := range needles {
		longest = max(longest, len(n.masked))
	}
	// One buffer for the whole scan, cleared after each read: a copy of a
	// secret made by looking for it must not be what the next look finds.
	buf := make([]byte, chunk+longest)
	defer clear(buf)
	hits := map[string]bool{}
	lines := bufio.NewScanner(maps)
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "r") || fields[1][3] != 'p' {
			continue
		}
		// The kernel's own pages in the process read as errors or hold
		// nothing of the process.
		if len(fields) >= 6 && (fields[5] == "[vvar]" || fields[5] == "[vsyscall]" || fields[5] == "[vdso]" || fields[5] == "[vvar_vclock]") {
			continue
		}
		from, to, ok := strings.Cut(fields[0], "-")
		start, err1 := strconv.ParseUint(from, 16, 64)
		end, err2 := strconv.ParseUint(to, 16, 64)
		if !ok || err1 != nil || err2 != nil {
			t.Fatalf("a mapping the test cannot read: %q", lines.Text())
		}
		for at := start; at < end; at += chunk {
			size := min(uint64(len(buf)), end-at)
			n, err := mem.ReadAt(buf[:size], int64(at))
			if n == 0 && err != nil {
				// A guard page, or a mapping that went away meanwhile.
				continue
			}
			for _, nd := range needles {
				if hits[nd.name] {
					continue
				}
				if containsMasked(buf[:n], nd.masked) {
					hits[nd.name] = true
				}
			}
			clear(buf[:n])
		}
	}
	if err := lines.Err(); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, nd := range needles {
		if hits[nd.name] {
			names = append(names, nd.name)
		}
	}
	return names
}

// containsMasked reports whether data holds the bytes that masked hides.
func containsMasked(data, masked []byte) bool {
	if len(masked) == 0 || len(data) < len(masked) {
		return false
	}
	first := masked[0] ^ mask
	for i := 0; i+len(masked) <= len(data); i++ {
		at := bytes.IndexByte(data[i:len(data)-len(masked)+1], first)
		if at < 0 {
			return false
		}
		i += at
		match := true
		for j := 1; j < len(masked); j++ {
			if data[i+j] != masked[j]^mask {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// What a guest's one-time keys leave in its process once they are erased is
// nothing: not the keys where they were kept, and not what signing with one
// or expanding the other put on a stack or on the heap. A session that broke
// out of its sandbox reads this process's memory and finds no key that signs
// a receipt, and none that opens a command sealed to the guest.
func TestErasedOneTimeKeysLeaveNothingInMemory(t *testing.T) {
	if !erasesTemporaries {
		t.Fatal("this build does not erase what work on a secret leaves behind")
	}
	keys, err := newOneTime()
	if err != nil {
		t.Fatal(err)
	}
	var needles []needle
	// expanded is the KEM key as the library holds it once it is used, kept
	// alive until the first scan so that the scan shows what it looks like.
	var expanded hpke.PrivateKey
	inSecret(func() {
		seed := keys.signing[:ed25519.SeedSize]
		needles = append(needles, masks("the signing key's seed", seed))
		h := sha512.Sum512(seed)
		needles = append(needles, masks("the signing key's nonce prefix", h[32:]))
		scalar := h[:32]
		scalar[0] &= 248
		scalar[31] &= 127
		scalar[31] |= 64
		needles = append(needles, masks("the signing key's scalar", scalar))
		clear(h[:])

		needles = append(needles, masks("the KEM key's seed", keys.kem))
		var wide [96]byte
		shake := sha3.NewSHAKE256()
		_, _ = shake.Write(keys.kem)
		_, _ = shake.Read(wide[:])
		needles = append(needles, masks("the KEM key's lattice seed", wide[:64]))
		needles = append(needles, masks("the KEM key's curve scalar", wide[64:]))
		clear(wide[:])
		expanded, err = hpke.MLKEM768X25519().NewPrivateKey(keys.kem)
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()

	// While the keys live they are there to be found: the scan sees what it
	// is meant to see.
	alive := found(t, needles)
	for _, want := range []string{"the signing key's seed", "the KEM key's seed", "the KEM key's lattice seed", "the KEM key's curve scalar"} {
		if !contains(alive, want) {
			t.Fatalf("the scan does not find %s while the keys are held: it found %v", want, alive)
		}
	}
	runtime.KeepAlive(expanded)
	expanded = nil

	// The bind: the receipt is signed and the signing key erased, a command
	// sealed to the KEM key is opened, and the KEM key erased.
	message := []byte("a receipt")
	signature, err := keys.sign(message)
	if err != nil || !ed25519.Verify(keys.public.Signing, message, signature) {
		t.Fatalf("the receipt's signature: %v", err)
	}
	enc, sender, err := hpke.NewSender(mustPublic(t, keys.public.KEM), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("info"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sender.Seal(nil, []byte("a command"))
	if err != nil {
		t.Fatal(err)
	}
	var opened []byte
	inSecret(func() {
		key, e := hpke.MLKEM768X25519().NewPrivateKey(keys.kem)
		if e != nil {
			err = e
			return
		}
		recipient, e := hpke.NewRecipient(enc, key, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("info"))
		if e != nil {
			err = e
			return
		}
		plain, e := recipient.Open(nil, sealed)
		if e != nil {
			err = e
			return
		}
		opened = bytes.Clone(plain)
	})
	if err != nil || string(opened) != "a command" {
		t.Fatalf("the command sealed to the KEM key opened to %q: %v", opened, err)
	}
	// The test opened the command where the guest will: it says so as the
	// guest does.
	keys.mu.Lock()
	keys.used = true
	keys.mu.Unlock()
	keys.eraseKEM()
	if !keys.gone() {
		t.Fatal("the keys are not gone")
	}
	// What the work allocated is erased when the collector finds it
	// unreachable, and the guest's own collection is what makes it look.
	keys.collect()

	if left := found(t, needles); len(left) != 0 {
		t.Fatalf("after the keys were erased this process still holds: %s", strings.Join(left, "; "))
	}
}

func mustPublic(t *testing.T, raw []byte) hpke.PublicKey {
	t.Helper()
	key, err := hpke.MLKEM768X25519().NewPublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func contains(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}

// The scan finds a byte string that is in memory and no other, so a clean
// result above means something.
func TestMemoryScanFindsWhatIsThere(t *testing.T) {
	present := bytes.Repeat([]byte{0xc3, 0x17, 0x9e, 0x42}, 8)
	absent := bytes.Repeat([]byte{0x3c, 0xe8, 0x61, 0xbd}, 8)
	needles := []needle{masks("present", present), masks("absent", absent)}
	clear(absent)
	got := found(t, needles)
	runtime.KeepAlive(present)
	if fmt.Sprint(got) != "[present]" {
		t.Fatalf("the scan found %v, want the one string that is in memory", got)
	}
}
