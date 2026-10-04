package devmapper

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// superblock builds a verity superblock as veritysetup writes one.
func superblock(mutate func(b []byte)) []byte {
	b := make([]byte, 512)
	copy(b, "verity\x00\x00")
	binary.LittleEndian.PutUint32(b[8:], 1)
	binary.LittleEndian.PutUint32(b[12:], 1)
	copy(b[32:], "sha256")
	binary.LittleEndian.PutUint32(b[64:], 4096)
	binary.LittleEndian.PutUint32(b[68:], 4096)
	binary.LittleEndian.PutUint64(b[72:], 74240)
	binary.LittleEndian.PutUint16(b[80:], 32)
	copy(b[88:], bytes.Repeat([]byte{0xab}, 32))
	if mutate != nil {
		mutate(b)
	}
	return b
}

func TestParseVeritySuperblock(t *testing.T) {
	sb, err := ParseVeritySuperblock(superblock(nil))
	if err != nil {
		t.Fatal(err)
	}
	if sb.HashType != 1 || sb.Algorithm != "sha256" || sb.DataBlockSize != 4096 || sb.HashBlockSize != 4096 ||
		sb.DataBlocks != 74240 || !bytes.Equal(sb.Salt, bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatalf("parsed %+v", sb)
	}
}

func TestParseVeritySuperblockRefuses(t *testing.T) {
	cases := map[string]func(b []byte){
		"no signature":              func(b []byte) { b[0] = 'V' },
		"another version":           func(b []byte) { binary.LittleEndian.PutUint32(b[8:], 2) },
		"an unknown hash type":      func(b []byte) { binary.LittleEndian.PutUint32(b[12:], 2) },
		"no algorithm":              func(b []byte) { copy(b[32:64], make([]byte, 32)) },
		"an algorithm with a space": func(b []byte) { copy(b[32:], "sha256 1 panic") },
		"a data block of 0":         func(b []byte) { binary.LittleEndian.PutUint32(b[64:], 0) },
		"a hash block of 3000":      func(b []byte) { binary.LittleEndian.PutUint32(b[68:], 3000) },
		"a block above 1 MiB":       func(b []byte) { binary.LittleEndian.PutUint32(b[64:], 1<<21) },
		"no data blocks":            func(b []byte) { binary.LittleEndian.PutUint64(b[72:], 0) },
		"data blocks that overflow": func(b []byte) { binary.LittleEndian.PutUint64(b[72:], 1<<62) },
		"a salt of 300 bytes":       func(b []byte) { binary.LittleEndian.PutUint16(b[80:], 300) },
	}
	for name, mutate := range cases {
		if _, err := ParseVeritySuperblock(superblock(mutate)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := ParseVeritySuperblock(make([]byte, 100)); err == nil {
		t.Error("a short buffer: parsed")
	}
}

func TestVerityTable(t *testing.T) {
	sb, err := ParseVeritySuperblock(superblock(nil))
	if err != nil {
		t.Fatal(err)
	}
	root := bytes.Repeat([]byte{0x5f}, 32)
	target, err := VerityTable(sb, Device{253, 2}, Device{253, 3}, root)
	if err != nil {
		t.Fatal(err)
	}
	want := "1 253:2 253:3 4096 4096 74240 1 sha256 " + hex.EncodeToString(root) + " " +
		strings.Repeat("ab", 32) + " 1 panic_on_corruption"
	if target.Type != "verity" || target.Start != 0 || target.Length != 74240*8 || target.Params != want {
		t.Fatalf("table %+v\nwant params %s", target, want)
	}

	// A tree without a salt names it with a dash.
	sb.Salt = nil
	target, err = VerityTable(sb, Device{253, 2}, Device{253, 3}, root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(target.Params, " "+hex.EncodeToString(root)+" - 1 panic_on_corruption") {
		t.Fatalf("unsalted params %s", target.Params)
	}

	// With 512-byte hash blocks the superblock is one block, and the tree
	// starts at the next.
	sb.HashBlockSize = 512
	target, _ = VerityTable(sb, Device{253, 2}, Device{253, 3}, root)
	if !strings.Contains(target.Params, " 4096 512 74240 1 sha256 ") {
		t.Fatalf("512-byte hash block params %s", target.Params)
	}

	if _, err := VerityTable(sb, Device{253, 2}, Device{253, 3}, nil); err == nil {
		t.Fatal("a table without a root hash")
	}
}

func TestCryptTable(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 64)
	target, err := CryptTable(Device{252, 16}, 8388608, key, CryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := "aes-xts-plain64 " + strings.Repeat("11", 64) + " 0 252:16 0"
	if target.Type != "crypt" || target.Length != 8388608 || target.Params != want {
		t.Fatalf("table %+v", target)
	}

	target, err = CryptTable(Device{252, 16}, 8388608, key, CryptOptions{SectorSize: 4096, IVLargeSectors: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(target.Params, " 0 252:16 0 2 sector_size:4096 iv_large_sectors") {
		t.Fatalf("4 KiB sector params %s", strings.TrimPrefix(target.Params, "aes-xts-plain64 "+strings.Repeat("11", 64)))
	}

	refused := map[string]func() (Target, error){
		"a 32-byte key":              func() (Target, error) { return CryptTable(Device{252, 16}, 8, key[:32], CryptOptions{}) },
		"no sectors":                 func() (Target, error) { return CryptTable(Device{252, 16}, 0, key, CryptOptions{}) },
		"a sector size of 3000":      func() (Target, error) { return CryptTable(Device{252, 16}, 8, key, CryptOptions{SectorSize: 3000}) },
		"a length off the sector":    func() (Target, error) { return CryptTable(Device{252, 16}, 9, key, CryptOptions{SectorSize: 4096}) },
		"large IVs on small sectors": func() (Target, error) { return CryptTable(Device{252, 16}, 8, key, CryptOptions{IVLargeSectors: true}) },
	}
	for name, build := range refused {
		if _, err := build(); err == nil {
			t.Errorf("%s: built", name)
		}
	}
}

func TestEncodeTable(t *testing.T) {
	targets := []Target{
		{Start: 0, Length: 100, Type: "linear", Params: "253:2 0"},
		{Start: 100, Length: 50, Type: "verity", Params: "1 a b"},
	}
	buf, err := encodeTable("root", flagReadOnly, targets)
	if err != nil {
		t.Fatal(err)
	}
	le := binary.LittleEndian
	if le.Uint32(buf[0:]) != 4 || le.Uint32(buf[12:]) != uint32(len(buf)) || le.Uint32(buf[16:]) != headerSize ||
		le.Uint32(buf[20:]) != 2 || le.Uint32(buf[28:]) != flagReadOnly {
		t.Fatalf("header % x", buf[:48])
	}
	if got := string(bytes.TrimRight(buf[48:48+nameLen], "\x00")); got != "root" {
		t.Fatalf("name %q", got)
	}
	at := headerSize
	for i, want := range targets {
		if le.Uint64(buf[at:]) != want.Start || le.Uint64(buf[at+8:]) != want.Length {
			t.Fatalf("target %d: start and length % x", i, buf[at:at+16])
		}
		if got := string(bytes.TrimRight(buf[at+24:at+40], "\x00")); got != want.Type {
			t.Fatalf("target %d: type %q", i, got)
		}
		next := int(le.Uint32(buf[at+20:]))
		if next%8 != 0 {
			t.Fatalf("target %d: the next one is %d bytes on, off the 8-byte grid", i, next)
		}
		params := buf[at+targetSpecSize : at+next]
		if got := string(params[:bytes.IndexByte(params, 0)]); got != want.Params {
			t.Fatalf("target %d: params %q", i, got)
		}
		at += next
	}
	if at != len(buf) {
		t.Fatalf("targets end at %d of %d", at, len(buf))
	}
}

func TestEncodeTableRefuses(t *testing.T) {
	ok := []Target{{Length: 1, Type: "linear", Params: "1:2 0"}}
	cases := map[string]struct {
		name    string
		targets []Target
	}{
		"no targets":            {"root", nil},
		"no name":               {"", ok},
		"a name with a slash":   {"a/b", ok},
		"a name with a space":   {"a b", ok},
		"a name of 128 bytes":   {strings.Repeat("n", 128), ok},
		"a target of no type":   {"root", []Target{{Length: 1}}},
		"a long target type":    {"root", []Target{{Length: 1, Type: strings.Repeat("t", 16)}}},
		"a target of no length": {"root", []Target{{Type: "linear"}}},
	}
	for name, c := range cases {
		if _, err := encodeTable(c.name, 0, c.targets); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
}

func TestRequestAndDevice(t *testing.T) {
	// DM_TABLE_LOAD as the kernel's headers define it.
	if got := request(cmdTableLoad); got != 0xc138fd09 {
		t.Fatalf("table load request %#x", got)
	}
	buf := make([]byte, headerSize)
	// 253:5, then a minor above 255: 253:300.
	binary.LittleEndian.PutUint64(buf[offDev:], 253<<8|5)
	if dev := decodeDev(buf); dev != (Device{253, 5}) {
		t.Fatalf("decoded %v", dev)
	}
	binary.LittleEndian.PutUint64(buf[offDev:], 253<<8|300&0xff|(300&^0xff)<<12)
	if dev := decodeDev(buf); dev != (Device{253, 300}) {
		t.Fatalf("decoded %v", dev)
	}
	if got := (Device{253, 300}).String(); got != "253:300" {
		t.Fatalf("device %s", got)
	}
	secret := []byte{1, 2, 3}
	wipe(secret)
	if !bytes.Equal(secret, []byte{0, 0, 0}) {
		t.Fatal("not wiped")
	}
}
