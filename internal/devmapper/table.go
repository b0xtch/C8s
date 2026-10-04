// Package devmapper loads device-mapper tables with the kernel's own ioctls,
// for a guest that carries no cryptsetup, veritysetup or libdevmapper: the
// session guest's init opens its verity root and its encrypted state volume
// with nothing but its own binary.
package devmapper

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// SectorSize is the unit of every table's start and length.
const SectorSize = 512

// Target is one line of a device-mapper table.
type Target struct {
	// Start and Length are in 512-byte sectors.
	Start, Length uint64
	// Type is the target's name: "verity", "crypt", "linear".
	Type string
	// Params is the target's parameter string, as dmsetup would take it.
	Params string
}

// Device names a block device in a table by its numbers, which needs no
// device node: a guest without udev has none under /dev/mapper.
type Device struct{ Major, Minor uint32 }

func (d Device) String() string { return fmt.Sprintf("%d:%d", d.Major, d.Minor) }

// NodePath is where devtmpfs puts a device-mapper device's node.
func NodePath(dev Device) string { return fmt.Sprintf("/dev/dm-%d", dev.Minor) }

// Options say how a device is created.
type Options struct {
	// ReadOnly makes the device read-only: a verity device is.
	ReadOnly bool
	// Secure has the kernel wipe its copy of the request once it has used
	// it, and wipes this process's copy: for a table that carries a key.
	Secure bool
}

// veritySuperblockSize is how much of a hash device its superblock takes.
const veritySuperblockSize = 512

// VeritySuperblock is the on-disk description veritysetup writes at the start
// of a hash device. Nothing in it is trusted: the root hash, which comes from
// a measured source, covers the hash tree, and a tree read with the wrong
// parameters does not verify.
type VeritySuperblock struct {
	// HashType is 1 for the normal format and 0 for Chrome OS's.
	HashType      uint32
	Algorithm     string
	DataBlockSize uint32
	HashBlockSize uint32
	DataBlocks    uint64
	Salt          []byte
}

// ParseVeritySuperblock reads the superblock from the first 512 bytes of a
// hash device.
func ParseVeritySuperblock(b []byte) (*VeritySuperblock, error) {
	if len(b) < veritySuperblockSize {
		return nil, fmt.Errorf("verity superblock: %d bytes, want %d", len(b), veritySuperblockSize)
	}
	if string(b[:8]) != "verity\x00\x00" {
		return nil, errors.New("verity superblock: no signature")
	}
	if v := binary.LittleEndian.Uint32(b[8:12]); v != 1 {
		return nil, fmt.Errorf("verity superblock: version %d, want 1", v)
	}
	sb := &VeritySuperblock{
		HashType:      binary.LittleEndian.Uint32(b[12:16]),
		Algorithm:     strings.TrimRight(string(b[32:64]), "\x00"),
		DataBlockSize: binary.LittleEndian.Uint32(b[64:68]),
		HashBlockSize: binary.LittleEndian.Uint32(b[68:72]),
		DataBlocks:    binary.LittleEndian.Uint64(b[72:80]),
	}
	saltSize := int(binary.LittleEndian.Uint16(b[80:82]))
	if saltSize > 256 {
		return nil, fmt.Errorf("verity superblock: salt of %d bytes", saltSize)
	}
	sb.Salt = append([]byte(nil), b[88:88+saltSize]...)
	if sb.HashType > 1 {
		return nil, fmt.Errorf("verity superblock: hash type %d", sb.HashType)
	}
	// The algorithm goes into a table line: hold it to a name.
	if sb.Algorithm == "" || strings.Trim(sb.Algorithm, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		return nil, fmt.Errorf("verity superblock: algorithm %q", sb.Algorithm)
	}
	for _, size := range []uint32{sb.DataBlockSize, sb.HashBlockSize} {
		if size < 512 || size > 1<<20 || size&(size-1) != 0 {
			return nil, fmt.Errorf("verity superblock: block size %d", size)
		}
	}
	if sb.DataBlocks == 0 || sb.DataBlocks > (1<<63)/uint64(sb.DataBlockSize) {
		return nil, fmt.Errorf("verity superblock: %d data blocks", sb.DataBlocks)
	}
	return sb, nil
}

// VerityTable is the table of a verity device over data with its hash tree
// on hash, for a hash device that starts with sb. A block that does not
// verify panics the kernel: on a confidential guest a changed root is its
// host's doing, and a guest that reads on past it runs on what its host chose.
func VerityTable(sb *VeritySuperblock, data, hash Device, rootHash []byte) (Target, error) {
	if len(rootHash) == 0 {
		return Target{}, errors.New("verity: no root hash")
	}
	salt := "-"
	if len(sb.Salt) > 0 {
		salt = hex.EncodeToString(sb.Salt)
	}
	// The hash tree follows the superblock, from the next hash block on.
	hashStart := (veritySuperblockSize + uint64(sb.HashBlockSize) - 1) / uint64(sb.HashBlockSize)
	return Target{
		Length: sb.DataBlocks * uint64(sb.DataBlockSize) / SectorSize,
		Type:   "verity",
		Params: fmt.Sprintf("%d %s %s %d %d %d %d %s %s %s 1 panic_on_corruption",
			sb.HashType, data, hash, sb.DataBlockSize, sb.HashBlockSize, sb.DataBlocks, hashStart,
			sb.Algorithm, hex.EncodeToString(rootHash), salt),
	}, nil
}

// CryptOptions shape a crypt table beyond its cipher and key.
type CryptOptions struct {
	// SectorSize is the encryption unit in bytes: 512, or up to 4096 with
	// IVLargeSectors counting IVs in those units. Zero is 512.
	SectorSize     uint32
	IVLargeSectors bool
}

// CryptTable is the table of a plain dm-crypt device over the first sectors
// 512-byte sectors of dev: aes-xts-plain64, no header, the key in the table.
// The caller wipes key, and loads the table with Secure set.
func CryptTable(dev Device, sectors uint64, key []byte, opts CryptOptions) (Target, error) {
	if len(key) != 64 {
		return Target{}, fmt.Errorf("crypt: a key of %d bytes, want 64 for aes-xts with 256-bit AES", len(key))
	}
	if sectors == 0 {
		return Target{}, errors.New("crypt: an empty device")
	}
	params := fmt.Sprintf("aes-xts-plain64 %s 0 %s 0", hex.EncodeToString(key), dev)
	var optional []string
	switch opts.SectorSize {
	case 0, 512:
	case 1024, 2048, 4096:
		if sectors%(uint64(opts.SectorSize)/SectorSize) != 0 {
			return Target{}, fmt.Errorf("crypt: %d sectors is no multiple of the %d-byte sector", sectors, opts.SectorSize)
		}
		optional = append(optional, fmt.Sprintf("sector_size:%d", opts.SectorSize))
	default:
		return Target{}, fmt.Errorf("crypt: sector size %d", opts.SectorSize)
	}
	if opts.IVLargeSectors {
		if opts.SectorSize <= 512 {
			return Target{}, errors.New("crypt: iv_large_sectors needs a sector size above 512")
		}
		optional = append(optional, "iv_large_sectors")
	}
	if len(optional) > 0 {
		params += fmt.Sprintf(" %d %s", len(optional), strings.Join(optional, " "))
	}
	return Target{Length: sectors, Type: "crypt", Params: params}, nil
}
