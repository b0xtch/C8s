package sessioninit

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
)

// lbaSize is the sector size of a session guest's boot disk.
const lbaSize = 512

// The partition types the init looks for, as the Discoverable Partitions
// Specification names them for x86-64.
var (
	rootPartitionType   = mustGUID("4f68bce3-e8cd-4db1-96e7-fbcaf984b709")
	verityPartitionType = mustGUID("2c7357ed-ebd2-46d9-aec1-23d437ec2bf5")
)

// guid is a GUID as a partition table stores it: its first three fields
// little-endian.
type guid [16]byte

// mustGUID encodes a GUID's text form.
func mustGUID(text string) guid {
	raw, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
	if err != nil || len(raw) != 16 {
		panic("sessioninit: GUID " + text)
	}
	var g guid
	// time_low, time_mid and time_hi_and_version are stored reversed.
	for i, j := range []int{3, 2, 1, 0, 5, 4, 7, 6} {
		g[i] = raw[j]
	}
	copy(g[8:], raw[8:])
	return g
}

// partition is one used entry of a partition table.
type partition struct {
	// Number counts entries from 1, as the kernel names partitions.
	Number      int
	Type        guid
	First, Last uint64
}

// readGPT returns the used entries of the partition table on disk. A table
// that fails its own checksums is no table: what the init goes on to trust is
// the verity root hash, and this only keeps it from walking a garbled disk.
func readGPT(disk io.ReaderAt) ([]partition, error) {
	header := make([]byte, 92)
	if _, err := disk.ReadAt(header, lbaSize); err != nil {
		return nil, fmt.Errorf("partition table header: %w", err)
	}
	if !bytes.Equal(header[:8], []byte("EFI PART")) {
		return nil, errors.New("no partition table")
	}
	le := binary.LittleEndian
	if size := le.Uint32(header[12:]); size != 92 {
		return nil, fmt.Errorf("partition table header of %d bytes", size)
	}
	sum := le.Uint32(header[16:])
	le.PutUint32(header[16:], 0)
	if crc32.ChecksumIEEE(header) != sum {
		return nil, errors.New("partition table header fails its checksum")
	}
	entriesLBA, count, size := le.Uint64(header[72:]), le.Uint32(header[80:]), le.Uint32(header[84:])
	if count == 0 || count > 256 || size < 128 || size > 4096 || size%8 != 0 {
		return nil, fmt.Errorf("partition table of %d entries of %d bytes", count, size)
	}
	if entriesLBA < 2 || entriesLBA > 1<<40 {
		return nil, fmt.Errorf("partition entries at sector %d", entriesLBA)
	}
	entries := make([]byte, int(count)*int(size))
	if _, err := disk.ReadAt(entries, int64(entriesLBA)*lbaSize); err != nil {
		return nil, fmt.Errorf("partition entries: %w", err)
	}
	if crc32.ChecksumIEEE(entries) != le.Uint32(header[88:]) {
		return nil, errors.New("partition entries fail their checksum")
	}
	var parts []partition
	for i := range int(count) {
		entry := entries[i*int(size):]
		var p partition
		copy(p.Type[:], entry[:16])
		if p.Type == (guid{}) {
			continue
		}
		p.Number, p.First, p.Last = i+1, le.Uint64(entry[32:]), le.Uint64(entry[40:])
		if p.First == 0 || p.Last < p.First {
			return nil, fmt.Errorf("partition %d spans sectors %d to %d", p.Number, p.First, p.Last)
		}
		parts = append(parts, p)
	}
	return parts, nil
}

// rootPartitions picks the root file system's partition and its verity
// tree's from a table.
func rootPartitions(parts []partition) (root, verity partition, ok bool) {
	var haveRoot, haveVerity bool
	for _, p := range parts {
		switch {
		case p.Type == rootPartitionType && !haveRoot:
			root, haveRoot = p, true
		case p.Type == verityPartitionType && !haveVerity:
			verity, haveVerity = p, true
		}
	}
	return root, verity, haveRoot && haveVerity
}

// The ISO 9660 volume the launcher writes the launch files to is found by its
// volume identifier. The primary volume descriptor is the sixteenth 2048-byte
// sector: a type byte, "CD001", a version, then at offset 40 the identifier,
// padded with spaces to 32 bytes.
const (
	isoDescriptorOffset = 16 * 2048
	isoDescriptorSize   = 72
)

// isoVolumeLabel returns the volume identifier of an ISO 9660 file system on
// disk, or "" when disk holds none.
func isoVolumeLabel(disk io.ReaderAt) string {
	descriptor := make([]byte, isoDescriptorSize)
	if _, err := disk.ReadAt(descriptor, isoDescriptorOffset); err != nil {
		return ""
	}
	if descriptor[0] != 1 || !bytes.Equal(descriptor[1:6], []byte("CD001")) {
		return ""
	}
	return strings.TrimRight(string(descriptor[40:72]), " \x00")
}
