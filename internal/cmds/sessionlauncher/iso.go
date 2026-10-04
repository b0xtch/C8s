// Package sessionlauncher is the host side of one session guest: it turns a
// launch bundle into a running confidential VM inside its own cgroup and network
// namespace. Everything here runs on the untrusted host. It can refuse to
// start a guest or start the wrong one; it cannot make a wrong guest verify.
package sessionlauncher

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ISO9660 with Rock Ridge names, the format the measured initrd and the
// agent mount by volume label. Written here so the launcher needs no external
// image tool; the output is a pure function of its input.
const (
	isoSector    = 2048
	isoPVD       = 16
	isoPathL     = 18
	isoPathM     = 19
	isoRootDir   = 20
	isoERArea    = 21
	isoFirstFile = 22
	isoMaxName   = 64
	isoMaxFiles  = 16
)

// ISOFile is one regular file at the image root.
type ISOFile struct {
	Name string
	Data []byte
}

// BuildISO returns an ISO9660 image labelled label holding files at its root.
func BuildISO(label string, files []ISOFile) ([]byte, error) {
	if label == "" || len(label) > 32 || strings.ContainsAny(label, " /\x00") {
		return nil, fmt.Errorf("volume label %q must be 1..32 characters with no space or slash", label)
	}
	if len(files) == 0 || len(files) > isoMaxFiles {
		return nil, fmt.Errorf("an image holds 1..%d files, got %d", isoMaxFiles, len(files))
	}
	files = append([]ISOFile(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	for i, f := range files {
		if f.Name == "" || len(f.Name) > isoMaxName || f.Name == "." || f.Name == ".." || strings.ContainsAny(f.Name, "/\x00") {
			return nil, fmt.Errorf("file name %q is not a plain name of at most %d bytes", f.Name, isoMaxName)
		}
		if i > 0 && files[i-1].Name == f.Name {
			return nil, fmt.Errorf("duplicate file name %q", f.Name)
		}
	}

	// Lay files out after the fixed metadata sectors.
	extents := make([]uint32, len(files))
	next := uint32(isoFirstFile)
	for i, f := range files {
		extents[i] = next
		next += sectors(len(f.Data))
	}
	total := next

	root := make([]byte, 0, isoSector)
	er := rockRidgeER()
	// "." carries SP, which announces SUSP, and CE, which points at ER.
	self := []byte{'S', 'P', 7, 1, 0xBE, 0xEF, 0}
	self = append(self, rockRidgeCE(isoERArea, 0, uint32(len(er)))...)
	self = append(self, rockRidgePX(0o040555, 2)...)
	root = append(root, dirRecord(isoRootDir, isoSector, true, []byte{0}, self)...)
	root = append(root, dirRecord(isoRootDir, isoSector, true, []byte{1}, rockRidgePX(0o040555, 2))...)
	for i, f := range files {
		// The ISO name is a placeholder; readers use the Rock Ridge name.
		id := []byte(fmt.Sprintf("F%07d.;1", i))
		use := append(rockRidgePX(0o100444, 1), rockRidgeNM(f.Name)...)
		rec := dirRecord(extents[i], uint32(len(f.Data)), false, id, use)
		// A record never spans a sector; this directory is exactly one.
		if len(root)+len(rec) > isoSector {
			return nil, errors.New("directory does not fit one sector")
		}
		root = append(root, rec...)
	}

	img := make([]byte, int(total)*isoSector)
	pvd := img[isoPVD*isoSector:]
	pvd[0] = 1
	copy(pvd[1:], "CD001")
	pvd[6] = 1
	padded(pvd[8:40], "LINUX")
	padded(pvd[40:72], label)
	both32(pvd[80:], total)
	both16(pvd[120:], 1)
	both16(pvd[124:], 1)
	both16(pvd[128:], isoSector)
	const pathTableSize = 10
	both32(pvd[132:], pathTableSize)
	binary.LittleEndian.PutUint32(pvd[140:], isoPathL)
	binary.BigEndian.PutUint32(pvd[148:], isoPathM)
	copy(pvd[156:190], dirRecord(isoRootDir, isoSector, true, []byte{0}, nil))
	for _, field := range [][2]int{{190, 318}, {318, 446}, {446, 574}, {574, 702}, {702, 739}, {739, 776}, {776, 813}} {
		padded(pvd[field[0]:field[1]], "")
	}
	for _, off := range []int{813, 830, 847, 864} {
		copy(pvd[off:off+16], "0000000000000000")
	}
	pvd[881] = 1

	term := img[(isoPVD+1)*isoSector:]
	term[0] = 255
	copy(term[1:], "CD001")
	term[6] = 1

	for _, table := range []struct {
		sector int
		order  binary.ByteOrder
	}{{isoPathL, binary.LittleEndian}, {isoPathM, binary.BigEndian}} {
		rec := img[table.sector*isoSector:]
		rec[0] = 1
		table.order.PutUint32(rec[2:], isoRootDir)
		table.order.PutUint16(rec[6:], 1)
	}
	copy(img[isoRootDir*isoSector:], root)
	copy(img[isoERArea*isoSector:], er)
	for i, f := range files {
		copy(img[int(extents[i])*isoSector:], f.Data)
	}
	return img, nil
}

func sectors(n int) uint32 {
	if n == 0 {
		return 1
	}
	return uint32((n + isoSector - 1) / isoSector)
}

// dirRecord encodes one directory record with its system use area.
func dirRecord(extent, size uint32, dir bool, id, systemUse []byte) []byte {
	n := 33 + len(id)
	if len(id)%2 == 0 {
		n++ // pad so the system use area starts on an even offset
	}
	suStart := n
	n += len(systemUse)
	if n%2 == 1 {
		n++
	}
	rec := make([]byte, n)
	rec[0] = byte(n)
	both32(rec[2:], extent)
	both32(rec[10:], size)
	// A fixed date keeps the image reproducible: 1970-01-01 00:00:00 UTC.
	copy(rec[18:25], []byte{70, 1, 1, 0, 0, 0, 0})
	if dir {
		rec[25] = 0x02
	}
	both16(rec[28:], 1)
	rec[32] = byte(len(id))
	copy(rec[33:], id)
	copy(rec[suStart:], systemUse)
	return rec
}

func rockRidgePX(mode, links uint32) []byte {
	px := make([]byte, 36)
	copy(px, []byte{'P', 'X', 36, 1})
	both32(px[4:], mode)
	both32(px[12:], links)
	// uid and gid stay 0.
	return px
}

func rockRidgeNM(name string) []byte {
	return append([]byte{'N', 'M', byte(5 + len(name)), 1, 0}, name...)
}

func rockRidgeCE(sector, offset, length uint32) []byte {
	ce := make([]byte, 28)
	copy(ce, []byte{'C', 'E', 28, 1})
	both32(ce[4:], sector)
	both32(ce[12:], offset)
	both32(ce[20:], length)
	return ce
}

// rockRidgeER identifies the extension in use, as SUSP requires.
func rockRidgeER() []byte {
	const (
		id   = "RRIP_1991A"
		desc = "THE ROCK RIDGE INTERCHANGE PROTOCOL PROVIDES SUPPORT FOR POSIX FILE SYSTEM SEMANTICS"
		src  = "PLEASE CONTACT DISC PUBLISHER FOR SPECIFICATION SOURCE.  SEE PUBLISHER IDENTIFIER IN PRIMARY VOLUME DESCRIPTOR FOR CONTACT INFORMATION."
	)
	er := []byte{'E', 'R', byte(8 + len(id) + len(desc) + len(src)), 1, byte(len(id)), byte(len(desc)), byte(len(src)), 1}
	return append(append(append(er, id...), desc...), src...)
}

func both32(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
	binary.BigEndian.PutUint32(b[4:], v)
}

func both16(b []byte, v uint16) {
	binary.LittleEndian.PutUint16(b, v)
	binary.BigEndian.PutUint16(b[2:], v)
}

// padded writes s left-aligned and fills the rest with spaces.
func padded(b []byte, s string) {
	n := copy(b, s)
	for i := n; i < len(b); i++ {
		b[i] = ' '
	}
}
