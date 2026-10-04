package devmapper

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The kernel's ioctl interface (include/uapi/linux/dm-ioctl.h). One buffer
// goes in and comes back: a fixed header, then for a table load one target
// spec and its parameter string per target, each padded to 8 bytes.
const (
	headerSize     = 312
	targetSpecSize = 40
	nameLen        = 128
	uuidLen        = 129
	maxTypeName    = 16

	// The header's fields.
	offVersion     = 0
	offDataSize    = 12
	offDataStart   = 16
	offTargetCount = 20
	offFlags       = 28
	offDev         = 40
	offName        = 48
	offUUID        = offName + nameLen

	// The interface version this code speaks. The kernel accepts any minor
	// version at or below its own.
	versionMajor, versionMinor, versionPatch = 4, 0, 0

	flagReadOnly   = 1 << 0
	flagSuspend    = 1 << 1
	flagSecureData = 1 << 15

	cmdDevCreate  = 3
	cmdDevRemove  = 4
	cmdDevSuspend = 6
	cmdTableLoad  = 9
)

// request is _IOWR(0xfd, nr, struct dm_ioctl).
func request(nr uintptr) uintptr {
	const dirReadWrite = 3
	return dirReadWrite<<30 | headerSize<<16 | 0xfd<<8 | nr
}

// header writes the fixed part of a request for the device name into buf,
// which is the whole buffer the kernel gets.
func header(buf []byte, name string, flags uint32) error {
	if name == "" || len(name) >= nameLen {
		return fmt.Errorf("device-mapper: a name of %d bytes", len(name))
	}
	for i := range len(name) {
		// The name becomes a sysfs entry and a uevent field.
		if c := name[i]; c <= ' ' || c == '/' || c > '~' {
			return fmt.Errorf("device-mapper: name %q", name)
		}
	}
	le := binary.LittleEndian
	le.PutUint32(buf[offVersion:], versionMajor)
	le.PutUint32(buf[offVersion+4:], versionMinor)
	le.PutUint32(buf[offVersion+8:], versionPatch)
	le.PutUint32(buf[offDataSize:], uint32(len(buf)))
	le.PutUint32(buf[offDataStart:], headerSize)
	le.PutUint32(buf[offFlags:], flags)
	copy(buf[offName:offName+nameLen-1], name)
	return nil
}

// encodeTable builds a table load request: the header and every target.
func encodeTable(name string, flags uint32, targets []Target) ([]byte, error) {
	if len(targets) == 0 {
		return nil, errors.New("device-mapper: an empty table")
	}
	size := headerSize
	for _, t := range targets {
		if t.Type == "" || len(t.Type) >= maxTypeName {
			return nil, fmt.Errorf("device-mapper: target type %q", t.Type)
		}
		if t.Length == 0 {
			return nil, fmt.Errorf("device-mapper: a %s target of no length", t.Type)
		}
		size += targetSpecSize + pad8(len(t.Params)+1)
	}
	buf := make([]byte, size)
	if err := header(buf, name, flags); err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	le.PutUint32(buf[offTargetCount:], uint32(len(targets)))
	at := headerSize
	for _, t := range targets {
		next := targetSpecSize + pad8(len(t.Params)+1)
		le.PutUint64(buf[at:], t.Start)
		le.PutUint64(buf[at+8:], t.Length)
		le.PutUint32(buf[at+20:], uint32(next))
		copy(buf[at+24:at+24+maxTypeName-1], t.Type)
		copy(buf[at+targetSpecSize:], t.Params)
		at += next
	}
	return buf, nil
}

func pad8(n int) int { return (n + 7) &^ 7 }

// decodeDev reads the device number a request came back with. The kernel
// packs it as huge_encode_dev does: the minor's low byte, the major, then the
// rest of the minor.
func decodeDev(buf []byte) Device {
	dev := binary.LittleEndian.Uint64(buf[offDev:])
	return Device{
		Major: uint32(dev>>8) & 0xfff,
		Minor: uint32(dev&0xff) | uint32(dev>>12)&0xfff00,
	}
}

// wipe clears a request that held a key.
func wipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
