package imagestoretest

import (
	"bytes"
	"debug/elf"
	"testing"
)

// Wherever the tests run, the probe is a well-formed executable for the
// machine a guest is.
func TestSocketProbeIsAnAMD64Executable(t *testing.T) {
	probe := SocketProbe(afVsock)
	f, err := elf.NewFile(bytes.NewReader(probe))
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != elf.ET_EXEC || f.Machine != elf.EM_X86_64 || f.Class != elf.ELFCLASS64 {
		t.Fatalf("type %v, machine %v, class %v", f.Type, f.Machine, f.Class)
	}
	if len(f.Progs) != 1 || f.Progs[0].Type != elf.PT_LOAD || f.Progs[0].Flags != elf.PF_R|elf.PF_X || f.Progs[0].Filesz != uint64(len(probe)) {
		t.Fatalf("segments %+v for %d bytes", f.Progs, len(probe))
	}
	if f.Entry != f.Progs[0].Vaddr+64+56 {
		t.Fatalf("entry %#x is not the first byte after the headers", f.Entry)
	}
	if bytes.Equal(SocketProbe(afInet), probe) {
		t.Fatal("two families gave one program")
	}
}
