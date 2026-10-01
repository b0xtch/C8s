package podlauncher

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testFiles() []ISOFile {
	return []ISOFile{
		{Name: "pubkey", Data: []byte("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n")},
		{Name: "launch.yaml.sig", Data: []byte("c2ln\n")},
		{Name: "launch.yaml", Data: bytes.Repeat([]byte("tenant: acme\n"), 400)},
	}
}

func TestBuildISOStructure(t *testing.T) {
	img, err := BuildISO("opkeydata", testFiles())
	if err != nil {
		t.Fatal(err)
	}
	if len(img)%isoSector != 0 {
		t.Fatalf("image is %d bytes, which is no whole number of sectors", len(img))
	}
	pvd := img[isoPVD*isoSector:]
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" {
		t.Fatal("no primary volume descriptor at sector 16")
	}
	if label := strings.TrimRight(string(pvd[40:72]), " "); label != "opkeydata" {
		t.Fatalf("volume label = %q", label)
	}
	again, err := BuildISO("opkeydata", testFiles())
	if err != nil || !bytes.Equal(img, again) {
		t.Fatal("the same input produced a different image")
	}
	reordered := testFiles()
	reordered[0], reordered[2] = reordered[2], reordered[0]
	if other, _ := BuildISO("opkeydata", reordered); !bytes.Equal(img, other) {
		t.Fatal("file order changed the image")
	}
}

func TestBuildISORejects(t *testing.T) {
	ok := testFiles()
	for name, tc := range map[string]struct {
		label string
		files []ISOFile
	}{
		"no label":       {"", ok},
		"long label":     {strings.Repeat("x", 33), ok},
		"no files":       {"opkeydata", nil},
		"nested name":    {"opkeydata", []ISOFile{{Name: "a/b"}}},
		"dot name":       {"opkeydata", []ISOFile{{Name: ".."}}},
		"duplicate name": {"opkeydata", []ISOFile{{Name: "a"}, {Name: "a"}}},
		"too many files": {"opkeydata", make([]ISOFile, isoMaxFiles+1)},
	} {
		if _, err := BuildISO(tc.label, tc.files); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// An independent ISO9660 reader must see the Rock Ridge names and the exact
// bytes. libarchive ships on macOS and most Linux distributions.
func TestBuildISOReadsBackWithLibarchive(t *testing.T) {
	bsdtar, err := exec.LookPath("bsdtar")
	if err != nil {
		t.Skip("bsdtar not installed")
	}
	files := append(testFiles(), ISOFile{Name: "empty"})
	img, err := BuildISO("opkeydata", files)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "opkey.iso")
	if err := os.WriteFile(path, img, 0o644); err != nil {
		t.Fatal(err)
	}
	listing, err := exec.Command(bsdtar, "-tf", path).CombinedOutput()
	if err != nil {
		t.Fatalf("bsdtar -t: %v\n%s", err, listing)
	}
	for _, f := range files {
		if !strings.Contains("\n"+string(listing), "\n"+f.Name+"\n") {
			t.Fatalf("listing lacks %q:\n%s", f.Name, listing)
		}
		got, err := exec.Command(bsdtar, "-xOf", path, f.Name).Output()
		if err != nil {
			t.Fatalf("extract %s: %v", f.Name, err)
		}
		if !bytes.Equal(got, f.Data) {
			t.Fatalf("%s read back %d bytes, want %d", f.Name, len(got), len(f.Data))
		}
	}
}
