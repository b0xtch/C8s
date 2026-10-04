package sessioninit

import (
	"hash/crc32"
	"reflect"
	"strings"
	"testing"
)

func crc32Of(b []byte) uint32 { return crc32.ChecksumIEEE(b) }

func TestRootHashFromCmdline(t *testing.T) {
	hash, err := rootHashFromCmdline("quiet roothash=" + testRootHash + " no-kvmclock")
	if err != nil || len(hash) != 32 || hash[0] != 0x5f {
		t.Fatalf("hash %x, %v", hash, err)
	}
	// The last one wins, as the kernel reads a repeated parameter.
	hash, err = rootHashFromCmdline("roothash=" + strings.Repeat("00", 32) + " roothash=" + testRootHash)
	if err != nil || hash[0] != 0x5f {
		t.Fatalf("hash %x, %v", hash, err)
	}
	if hash, err := rootHashFromCmdline("roothash=" + strings.Repeat("ab", 48)); err != nil || len(hash) != 48 {
		t.Fatalf("a SHA-384 digest: %x, %v", hash, err)
	}
	for _, cmdline := range []string{"", "roothash=", "roothash=zz", "roothash=abcd", "xroothash=" + testRootHash} {
		if _, err := rootHashFromCmdline(cmdline); err == nil {
			t.Errorf("%q: a root hash", cmdline)
		}
	}
}

func TestStateDirs(t *testing.T) {
	dirs, err := stateDirs(map[string][]byte{
		"50-b.conf": []byte("var\n/etc/app/\n"),
		"10-a.conf": []byte("# comment\n\nhome\r\nvar\nroot"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"home", "var", "root", "etc/app"}; !reflect.DeepEqual(dirs, want) {
		t.Fatalf("dirs %v", dirs)
	}
	for name, list := range map[string]string{
		"a path that climbs":      "var/../etc",
		"a path with a comma":     "var,upperdir=/etc",
		"a path with a colon":     "a:b",
		"the root itself":         "/",
		"a path with a dot":       "./var",
		"a path with two slashes": "var//lib",
	} {
		if _, err := stateDirs(map[string][]byte{"10-a.conf": []byte(list)}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := stateDirs(map[string][]byte{"10-a.conf": []byte("# nothing\n")}); err == nil {
		t.Error("an empty list: accepted")
	}
}

func TestSysctlSettings(t *testing.T) {
	settings, err := sysctlSettings([]map[string][]byte{
		{"50-default.conf": []byte("kernel.sysrq = 176\nnet.ipv4.conf.all.rp_filter=2\n"), "README": []byte("not a list")},
		{"50-default.conf": []byte("kernel.sysrq = 0\n; comment\n-fs.absent = 1\nnet/ipv4/conf/eth0.1/arp_filter = 1\n"), "10-first.conf": []byte("vm.swappiness=1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []setting{
		{Key: "vm/swappiness", Value: "1"},
		{Key: "kernel/sysrq", Value: "0"},
		{Key: "fs/absent", Value: "1", Optional: true},
		{Key: "net/ipv4/conf/eth0.1/arp_filter", Value: "1"},
	}
	if !reflect.DeepEqual(settings, want) {
		t.Fatalf("settings %+v", settings)
	}
	for name, file := range map[string]string{
		"a line without a value": "kernel.panic",
		"a key that climbs":      "kernel/../../etc/passwd = x",
		"an absolute key":        "/etc/passwd = x",
		"an empty key":           " = 1",
	} {
		if _, err := sysctlSettings([]map[string][]byte{{"10-a.conf": []byte(file)}}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseBootConfig(t *testing.T) {
	cfg, err := parseBootConfig([]byte(testBootConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "session" || len(cfg.Steps) != 2 || cfg.Service[0] != "/usr/local/bin/c8s-session-guest" {
		t.Fatalf("config %+v", cfg)
	}
	for name, data := range map[string]string{
		"nothing":                  "",
		"no service":               `{"steps":[["/bin/a"]]}`,
		"an empty step":            `{"steps":[[]],"service":["/bin/a"]}`,
		"a relative step":          `{"steps":[["a"]],"service":["/bin/a"]}`,
		"an unknown member":        `{"service":["/bin/a"],"x":1}`,
		"two documents":            `{"service":["/bin/a"]} {"service":["/bin/b"]}`,
		"a document that is cut":   `{"service":["/bin/a"]`,
		"a document that is large": `{"service":["/bin/a"],"hostname":"` + strings.Repeat("h", maxBootConfig) + `"}`,
	} {
		if _, err := parseBootConfig([]byte(data)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}
