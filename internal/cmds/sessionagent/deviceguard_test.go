package sessionagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pciBus writes a PCI bus as sysfs shows one: a directory for each function,
// with its ids in hex.
func pciBus(t *testing.T, functions map[string][3]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, ids := range functions {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		for i, file := range []string{"vendor", "device", "class"} {
			if ids[i] == "" {
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, name, file), []byte(ids[i]+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

// sessionBus is the bus of a session guest as its launcher builds it.
func sessionBus() map[string][3]string {
	return map[string][3]string{
		"0000:00:00.0": {"0x8086", "0x29c0", "0x060000"},
		"0000:00:01.0": {"0x1af4", "0x1042", "0x010000"},
		"0000:00:02.0": {"0x1af4", "0x1042", "0x010000"},
		"0000:00:03.0": {"0x1af4", "0x1042", "0x010000"},
		"0000:00:04.0": {"0x1af4", "0x1041", "0x020000"},
		"0000:00:05.0": {"0x1af4", "0x1053", "0x078000"},
		"0000:00:1f.0": {"0x8086", "0x2918", "0x060100"},
	}
}

// A session guest's bus holds its board's bridges and its virtio devices,
// and the guest ends on anything else: a device of another kind, one that
// says it is of another class, or a function whose ids it cannot read.
func TestDeviceGuard(t *testing.T) {
	if err := (DeviceGuard{Devices: pciBus(t, sessionBus())}).Check(); err != nil {
		t.Fatal(err)
	}
	with := func(name string, ids [3]string) map[string][3]string {
		bus := sessionBus()
		bus[name] = ids
		return bus
	}
	for name, tc := range map[string]struct {
		bus  map[string][3]string
		want string
	}{
		"a network card of the host's choosing":     {with("0000:00:06.0", [3]string{"0x8086", "0x10d3", "0x020000"}), "0000:00:06.0 (8086:10d3, class 020000)"},
		"a disk controller":                         {with("0000:00:1f.2", [3]string{"0x8086", "0x2922", "0x010601"}), "0000:00:1f.2"},
		"a virtio device of the old kind":           {with("0000:00:04.0", [3]string{"0x1af4", "0x1000", "0x020000"}), "1af4:1000"},
		"a virtio device this image has no use for": {with("0000:00:06.0", [3]string{"0x1af4", "0x1044", "0x00ff00"}), "1af4:1044"},
		"a block device that says it is a bridge":   {with("0000:00:01.0", [3]string{"0x1af4", "0x1042", "0x060400"}), "class 060400"},
		"a function behind a bridge":                {with("0000:01:00.0", [3]string{"0x1b36", "0x000d", "0x0c0330"}), "0000:01:00.0"},
		"a function with no vendor":                 {with("0000:00:06.0", [3]string{"", "0x1042", "0x010000"}), "0000:00:06.0"},
		"a function whose class is no number":       {with("0000:00:06.0", [3]string{"0x1af4", "0x1042", "disk"}), "0000:00:06.0"},
		"a console, in a guest that has none":       {with("0000:00:06.0", [3]string{"0x1af4", "0x1043", "0x078000"}), "1af4:1043"},
	} {
		err := (DeviceGuard{Devices: pciBus(t, tc.bus)}).Check()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want a refusal naming %q", name, err, tc.want)
		}
	}

	// A dev guest has a console, and nothing else besides.
	console := with("0000:00:06.0", [3]string{"0x1af4", "0x1043", "0x078000"})
	if err := (DeviceGuard{Devices: pciBus(t, console), Console: true}).Check(); err != nil {
		t.Fatalf("a dev guest's console: %v", err)
	}
	console["0000:00:07.0"] = [3]string{"0x8086", "0x10d3", "0x020000"}
	if err := (DeviceGuard{Devices: pciBus(t, console), Console: true}).Check(); err == nil {
		t.Fatal("a dev guest took a network card of its host's choosing")
	}
	console["0000:00:07.0"] = [3]string{"0x1af4", "0x1043", "0x020000"}
	if err := (DeviceGuard{Devices: pciBus(t, console), Console: true}).Check(); err == nil {
		t.Fatal("a console that says it is a network device was taken")
	}

	// A guest of a class with no network device has the same bus without
	// one. A network device on it is another machine's, and so is whatever a
	// session guest would not be given.
	replica := sessionBus()
	delete(replica, "0000:00:04.0")
	if err := (DeviceGuard{Devices: pciBus(t, replica), NoNetwork: true}).Check(); err != nil {
		t.Fatalf("a guest with no network device: %v", err)
	}
	if err := (DeviceGuard{Devices: pciBus(t, replica)}).Check(); err != nil {
		t.Fatalf("a session guest's check on a bus with no network device: %v", err)
	}
	err := (DeviceGuard{Devices: pciBus(t, sessionBus()), NoNetwork: true}).Check()
	if err == nil || !strings.Contains(err.Error(), "0000:00:04.0 (1af4:1041, class 020000) is none a guest of this class is given") {
		t.Fatalf("a guest of a class with no network device took one: %v", err)
	}
	replica["0000:00:06.0"] = [3]string{"0x1af4", "0x1043", "0x078000"}
	if err := (DeviceGuard{Devices: pciBus(t, replica), NoNetwork: true}).Check(); err == nil {
		t.Fatal("a guest with no network device took a console that it has none of")
	}
	if err := (DeviceGuard{Devices: pciBus(t, replica), NoNetwork: true, Console: true}).Check(); err != nil {
		t.Fatalf("a dev guest with no network device: %v", err)
	}
	replica["0000:00:07.0"] = [3]string{"0x8086", "0x10d3", "0x020000"}
	if err := (DeviceGuard{Devices: pciBus(t, replica), NoNetwork: true, Console: true}).Check(); err == nil {
		t.Fatal("a guest with no network device took a network card of its host's choosing")
	}

	// A bus the guest cannot read, or one with nothing on it, is no session
	// guest's.
	if err := (DeviceGuard{Devices: filepath.Join(t.TempDir(), "absent")}).Check(); err == nil {
		t.Fatal("a bus that is not there passed")
	}
	if err := (DeviceGuard{Devices: t.TempDir()}).Check(); err == nil {
		t.Fatal("an empty bus passed")
	}
}
