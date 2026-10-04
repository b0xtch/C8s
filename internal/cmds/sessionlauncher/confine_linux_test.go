//go:build linux

package sessionlauncher

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

func TestConfinementGroupsForADevice(t *testing.T) {
	device := filepath.Join(t.TempDir(), "kvm")
	if err := os.WriteFile(device, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	other := &Confinement{UID: uid + 1, GID: gid + 1}
	for name, tc := range map[string]struct {
		mode os.FileMode
		who  *Confinement
		want []uint32
		ok   bool
	}{
		"open to everyone":              {0o666, other, nil, true},
		"the device's group":            {0o660, other, []uint32{gid}, true},
		"the user's own group":          {0o660, &Confinement{UID: uid + 1, GID: gid}, nil, true},
		"the user's own device":         {0o600, &Confinement{UID: uid, GID: gid + 1}, nil, true},
		"its owner alone":               {0o600, other, nil, false},
		"a group that may only read":    {0o640, other, nil, false},
		"everyone may only read":        {0o644, other, nil, false},
		"a group and everyone, to read": {0o664, other, []uint32{gid}, true},
	} {
		if err := os.Chmod(device, tc.mode); err != nil {
			t.Fatal(err)
		}
		got, err := tc.who.groupsFor(device)
		if (err == nil) != tc.ok || len(got) != len(tc.want) || (len(got) == 1 && got[0] != tc.want[0]) {
			t.Errorf("%s: groups %v, %v; want %v, ok %v", name, got, err, tc.want, tc.ok)
		}
	}
	if _, err := other.groupsFor(device + "-missing"); err == nil {
		t.Error("a device that is not there was accepted")
	}
}

// A launcher without the capabilities says which it lacks before it starts
// anything: without CAP_KILL it could start a guest and never stop it.
func TestConfinementNeedsCapabilities(t *testing.T) {
	missing, err := missingCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&Confinement{UID: 64055, GID: 64055}).sysProcAttr(NetworkFD)
	if os.Geteuid() == 0 {
		// Root in a container may hold less than all of them.
		if len(missing) == 0 {
			t.Skip("this process holds every capability the check looks for")
		}
	} else if len(missing) != len(confining) {
		t.Fatalf("an unprivileged process lacks only %v", missing)
	}
	if err == nil || !strings.Contains(err.Error(), missing[0]) {
		t.Fatalf("a launcher lacking %v was allowed to confine: %v", missing, err)
	}
}

// The confined VMM is another user with no capability, alone in its process
// namespace. It reads its disks and its firmware through what it was handed
// and can open none of them where they lie. Needs root, as the launcher does
// to confine anything.
func TestRunConfinesTheVMM(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: only root can start a process as another user in namespaces of its own")
	}
	// A stand-in for /dev/kvm that the VMM's user reaches by its group alone.
	device := filepath.Join(t.TempDir(), "kvm")
	if err := os.WriteFile(device, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const deviceGroup = 4242
	if err := os.Chown(device, 0, deviceGroup); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{device: 0o660, filepath.Dir(filepath.Dir(device)): 0o755} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	real := kvmDevice
	kvmDevice = device
	t.Cleanup(func() { kvmDevice = real })
	own := map[string]string{}
	for _, ns := range []string{"pid", "net", "ipc", "uts", "mnt"} {
		link, err := os.Readlink("/proc/self/ns/" + ns)
		if err != nil {
			t.Fatal(err)
		}
		own[ns] = link
	}

	for name, tc := range map[string]struct {
		network string
		ownNet  bool
	}{
		"a guest whose tap it inherits":           {NetworkFD, true},
		"a guest on QEMU's own user-mode network": {NetworkUser, false},
	} {
		t.Run(name, func(t *testing.T) {
			// What it is, what it can open by path, and what it holds open.
			qemu, record := fakeQEMU(t, `{
  echo "uid $(id -u)"; echo "gid $(id -g)"; echo "groups $(id -G)"; echo "pid $$"
  grep -E '^(CapPrm|CapEff):' /proc/self/status
  for ns in pid net ipc uts mnt; do echo "ns-$ns $(readlink /proc/self/ns/$ns)"; done
  prev=; for a in "$@"; do [ "$prev" = -bios ] && bios=$a; prev=$a; done
  for f in "$WORK/opkey.iso" "$WORK/scratch.raw" "$IMAGE/OVMF.tdx.fd" "$DEVICE"; do
    if { true < "$f"; } 2>/dev/null; then echo "opens $f"; else echo "refused $f"; fi
  done
  if { true < "$bios"; } 2>/dev/null; then echo "firmware opens"; else echo "firmware refused"; fi
  if { true <> "$DEVICE"; } 2>/dev/null; then echo "opens-rw $DEVICE"; fi
} > "$record/confined"
# The first process of a namespace takes only the signals it handles, as QEMU
# handles SIGTERM.
trap 'exit 0' TERM
sleep 30 &
wait`)
			cfg := launchConfig(t, qemu)
			cfg.Confine = &Confinement{UID: 64055, GID: 64056}
			if tc.network == NetworkFD {
				tap, err := os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				defer tap.Close()
				cfg.Network, cfg.Forwards, cfg.TapFD, cfg.VhostFD = NetworkFD, nil, dupFD(t, tap), -1
				cfg.Guest, cfg.MAC = session.HostNetwork{Address: "169.254.17.2/30"}, "02:a8:1e:00:00:02"
			}
			// The image's files are public. The directory they are in is the
			// launcher's alone, as the work directory is.
			if err := os.Chmod(cfg.ImageDir, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("WORK", cfg.WorkDir)
			t.Setenv("IMAGE", cfg.ImageDir)
			t.Setenv("DEVICE", device)

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- Run(ctx, cfg, quiet) }()
			waitFor(t, filepath.Join(record, "confined"), done)
			time.Sleep(200 * time.Millisecond)
			raw, _ := os.ReadFile(filepath.Join(record, "confined"))
			got := map[string]string{}
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				key, value, _ := strings.Cut(strings.ReplaceAll(line, "\t", " "), " ")
				got[key+" "+strings.TrimSpace(value)] = ""
				got[key] = strings.TrimSpace(value)
			}
			for key, want := range map[string]string{
				"uid": "64055", "gid": "64056", "groups": "64056 " + strconv.Itoa(deviceGroup), "pid": "1",
				"CapPrm:": "0000000000000000", "CapEff:": "0000000000000000",
			} {
				if got[key] != want {
					t.Errorf("%s is %q, want %q", key, got[key], want)
				}
			}
			for _, ns := range []string{"pid", "ipc", "uts"} {
				if got["ns-"+ns] == own[ns] || got["ns-"+ns] == "" {
					t.Errorf("the VMM is in the launcher's %s namespace (%q)", ns, got["ns-"+ns])
				}
			}
			if alone := got["ns-net"] != own["net"]; alone != tc.ownNet {
				t.Errorf("the VMM's network namespace is its own: %v, want %v", alone, tc.ownNet)
			}
			for _, want := range []string{
				"refused " + filepath.Join(cfg.WorkDir, "opkey.iso"), "refused " + filepath.Join(cfg.WorkDir, "scratch.raw"),
				"refused " + filepath.Join(cfg.ImageDir, tdxFirmwareFile), "firmware opens",
				"opens " + device, "opens-rw " + device,
			} {
				if _, ok := got[want]; !ok {
					t.Errorf("want %q in:\n%s", want, raw)
				}
			}
			// It read both disks through the descriptors it was handed.
			if size, _ := os.ReadFile(filepath.Join(record, "scratch-size")); strings.TrimSpace(string(size)) != "67108864" {
				t.Errorf("the scratch disk it holds is %q bytes", strings.TrimSpace(string(size)))
			}
			if info, err := os.Stat(filepath.Join(record, "opkey.iso")); err != nil || info.Size() == 0 {
				t.Errorf("the launch disk it read: %v", err)
			}
			// Another user's process, stopped by the launcher all the same.
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("a requested stop is not an error: %v", err)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("Run did not return after cancel")
			}
		})
	}

	t.Run("a device its user cannot be given", func(t *testing.T) {
		if err := os.Chmod(device, 0o600); err != nil {
			t.Fatal(err)
		}
		qemu, record := fakeQEMU(t, "exit 0")
		cfg := launchConfig(t, qemu)
		cfg.Confine = &Confinement{UID: 64055, GID: 64056}
		if err := Run(context.Background(), cfg, quiet); err == nil || !strings.Contains(err.Error(), "--confine") {
			t.Fatalf("launched: %v", err)
		}
		if _, err := os.Stat(filepath.Join(record, "args")); err == nil {
			t.Fatal("QEMU was started")
		}
	})
}
