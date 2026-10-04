package sessionagent

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// pciKind names one kind of PCI function by its vendor and device ids.
type pciKind struct{ vendor, device uint16 }

// sessionDevices are the kinds of PCI function a session guest's launcher
// builds it, each with the class it must say it is of: the board's two
// bridges, and virtio devices of the current kind for its network, its
// disks and its socket to the host.
var sessionDevices = map[pciKind]uint16{
	{0x8086, 0x29c0}: 0x0600, // host bridge
	{0x8086, 0x2918}: 0x0601, // ISA bridge
	{0x1af4, 0x1041}: 0x0200, // virtio network device
	{0x1af4, 0x1042}: 0x0100, // virtio block device
	{0x1af4, 0x1053}: 0x0780, // virtio socket device
}

// consoleDevice is the virtio console of a dev guest.
var consoleDevice = pciKind{0x1af4, 0x1043}

const consoleClass = 0x0780

// DeviceGuard checks that the guest's PCI bus holds nothing but what a
// session guest is given. RTMR[0] records the shape its host declared to the
// firmware, and does not say what stands behind each slot: a host can put
// another device in one. The guest's kernel has a driver for none but its
// own, so such a device meets no code, and a guest that finds one is not on
// the machine its class describes. It ends.
type DeviceGuard struct {
	// Devices is the kernel's list of PCI functions, /sys/bus/pci/devices.
	Devices string
	// Console allows the virtio console a dev guest has.
	Console bool
}

// Check fails if the bus holds a function of another kind, or one that says
// it is of another class than its kind.
func (g DeviceGuard) Check() error {
	entries, err := os.ReadDir(g.Devices)
	if err != nil {
		return fmt.Errorf("the guest's PCI functions: %w", err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("the guest's PCI functions: %s lists none", g.Devices)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		read := func(file string) (uint64, error) {
			data, err := os.ReadFile(filepath.Join(g.Devices, name, file))
			if err != nil {
				return 0, err
			}
			return strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(string(data)), "0x"), 16, 32)
		}
		vendor, err := read("vendor")
		if err != nil {
			return fmt.Errorf("PCI function %s: %w", name, err)
		}
		device, err := read("device")
		if err != nil {
			return fmt.Errorf("PCI function %s: %w", name, err)
		}
		// Base class, subclass and programming interface: the last is not
		// part of what a kind is.
		class, err := read("class")
		if err != nil {
			return fmt.Errorf("PCI function %s: %w", name, err)
		}
		kind := pciKind{uint16(vendor), uint16(device)}
		want, known := sessionDevices[kind]
		if !known && g.Console && kind == consoleDevice {
			want, known = consoleClass, true
		}
		if !known || uint16(class>>8) != want {
			return fmt.Errorf("PCI function %s (%04x:%04x, class %06x) is none a session guest is given: its host built another machine",
				name, vendor, device, class)
		}
	}
	return nil
}
