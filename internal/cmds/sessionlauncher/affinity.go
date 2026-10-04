package sessionlauncher

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// maxCPUs bounds a CPU number read from sysfs: more than any kernel is built
// for, and small enough to count through.
const maxCPUs = 1 << 16

// packageFirstCPUs lists the first online CPU of each package, by the
// kernel's numbering, as sysfs under root describes the machine.
//
// A TDX host writes a package's caches back before it frees a guest's key,
// and runs that write-back on those CPUs in an interrupt handler until it is
// done (tdx_mmu_release_hkid). That takes tens of milliseconds for every
// guest taken apart, and whatever runs there waits. See startAway.
func packageFirstCPUs(root string) ([]int, error) {
	dir := filepath.Join(root, "devices", "system", "cpu")
	raw, err := os.ReadFile(filepath.Join(dir, "online"))
	if err != nil {
		return nil, err
	}
	online, err := parseCPUList(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, "online"), err)
	}
	var first []int
	seen := map[string]bool{}
	for _, cpu := range online {
		path := filepath.Join(dir, "cpu"+strconv.Itoa(cpu), "topology", "physical_package_id")
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if id := strings.TrimSpace(string(raw)); !seen[id] {
			seen[id] = true
			first = append(first, cpu)
		}
	}
	return first, nil
}

// parseCPUList reads the kernel's list of CPUs, such as "0-3,8,10-11", in
// ascending order.
func parseCPUList(list string) ([]int, error) {
	var cpus []int
	for _, part := range strings.Split(list, ",") {
		from, to, ranged := strings.Cut(part, "-")
		low, err := strconv.Atoi(from)
		if err != nil {
			return nil, fmt.Errorf("CPU list %q", list)
		}
		high := low
		if ranged {
			if high, err = strconv.Atoi(to); err != nil {
				return nil, fmt.Errorf("CPU list %q", list)
			}
		}
		if high < low || high >= maxCPUs || (len(cpus) > 0 && low <= cpus[len(cpus)-1]) {
			return nil, fmt.Errorf("CPU list %q", list)
		}
		for cpu := low; cpu <= high; cpu++ {
			cpus = append(cpus, cpu)
		}
	}
	return cpus, nil
}
