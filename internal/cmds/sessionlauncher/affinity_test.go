package sessionlauncher

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// fakeSysfs describes a machine the way sysfs does: which CPUs are online,
// and the package each is in.
func fakeSysfs(t *testing.T, online string, packages map[int]string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "devices", "system", "cpu")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "online"), []byte(online+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for cpu, id := range packages {
		topology := filepath.Join(dir, "cpu"+strconv.Itoa(cpu), "topology")
		if err := os.MkdirAll(topology, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(topology, "physical_package_id"), []byte(id+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestPackageFirstCPUs(t *testing.T) {
	// Two packages of two cores and two threads each, numbered the way a
	// kernel numbers them: the cores first, then their siblings.
	twoPackages := map[int]string{0: "0", 1: "0", 2: "1", 3: "1", 4: "0", 5: "0", 6: "1", 7: "1"}
	for name, tc := range map[string]struct {
		online   string
		packages map[int]string
		want     []int
	}{
		"one package":                  {"0-3", map[int]string{0: "0", 1: "0", 2: "0", 3: "0"}, []int{0}},
		"two packages":                 {"0-7", twoPackages, []int{0, 2}},
		"a package's first CPU is off": {"1-7", twoPackages, []int{1, 2}},
		"a package wholly off":         {"0-1,4-5", twoPackages, []int{0}},
		"one CPU":                      {"0", map[int]string{0: "0"}, []int{0}},
	} {
		got, err := packageFirstCPUs(fakeSysfs(t, tc.online, tc.packages))
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, %v; want %v", name, got, err, tc.want)
		}
	}

	for name, tc := range map[string]struct {
		online   string
		packages map[int]string
	}{
		"a CPU with no topology": {"0-1", map[int]string{0: "0"}},
		"a list that is none":    {"all", map[int]string{0: "0"}},
	} {
		if got, err := packageFirstCPUs(fakeSysfs(t, tc.online, tc.packages)); err == nil {
			t.Errorf("%s: read as %v", name, got)
		}
	}
	if got, err := packageFirstCPUs(t.TempDir()); err == nil {
		t.Errorf("a machine sysfs says nothing of: read as %v", got)
	}
}

func TestParseCPUList(t *testing.T) {
	for list, want := range map[string][]int{
		"0":           {0},
		"0-3":         {0, 1, 2, 3},
		"0,2-3,8":     {0, 2, 3, 8},
		"5-5":         {5},
		"65534-65535": {65534, 65535},
	} {
		if got, err := parseCPUList(list); err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %v, %v; want %v", list, got, err, want)
		}
	}
	for _, list := range []string{"", "a", "0-", "-1", "3-1", "0,0", "2,1", "0-2,2", "0-x", "1,,2", "0-65536", "65536"} {
		if got, err := parseCPUList(list); err == nil {
			t.Errorf("%q: read as %v", list, got)
		}
	}
}
