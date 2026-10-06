package hostcpu

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// What a process's threads waited for a processor is the sum of the second
// count the scheduler keeps for each, and a thread with no such count, or a
// system with no such list, adds nothing.
func TestWaitedSumsEachThreadsWait(t *testing.T) {
	dir := t.TempDir()
	for name, stat := range map[string]string{"11": "5000000 2000000 7\n", "12": "100 3500000 1\n", "13": "gone", "14": ""} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if stat == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name, "schedstat"), []byte(stat), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := waited(dir); got != 5500 {
		t.Fatalf("the threads waited %d us, want 5500", got)
	}
	if got := waited(filepath.Join(dir, "none")); got != 0 {
		t.Fatalf("a system with no list of threads: %d", got)
	}
}

// A host's CPU is the usage line of its root control group, whatever else
// the file holds, and nothing is read from a file without one.
func TestUsageInFindsTheHostsCPU(t *testing.T) {
	const stat = "user_usec 233096372000\nusage_usec 324961085000\nsystem_usec 91864713000\nnr_periods 0\n"
	if got, ok := usageIn([]byte(stat)); !ok || got != 324961085000 {
		t.Fatalf("the host gave %d (%v)", got, ok)
	}
	for name, stat := range map[string]string{
		"no such line":         "user_usec 1\nsystem_usec 2\n",
		"a line with no count": "usage_usec\n",
		"a count that is none": "usage_usec much\n",
		"an empty file":        "",
	} {
		if got, ok := usageIn([]byte(stat)); ok {
			t.Errorf("%s: read %d", name, got)
		}
	}
}

// What was given between two readings is the difference of each count, and
// a process that works has taken some of it.
func TestSinceIsTheDifference(t *testing.T) {
	if got := (Reading{Host: 150, Own: 30, Waited: 9}).Since(Reading{Host: 100, Own: 10, Waited: 4}); got != (Reading{Host: 50, Own: 20, Waited: 5}) {
		t.Fatalf("between the readings: %+v", got)
	}
	before, began := own(), time.Now()
	for n := 0; own()-before < 2000; n++ {
		if time.Since(began) > 10*time.Second {
			t.Fatal("a process that spun for ten seconds took no CPU of its own")
		}
		_ = n * n
	}
}
