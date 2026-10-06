package sessionagent

import (
	"strconv"
	"strings"
)

// A kernel says once, as it starts, what memory it zeroes: its build and its
// command line decide that, and the line gives what came of both. It begins
// with freedMemoryLine, and ends with freedMemoryOn when the kernel zeroes
// every page and every object it frees.
const (
	freedMemoryLine = "mem auto-init: stack:"
	freedMemoryOn   = ", heap free:on"
)

// freedMemoryRecord reads one record of a kernel's log as /dev/kmsg gives
// it, and returns the kernel's line on the memory it zeroes, or "" for any
// other record. A record a program wrote is another: it says nothing of the
// kernel, whatever its text.
func freedMemoryRecord(record string) string {
	head, text, ok := strings.Cut(record, ";")
	if !ok {
		return ""
	}
	// A record's first field is eight times its facility plus its level,
	// and the kernel's own facility is 0.
	priority, _, _ := strings.Cut(head, ",")
	if n, err := strconv.ParseUint(priority, 10, 32); err != nil || n>>3 != 0 {
		return ""
	}
	text, _, _ = strings.Cut(text, "\n")
	if !strings.HasPrefix(text, freedMemoryLine) {
		return ""
	}
	return text
}

// zeroesFreedMemory reports whether a kernel's line on the memory it zeroes
// says that it zeroes what it frees.
func zeroesFreedMemory(line string) bool {
	return strings.HasPrefix(line, freedMemoryLine) && strings.HasSuffix(line, freedMemoryOn)
}
