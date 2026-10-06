//go:build !linux

package sessionagent

import "errors"

// startKeyHelper has no helper to start: a guest runs Linux.
func startKeyHelper([]string) (*keyHelper, error) {
	return nil, errors.New("the key helper runs on Linux only")
}

func helperMemory(int) (resident, own int) { return 0, 0 }
