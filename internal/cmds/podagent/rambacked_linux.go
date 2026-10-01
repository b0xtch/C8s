//go:build linux

package podagent

import "github.com/confidential-dot-ai/c8s/internal/fileutil"

func requireRAMBacked(dir string) error { return fileutil.RequireRAMBacked(dir) }
