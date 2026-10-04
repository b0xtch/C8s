//go:build linux

package sessionagent

import "github.com/confidential-dot-ai/c8s/internal/fileutil"

func requireRAMBacked(dir string) error { return fileutil.RequireRAMBacked(dir) }
