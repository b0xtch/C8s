//go:build !linux

package sessionagent

import "errors"

func idleThread() error { return errors.New("no idle scheduling class on this system") }
