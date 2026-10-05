//go:build !linux

package main

import "errors"

// affinity keeps VMMs to CPUs on Linux alone, where the VMM runs.
func affinity(list string) (func() (func(), error), error) {
	if list != "" {
		return nil, errors.New("CPUs are named on Linux alone")
	}
	return func() (func(), error) { return func() {}, nil }, nil
}
