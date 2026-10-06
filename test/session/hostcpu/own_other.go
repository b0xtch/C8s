//go:build !unix

package hostcpu

func own() int64 { return 0 }
