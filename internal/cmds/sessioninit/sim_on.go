//go:build c8s_simtee

package sessioninit

import (
	"crypto/sha512"
	"fmt"
	"path"
)

// simRegisterPath is where a simulated guest keeps RTMR[3]: a file in the
// guest's memory, which its agent extends (internal/simtee.RegisterPath).
const simRegisterPath = "/run/c8s-simtee/rtmr3"

// tdxDevice is the device a trust domain's kernel has.
const tdxDevice = "/dev/tdx_guest"

// bindSimulated is the init of a build whose TEE is simulated in software
// (docs/session-performance.md): it extends the launch key's digest into a
// register it makes in memory, as a TDX module's RTMR[3] would hold it. It
// protects nothing, and it runs in no guest that has a TEE.
func bindSimulated(p platform, key []byte) (bool, error) {
	for _, tee := range []string{rtmr3Path, tdxDevice, sevGuest} {
		if p.Exists(tee) {
			return false, fmt.Errorf("this image simulates a TEE and this guest has one (%s): a simulation build runs in none", tee)
		}
	}
	digest := sha512.Sum384(key)
	h := sha512.New384()
	h.Write(make([]byte, sha512.Size384))
	h.Write(digest[:])
	register := newRoot + simRegisterPath
	if err := p.MkdirAll(path.Dir(register), 0o700); err != nil {
		return false, err
	}
	if err := p.WriteFile(register, h.Sum(nil), 0o600); err != nil {
		return false, fmt.Errorf("simulated RTMR[3]: %w", err)
	}
	// The image's build looks for the tag's name in the program's own text.
	p.Log("launch key: its digest is extended into a register kept in memory: this guest's TEE is simulated and protects nothing (c8s_simtee)")
	return true, nil
}
