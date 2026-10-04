package session

import (
	"testing"
	"time"
)

// A verdict on real evidence against documents the engine already holds:
// what a verifier pays for each guest after its first.
func BenchmarkVerifyTDXWithKeptCollateral(b *testing.B) {
	env, reportData := fixture(b)
	k := keptCollateral(b)
	engine := k.engineAt(k.newest.Add(10*time.Minute), k.intel(true), false)
	ctx := lenient()
	if _, err := engine.VerifyEvidence(ctx, env, reportData); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := engine.VerifyEvidence(ctx, env, reportData); err != nil {
			b.Fatal(err)
		}
	}
}
