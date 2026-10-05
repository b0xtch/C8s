//go:build !c8s_simtee

package sessionlauncher

import (
	"context"
	"os"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// simulation is a TEE a launcher simulates in software for its guest, in
// place of the platform's. This build simulates none and has no option that
// would: a guest it launches runs in the TEE its platform names.
type simulation struct{}

func (*simulation) flags(*pflag.FlagSet) {}

func (*simulation) on() bool { return false }

func (*simulation) open(*Config) error { return nil }

// vendor is where a guest's road to one of the vendor's services leads.
func (*simulation) vendor(service string) string { return service }

// fetcher asks the vendor for the documents a guest's host answers it with.
func (*simulation) fetcher() func(context.Context, session.CollateralPlatform) ([]session.CollateralDocument, error) {
	return session.FetchCollateral
}

// stockDir is where the launchers of one host keep those documents.
func (*simulation) stockDir(dir string) string { return dir }

// declare returns the files that stand for the hardware of a guest booted
// from firmware and disk.
func (*simulation) declare(*Config, *os.File, *os.File) ([]ISOFile, error) { return nil, nil }
