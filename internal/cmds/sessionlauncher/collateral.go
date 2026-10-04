package sessionlauncher

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

// feedPace is how often a launcher hands its guest Intel's documents. Intel
// signs them anew about once an hour and a verifier takes one for two hours
// from Intel's date on it, so a third of an hour leaves room for a round
// that fails.
type feedPace struct {
	// every is the time between two rounds that worked.
	every time.Duration
	// knock is how soon the launcher asks again a guest that did not answer.
	// It doubles from there: up to booting while the guest can still be on
	// its way up, for boot from the feeder's start, so that a guest has its
	// documents about as soon as it serves, and up to retry after that, for
	// a guest whose image takes no hand-in.
	knock, booting, boot time.Duration
	// retry is the time after a round that failed.
	retry time.Duration
	// fetch bounds one round's fetch from Intel.
	fetch time.Duration
}

var collateralPace = feedPace{
	every: 20 * time.Minute, knock: 250 * time.Millisecond, booting: time.Second, boot: 2 * time.Minute,
	retry: 30 * time.Second, fetch: 30 * time.Second,
}

// maxPlatformLine bounds the one line a guest sends its host.
const maxPlatformLine = 256

// errNoAnswer is a guest that took no connection: one that is not up yet, or
// one whose image takes no hand-in.
var errNoAnswer = errors.New("the guest does not answer")

// feeder hands one guest Intel's documents for its platform: see
// session.CollateralVsockPort. Nothing a guest or a verifier trusts rests on
// it. A verifier checks Intel's signature on each document and Intel's own
// date in it, so a launcher that hands in nothing, or anything else, costs a
// verifier a fetch from Intel.
type feeder struct {
	// dial opens a connection to the guest's hand-in port.
	dial func() (io.ReadWriteCloser, error)
	// fetch asks Intel for a platform's documents.
	fetch func(context.Context, session.CollateralPlatform) ([]session.CollateralDocument, error)
	pace  feedPace
	log   *slog.Logger
	// wait, when set, stands in for the time between two rounds. It reports
	// false once ctx has ended.
	wait func(ctx context.Context, d time.Duration) bool
	// now, when set, stands in for the clock.
	now func() time.Time
}

// run hands the guest its documents now and again until ctx ends.
func (f *feeder) run(ctx context.Context) {
	clock := f.now
	if clock == nil {
		clock = time.Now
	}
	started := clock()
	knock, handed, failing := f.pace.knock, false, false
	for {
		wait := f.pace.every
		switch err := f.round(ctx); {
		case err == nil:
			if !handed || failing {
				f.log.Info("handed the guest Intel's collateral for its platform")
			}
			knock, handed, failing = f.pace.knock, true, false
		case errors.Is(err, errNoAnswer):
			wait = knock
			slowest := f.pace.retry
			if clock().Sub(started) < f.pace.boot {
				slowest = f.pace.booting
			}
			knock = min(2*knock, slowest)
		default:
			if !failing && ctx.Err() == nil {
				f.log.Warn("the guest goes without Intel's collateral for now, and its verifiers ask Intel", "error", err)
			}
			wait, failing = f.pace.retry, true
		}
		if !f.pause(ctx, wait) {
			return
		}
	}
}

func (f *feeder) pause(ctx context.Context, d time.Duration) bool {
	if f.wait != nil {
		return f.wait(ctx, d)
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// round asks the guest which platform it is, fetches Intel's documents for
// it, and hands them in. The guest is asked twice, so that it waits for no
// fetch: its connection has a short deadline of its own.
func (f *feeder) round(ctx context.Context) error {
	platform, conn, err := f.ask()
	if err != nil {
		return err
	}
	_ = conn.Close()
	fetching, cancel := context.WithTimeout(ctx, f.pace.fetch)
	docs, err := f.fetch(fetching, platform)
	cancel()
	if err != nil {
		return fmt.Errorf("fetch Intel's collateral: %w", err)
	}
	blob, err := json.Marshal(session.CollateralResponse{Documents: docs})
	if err != nil {
		return err
	}
	if len(blob) > session.MaxCollateralBytes {
		return fmt.Errorf("the collateral is %d bytes, and a guest takes %d", len(blob), session.MaxCollateralBytes)
	}
	again, conn, err := f.ask()
	if err != nil {
		return err
	}
	defer conn.Close()
	if again != platform {
		return errors.New("the guest names another platform than a moment ago")
	}
	if _, err := conn.Write(blob); err != nil {
		return fmt.Errorf("hand the guest Intel's collateral: %w", err)
	}
	return nil
}

// ask opens a connection and reads which platform the guest says it is. What
// a guest says decides what its host fetches, so it is held to the two values
// of a fixed shape that Intel's URLs are built from.
func (f *feeder) ask() (session.CollateralPlatform, io.ReadWriteCloser, error) {
	var platform session.CollateralPlatform
	conn, err := f.dial()
	if err != nil {
		return platform, nil, fmt.Errorf("%w: %w", errNoAnswer, err)
	}
	line, err := bufio.NewReaderSize(io.LimitReader(conn, maxPlatformLine), maxPlatformLine).ReadBytes('\n')
	if err != nil {
		_ = conn.Close()
		// A guest that takes the connection and says nothing has no platform
		// to name yet.
		if len(line) == 0 {
			return platform, nil, fmt.Errorf("%w: %w", errNoAnswer, err)
		}
		return platform, nil, fmt.Errorf("the guest's platform: a line of %d bytes and no end", len(line))
	}
	if err := json.Unmarshal(line, &platform); err != nil {
		_ = conn.Close()
		return platform, nil, fmt.Errorf("the guest's platform: %w", err)
	}
	if _, err := platform.URLs(); err != nil {
		_ = conn.Close()
		return platform, nil, fmt.Errorf("the guest's platform: %w", err)
	}
	return platform, conn, nil
}
