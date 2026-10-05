package sessiond

import (
	"cmp"
	"slices"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
)

// maxEventWatchers bounds the streams that watch the host's TDs.
const maxEventWatchers = 16

// shownTD is what a stream last showed of a TD.
type shownTD struct {
	state         State
	session, pool string
}

// forgotten is why a TD is shown as ended when the daemon kept its record no
// longer than a stream took to read on.
const forgotten = "ended, and its record is kept no more"

// Watch streams what becomes of the host's TDs to an orchestrator: each TD
// as it is now, oldest first, then each as it changes. A stream shows a TD
// as it is, so one that changed twice between two messages is shown once.
// That is enough for an orchestrator to know every session its hosts serve,
// also one that a binder's bind started with no claim: such a TD is shown
// with its session and the binder that claimed it.
func (d *Daemon) Watch(_ *sessionv1alpha1.WatchRequest, stream sessionv1alpha1.Sessions_WatchServer) error {
	ctx := stream.Context()
	d.mu.Lock()
	if d.eventWatchers >= maxEventWatchers {
		d.mu.Unlock()
		return status.Error(codes.ResourceExhausted, "too many streams watch this host's TDs")
	}
	d.eventWatchers++
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.eventWatchers--
		d.mu.Unlock()
	}()

	shown := map[string]shownTD{}
	for {
		due, changed := d.eventsUnshown(shown)
		for _, event := range due {
			if err := stream.Send(event); err != nil {
				return err
			}
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case <-d.stop:
			return status.Error(codes.Unavailable, "the daemon is stopping")
		}
	}
}

// eventsUnshown returns the TDs that are no longer as shown has them, oldest
// first, and brings shown up to them. changed is closed when a TD next
// changes.
func (d *Daemon) eventsUnshown(shown map[string]shownTD) (due []*sessionv1alpha1.Event, changed <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	tds := make([]*td, 0, len(d.tds))
	for _, t := range d.tds {
		tds = append(tds, t)
	}
	slices.SortFunc(tds, func(a, b *td) int {
		if c := a.rec.Created.Compare(b.rec.Created); c != 0 {
			return c
		}
		return cmp.Compare(a.rec.ID, b.rec.ID)
	})
	for _, t := range tds {
		is := shownTD{state: t.rec.State, session: t.session(), pool: t.rec.Pool}
		if shown[t.rec.ID] == is {
			continue
		}
		shown[t.rec.ID] = is
		due = append(due, d.event(t, now))
	}
	// A record the daemon keeps no more is an ended TD's. A stream that read
	// on too slowly to be shown its end is told of it now.
	var gone []string
	for id, was := range shown {
		if _, kept := d.tds[id]; kept {
			continue
		}
		delete(shown, id)
		if was.state != StateEnded {
			gone = append(gone, id)
			due = append(due, &sessionv1alpha1.Event{
				Td: id, Pool: was.pool, Host: d.cfg.Host, State: sessionv1alpha1.TDState_TD_STATE_ENDED,
				Session: was.session, Reason: forgotten, At: timestamppb.New(now),
			})
		}
	}
	if len(gone) > 1 {
		// Map order is none: the same events in the same order each time.
		tail := due[len(due)-len(gone):]
		slices.SortFunc(tail, func(a, b *sessionv1alpha1.Event) int { return cmp.Compare(a.GetTd(), b.GetTd()) })
	}
	return due, d.changed
}

// event is a TD as it is. The caller holds the lock.
func (d *Daemon) event(t *td, now time.Time) *sessionv1alpha1.Event {
	event := &sessionv1alpha1.Event{
		Td: t.rec.ID, Pool: t.rec.Pool, Host: d.cfg.Host, State: stateOf(t.rec.State), Session: t.session(), At: timestamppb.New(now),
	}
	// Only a bind that claimed its TD names a binder.
	if claim := t.rec.Claim; claim != nil {
		event.ClaimedBy = claim.Binder
	}
	if ended := t.rec.Ended; ended != nil {
		event.Reason, event.At = ended.Reason, timestamppb.New(ended.At)
	}
	return event
}

func stateOf(state State) sessionv1alpha1.TDState {
	switch state {
	case StateBooting:
		return sessionv1alpha1.TDState_TD_STATE_BOOTING
	case StateReady:
		return sessionv1alpha1.TDState_TD_STATE_READY
	case StateClaimed:
		return sessionv1alpha1.TDState_TD_STATE_CLAIMED
	case StateBound:
		return sessionv1alpha1.TDState_TD_STATE_BOUND
	case StateRunning:
		return sessionv1alpha1.TDState_TD_STATE_RUNNING
	case StateEnded:
		return sessionv1alpha1.TDState_TD_STATE_ENDED
	}
	return sessionv1alpha1.TDState_TD_STATE_UNSPECIFIED
}
