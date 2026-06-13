// Package peerhygiene keeps the node from repeatedly hammering dead overlay
// peers. The canonical SLAP/SHIP discovery returns whatever is advertised on the
// shared trackers — including stale junk (dead ngrok tunnels, 404ing railway
// apps, hosts serving the wrong TLS cert). Without hygiene the node re-queries
// every one of them on every GASP sync and lookup resolution, burning time and
// flooding logs ("Error querying host ...") — exactly the federation thrash the
// DEX reported alongside the submit-500.
//
// The fix is a thin wrapper around the go-sdk lookup Facilitator: a host that
// fails repeatedly is short-circuited (skipped without an HTTP call) for an
// exponentially growing, capped backoff window, and reinstated the moment it
// succeeds again. State is in-memory — dead peers are re-learned within a sync
// round, so it isn't worth persisting.
package peerhygiene

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

// Tuning for the failure tracker. A peer is only backed off after a couple of
// failures (a single blip is tolerated); the window then doubles each time the
// host fails AGAIN after a prior window expired — so a burst of per-topic
// failures within one sync collapses to a single step rather than rocketing to
// the cap — up to a maximum, and clears on the first success.
const (
	defaultFailuresBeforeBackoff = 2
	defaultBaseBackoff           = 1 * time.Minute
	defaultMaxBackoff            = 1 * time.Hour
)

// ErrHostInBackoff is returned — without making an HTTP call — when a host is
// being skipped because it recently failed repeatedly.
var ErrHostInBackoff = errors.New("peerhygiene: host in backoff, skipped")

// tracker records per-host failure state. Safe for concurrent use: the resolver
// fans out one goroutine per host.
type tracker struct {
	mu    sync.Mutex
	hosts map[string]*hostState
	now   func() time.Time

	failuresBeforeBackoff int
	baseBackoff           time.Duration
	maxBackoff            time.Duration
}

type hostState struct {
	failures     int
	backoffUntil time.Time
}

func newTracker(now func() time.Time) *tracker {
	if now == nil {
		now = time.Now
	}
	return &tracker{
		hosts:                 make(map[string]*hostState),
		now:                   now,
		failuresBeforeBackoff: defaultFailuresBeforeBackoff,
		baseBackoff:           defaultBaseBackoff,
		maxBackoff:            defaultMaxBackoff,
	}
}

// inBackoff reports whether host is currently being skipped.
func (t *tracker) inBackoff(host string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.hosts[host]
	return st != nil && t.now().Before(st.backoffUntil)
}

// recordSuccess clears a host's failure state. Returns true if the host had been
// backed off (so the caller can log the recovery).
func (t *tracker) recordSuccess(host string) (wasBackedOff bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.hosts[host]
	if !ok {
		return false
	}
	wasBackedOff = !st.backoffUntil.IsZero()
	delete(t.hosts, host)
	return wasBackedOff
}

// recordFailure increments a host's failure count and, once it crosses the
// threshold, sets an exponentially growing (capped) backoff. Returns the backoff
// deadline (zero until the threshold is crossed) for logging.
func (t *tracker) recordFailure(host string) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.hosts[host]
	if st == nil {
		st = &hostState{}
		t.hosts[host] = st
	}
	now := t.now()
	// A failure that lands while an existing backoff window is still active is a
	// concurrent / within-burst failure — e.g. the same dead host queried once
	// per topic in a single GASP sync. It must NOT escalate the window: otherwise
	// a many-topic sync would rocket a host to the cap in one round, making a
	// transient one-sync outage stick for hours. Escalation only happens for a
	// fresh failure AFTER the host was given another chance (its prior window
	// expired).
	if !st.backoffUntil.IsZero() && now.Before(st.backoffUntil) {
		return st.backoffUntil
	}
	st.failures++
	if st.failures < t.failuresBeforeBackoff {
		return time.Time{}
	}
	// Double the base window once per escalation past the threshold, capped. Loop
	// (not a shift) so it can't overflow the duration on a long-dead host.
	backoff := t.baseBackoff
	for i := t.failuresBeforeBackoff; i < st.failures && backoff < t.maxBackoff; i++ {
		backoff *= 2
	}
	if backoff > t.maxBackoff {
		backoff = t.maxBackoff
	}
	st.backoffUntil = now.Add(backoff)
	return st.backoffUntil
}

// Facilitator wraps a lookup.Facilitator with dead-peer hygiene. Hosts that
// repeatedly fail are skipped for a growing backoff window instead of being
// re-queried every round.
type Facilitator struct {
	inner   lookup.Facilitator
	tracker *tracker
	logger  *slog.Logger
}

// compile-time assertion that we satisfy the go-sdk interface.
var _ lookup.Facilitator = (*Facilitator)(nil)

// NewFacilitator wraps inner (the real HTTP facilitator) with hygiene tracking.
// logger may be nil (falls back to slog.Default()).
func NewFacilitator(inner lookup.Facilitator, logger *slog.Logger) *Facilitator {
	return newFacilitatorWithClock(inner, logger, nil)
}

func newFacilitatorWithClock(inner lookup.Facilitator, logger *slog.Logger, now func() time.Time) *Facilitator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Facilitator{inner: inner, tracker: newTracker(now), logger: logger}
}

// Lookup short-circuits hosts in backoff; otherwise it delegates and records the
// outcome. A successful response clears any prior failure; a failure counts
// toward backoff — except context cancellation, which is our own teardown (e.g.
// node shutdown) and not the host's fault.
func (f *Facilitator) Lookup(ctx context.Context, url string, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	if f.tracker.inBackoff(url) {
		return nil, fmt.Errorf("%w: %s", ErrHostInBackoff, url)
	}

	answer, err := f.inner.Lookup(ctx, url, question)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			// Our cancellation, not a peer fault — don't penalise the host.
			return nil, err
		}
		if deadline := f.tracker.recordFailure(url); !deadline.IsZero() {
			f.logger.Warn("overlay peer backed off after repeated lookup failures",
				"host", url, "backoff_until", deadline, "error", err)
		}
		return nil, err
	}

	if f.tracker.recordSuccess(url) {
		f.logger.Info("overlay peer recovered, backoff cleared", "host", url)
	}
	return answer, nil
}
