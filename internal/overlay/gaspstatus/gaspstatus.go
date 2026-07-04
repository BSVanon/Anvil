// Package gaspstatus tracks the node's GASP federation-sync state so the legacy
// /overlay/query handler can tell a client HOW CURRENT + COMPLETE this node's
// overlay view is.
//
// An overlay lookup is local-only: a 200-empty answer means "no match in this
// node's local index", which is only trustworthy as "genuinely absent" once the
// node has completed at least one federation sync. A cold-started, mid-sync, or
// sync-disabled node returns the same empty answer for a token that exists
// elsewhere in the mesh. This tracker exposes exactly the state needed to tell
// those apart — surfaced as X-Overlay-* response headers on /overlay/query so a
// caller (e.g. a wallet making a funds-safety mint/no-mint decision) can gate on
// it atomically with the answer it acts on.
package gaspstatus

import (
	"sync"
	"time"
)

// Snapshot is an immutable view of GASP sync state at a point in time.
type Snapshot struct {
	Enabled         bool  // federation sync is wired + running on this node
	InitialSyncDone bool  // at least one GASP cycle has completed successfully since boot
	LastSyncUnix    int64 // unix seconds of the last successful sync; 0 = never
	IntervalSecs    int   // configured sync cadence (for a caller's freshness gate)
}

// Tracker is a concurrency-safe holder of GASP sync state: the sync loop records
// outcomes, readers take Snapshots. Safe for concurrent use.
type Tracker struct {
	mu   sync.RWMutex
	snap Snapshot
	now  func() time.Time
}

// New returns a tracker for a node whose sync cadence is intervalSecs. It starts
// DISABLED: call MarkEnabled once the sync loop is actually launched. A node with
// federation sync gated off therefore reports Enabled=false, so its empty answers
// are never mistaken for a settled, mesh-complete view.
func New(intervalSecs int) *Tracker {
	return newWithClock(intervalSecs, time.Now)
}

func newWithClock(intervalSecs int, now func() time.Time) *Tracker {
	return &Tracker{snap: Snapshot{IntervalSecs: intervalSecs}, now: now}
}

// MarkEnabled records that the GASP sync loop is running on this node.
func (t *Tracker) MarkEnabled() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.snap.Enabled = true
}

// RecordSuccess marks a completed sync cycle: it sets InitialSyncDone and stamps
// the time. A cycle that reached the federation without error counts even if it
// pulled nothing new — the node's view is then as complete as the federation
// offers. Once set, InitialSyncDone stays set (a later transient failure does not
// un-populate the index); staleness is instead conveyed by LastSyncUnix aging
// against IntervalSecs.
func (t *Tracker) RecordSuccess() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.snap.InitialSyncDone = true
	t.snap.LastSyncUnix = t.now().Unix()
}

// Snapshot returns the current state.
func (t *Tracker) Snapshot() Snapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.snap
}
