package gaspstatus

import (
	"sync"
	"testing"
	"time"
)

func TestTracker_LifecycleAndSnapshot(t *testing.T) {
	clk := time.Unix(1700000000, 0)
	tr := newWithClock(1800, func() time.Time { return clk })

	// Fresh: disabled, never synced, interval carried through.
	if s := tr.Snapshot(); s.Enabled || s.InitialSyncDone || s.LastSyncUnix != 0 || s.IntervalSecs != 1800 {
		t.Fatalf("fresh tracker must be disabled/unsynced with interval 1800, got %+v", s)
	}

	// MarkEnabled flips Enabled only — NOT initial-sync-done (a running-but-not-
	// yet-synced node must not look settled).
	tr.MarkEnabled()
	if s := tr.Snapshot(); !s.Enabled || s.InitialSyncDone {
		t.Fatalf("MarkEnabled must set Enabled only, got %+v", s)
	}

	// RecordSuccess sets initial-sync-done + stamps the time.
	tr.RecordSuccess()
	if s := tr.Snapshot(); !s.InitialSyncDone || s.LastSyncUnix != clk.Unix() {
		t.Fatalf("RecordSuccess must set InitialSyncDone + LastSyncUnix, got %+v", s)
	}
}

func TestTracker_ConcurrentSafe(t *testing.T) {
	tr := New(60)
	tr.MarkEnabled()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); tr.RecordSuccess() }()
		go func() { defer wg.Done(); _ = tr.Snapshot() }()
	}
	wg.Wait()
	if s := tr.Snapshot(); !s.InitialSyncDone || !s.Enabled {
		t.Fatalf("expected enabled + synced after concurrent ops, got %+v", s)
	}
}
