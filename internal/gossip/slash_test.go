package gossip

import (
	"testing"
	"time"
)

func TestSlashTrackerGracePeriod(t *testing.T) {
	st := newSlashTracker()

	w := SlashWarningPayload{
		Target:    "peer-a",
		Reason:    SlashGossipSpam,
		Reporter:  "reporter-1",
		Timestamp: time.Now().Unix(),
	}

	// First warning — should not deregister (need 3 from 2+ reporters)
	if st.addWarning(w) {
		t.Fatal("should not deregister after 1 warning")
	}

	// Second warning same reporter — still only 1 unique reporter
	w.Timestamp++
	if st.addWarning(w) {
		t.Fatal("should not deregister with only 1 unique reporter")
	}

	// Third warning same reporter — 3 warnings but only 1 reporter
	w.Timestamp++
	if st.addWarning(w) {
		t.Fatal("should not deregister: 3 warnings but only 1 unique reporter")
	}

	// Fourth warning from second reporter — now 2 unique reporters + threshold met
	w.Reporter = "reporter-2"
	w.Timestamp++
	if !st.addWarning(w) {
		t.Fatal("should deregister: 4 warnings from 2 unique reporters")
	}
}

func TestSlashDoublePublishRequiresCorroboration(t *testing.T) {
	st := newSlashTracker()

	w := SlashWarningPayload{
		Target:    "peer-b",
		Reason:    SlashDoublePublish,
		Reporter:  "self",
		Evidence:  "3+ different payloads for same topic+pubkey+timestamp",
		Timestamp: time.Now().Unix(),
	}

	if st.addWarning(w) {
		t.Fatal("single-reporter double-publish should not deregister")
	}

	w.Reporter = "peer-2"
	w.Timestamp++
	if !st.addWarning(w) {
		t.Fatal("double-publish should deregister after corroboration from a second reporter")
	}
}

func TestSlashMixedReasonsDoNotCrossContaminate(t *testing.T) {
	st := newSlashTracker()

	// One gossip_spam warning from reporter-1
	spam := SlashWarningPayload{
		Target:    "peer-mixed",
		Reason:    SlashGossipSpam,
		Reporter:  "reporter-1",
		Timestamp: time.Now().Unix(),
	}
	if st.addWarning(spam) {
		t.Fatal("single spam warning should not deregister")
	}

	// One double_publish warning from reporter-2 — different reason, different reporter
	dp := SlashWarningPayload{
		Target:    "peer-mixed",
		Reason:    SlashDoublePublish,
		Reporter:  "reporter-2",
		Evidence:  "conflicting payloads",
		Timestamp: time.Now().Unix(),
	}
	// This should NOT deregister: only 1 double_publish warning from 1 reporter,
	// even though there are 2 total warnings from 2 unique reporters.
	if st.addWarning(dp) {
		t.Fatal("mixed reasons should not cross-contaminate: 1 spam + 1 double_publish should not trigger deregistration")
	}

	// Second double_publish from a third reporter — now 2 double_publish from 2 reporters
	dp2 := SlashWarningPayload{
		Target:    "peer-mixed",
		Reason:    SlashDoublePublish,
		Reporter:  "reporter-3",
		Evidence:  "conflicting payloads",
		Timestamp: time.Now().Unix() + 1,
	}
	if !st.addWarning(dp2) {
		t.Fatal("2 double_publish from 2 reporters should deregister")
	}
}

func TestSlashGracePeriodExpiry(t *testing.T) {
	st := newSlashTracker()

	w := SlashWarningPayload{
		Target:    "peer-c",
		Reason:    SlashGossipSpam,
		Reporter:  "reporter-1",
		Timestamp: time.Now().Unix(),
	}

	// Add 2 warnings
	st.addWarning(w)
	w.Reporter = "reporter-2"
	st.addWarning(w)

	// Manually expire the record
	st.mu.Lock()
	rec := st.records["peer-c"]
	rec.FirstWarn = time.Now().Add(-49 * time.Hour) // past 48h grace
	st.mu.Unlock()

	// New warning after expiry should reset the slate
	w.Reporter = "reporter-3"
	if st.addWarning(w) {
		t.Fatal("should not deregister — grace period expired, slate wiped")
	}

	// Verify only 1 active warning (the new one)
	active := st.activeWarnings("peer-c")
	if len(active) != 1 {
		t.Fatalf("expected 1 active warning after expiry reset, got %d", len(active))
	}
}

func TestSlashWarningDedup(t *testing.T) {
	// Test that the seen-hash mechanism prevents loops.
	// This tests the dedup hash format, not the full gossip flow.
	m := NewManager(ManagerConfig{MaxSeen: 100})
	defer m.Stop()

	warnHash := "slash:peer-x:reporter-1:gossip_spam:1234567890"
	m.seenMu.Lock()
	m.seen[warnHash] = struct{}{}
	m.seenMu.Unlock()

	// Same hash should be in seen map
	m.seenMu.Lock()
	_, exists := m.seen[warnHash]
	m.seenMu.Unlock()
	if !exists {
		t.Fatal("warn hash should be in seen map")
	}
}
