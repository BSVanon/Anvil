package gossip

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// The manager-wide allowUnstoredRelay budget (relay_budget.go): an exact,
// fake-clock-driven bound on how many forwards a node relays without
// holding its own stored copy, for both a node that stores other
// messages (TestAllowUnstoredRelayBoundsForwardCopyTTLZeroFlood) and a
// node with no message store at all (TestRelayOnlyNodeBoundByUnstoredRelayBudget).

// relayBudgetClock is a fake, manually-advanced clock for driving
// allowUnstoredRelay's token bucket (relay_budget.go) in tests without
// depending on real wall-clock time. An exact-equality assertion against
// the real clock used to flake under -race once a long enough
// synchronous call loop let a token or two legitimately refill
// mid-flood (observed 52-53 of 70, not exactly 50); a fake clock removes
// the dependency on how long the loop actually takes.
type relayBudgetClock struct {
	mu  sync.Mutex
	now time.Time
}

func newRelayBudgetClock() *relayBudgetClock {
	return &relayBudgetClock{now: time.Unix(1_800_000_000, 0)}
}

func (c *relayBudgetClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *relayBudgetClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// floodUnstoredRelay sends n distinct forwards for sender/recipient
// through mgr.onMsgForward, each with a unique MessageID so none of them
// collide in the per-connection dedup set.
func floodUnstoredRelay(t *testing.T, mgr *Manager, senderKey *ec.PrivateKey, sender, recipient, idPrefix string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		msg := sampleMsg(sender, recipient)
		msg.MessageID = fmt.Sprintf("%s-%d", idPrefix, i)
		raw, err := json.Marshal(legacyForward(t, senderKey, msg))
		if err != nil {
			t.Fatal(err)
		}
		if err := mgr.onMsgForward("peer", raw); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAllowUnstoredRelayBoundsForwardCopyTTLZeroFlood proves the relay
// bound with forward_copy_ttl=0: a flood of distinct messages this node
// never stores is NOT all relayed — the manager-wide allowUnstoredRelay
// budget caps it at exactly its burst size, then lets through exactly
// its per-second refill rate as the (fake) clock advances, even though
// the per-peer entry bucket (burst 100, default) lets all of them
// through to onMsgForward in the first place. The 50 and 10 below are
// deliberately literal, not references to unstoredRelayBurst/
// unstoredRelayRate: that's what makes a doubled burst or a doubled
// rate in relay_budget.go show up here as a wrong number instead of
// silently relabeling what "correct" means.
func TestAllowUnstoredRelayBoundsForwardCopyTTLZeroFlood(t *testing.T) {
	store := newForwardTestStore(t)
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	mgr.SetMessagingPolicy(MessagingPolicy{ForwardCopyTTLSeconds: ttlPtr(0)})
	clock := newRelayBudgetClock()
	mgr.unstoredRelay.nowFunc = clock.Now
	relays := observeForwardRelays(t, mgr)

	senderKey, sender := newID(t)
	_, recipient := newID(t)

	// t=0: a flood of 70 arrives instantly (the clock never moves on its
	// own); exactly the burst of 50 gets through.
	floodUnstoredRelay(t, mgr, senderKey, sender, recipient, "flood-t0", 70)
	if *relays != 50 {
		t.Fatalf("relays at t=0 = %d, want exactly 50 (the burst)", *relays)
	}
	if store.Count() != 0 {
		t.Fatalf("store count = %d, want 0 (forward_copy_ttl=0 never stores)", store.Count())
	}

	// Advance one simulated second: exactly 10 more tokens (the per-second
	// rate) refill, so exactly 10 more of a fresh flood get through.
	clock.Advance(1 * time.Second)
	*relays = 0
	floodUnstoredRelay(t, mgr, senderKey, sender, recipient, "flood-t1", 70)
	if *relays != 10 {
		t.Fatalf("relays after +1s = %d, want exactly 10 (the per-second refill)", *relays)
	}
}

// TestRelayOnlyNodeBoundByUnstoredRelayBudget: a node with no message
// store at all (SetMsgStore never called) used to relay every forward
// unconditionally, bypassing the manager-wide allowUnstoredRelay budget
// that every OTHER unstored-relay path (a stored node's non-home/quota
// branches) already respects. It must share the same bound, with the
// same fake-clock exactness as
// TestAllowUnstoredRelayBoundsForwardCopyTTLZeroFlood above.
func TestRelayOnlyNodeBoundByUnstoredRelayBudget(t *testing.T) {
	mgr := NewManager(ManagerConfig{Logger: slog.Default()}) // no SetMsgStore: relay-only
	clock := newRelayBudgetClock()
	mgr.unstoredRelay.nowFunc = clock.Now
	relays := observeForwardRelays(t, mgr)

	senderKey, sender := newID(t)
	_, recipient := newID(t)

	floodUnstoredRelay(t, mgr, senderKey, sender, recipient, "relay-only-t0", 70)
	if *relays != 50 {
		t.Fatalf("relay-only node: relays at t=0 = %d, want exactly 50 (the burst)", *relays)
	}

	clock.Advance(1 * time.Second)
	*relays = 0
	floodUnstoredRelay(t, mgr, senderKey, sender, recipient, "relay-only-t1", 70)
	if *relays != 10 {
		t.Fatalf("relay-only node: relays after +1s = %d, want exactly 10 (the per-second refill)", *relays)
	}
}
