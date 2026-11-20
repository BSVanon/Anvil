package gossip

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// deliverForward's decision-3 policy table (handlers_msg_policy.go): what
// Home, Unadvertised, and Elsewhere recipients each do with an incoming
// forward (store, relay, both, or neither). The relay-budget exactness
// tests live in relay_budget_test.go and the forward_peers allow-list
// tests live in forward_peers_test.go.

func newForwardTestStore(t *testing.T) *messaging.Store {
	t.Helper()
	s, err := messaging.NewStore(t.TempDir(), messaging.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// stubHomeResolver is a fixed-answer messaging.HomeResolver for decision
// 3's gossip-side table tests, below.
type stubHomeResolver struct {
	state        messaging.HomeState
	hasOtherHost bool
}

func (s stubHomeResolver) Resolve(string) (messaging.Resolution, error) {
	return messaging.Resolution{State: s.state, HasOtherHost: s.hasOtherHost}, nil
}

func ttlPtr(v int64) *int64 { return &v }

// TestDeliverForwardHomeRelaysOnlyWhenHasOtherHost is the spec's
// decision-3 table test: "a home node relays only when the recipient
// also advertises elsewhere." Both cases store at ttl_seconds either
// way (decision 3: Home always stores) — only the relay outcome
// differs.
func TestDeliverForwardHomeRelaysOnlyWhenHasOtherHost(t *testing.T) {
	cases := []struct {
		name         string
		msgID        string
		hasOtherHost bool
		wantRelays   int
	}{
		{"home only here, no relay", "home-only", false, 0},
		{"home and advertised elsewhere, relays", "home-and-elsewhere", true, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := newForwardTestStore(t)
			mgr := NewManager(ManagerConfig{Logger: slog.Default()})
			mgr.SetMsgStore(store)
			mgr.SetMessagingPolicy(MessagingPolicy{
				Home:                  stubHomeResolver{state: messaging.Home, hasOtherHost: c.hasOtherHost},
				ForwardCopyTTLSeconds: ttlPtr(86400),
			})
			relays := observeForwardRelays(t, mgr)
			senderKey, sender := newID(t)
			_, recipient := newID(t)
			msg := sampleMsg(sender, recipient)
			msg.MessageID = c.msgID
			raw, err := json.Marshal(legacyForward(t, senderKey, msg))
			if err != nil {
				t.Fatal(err)
			}
			if err := mgr.onMsgForward("peer", raw); err != nil {
				t.Fatal(err)
			}
			if *relays != c.wantRelays {
				t.Fatalf("relays = %d, want %d", *relays, c.wantRelays)
			}
			if store.Count() != 1 {
				t.Fatalf("a Home recipient must always be stored: count=%d", store.Count())
			}
		})
	}
}

// TestDeliverForwardDuplicateAlreadyStoredNotRelayedAgain is blocker
// B2's regression test (cold review R2): a forward for a message this
// node already stores — the origin's own forward echoing back in a
// cyclic mesh, a post-restart resend, or a msgSeen dedup eviction retry
// — must not be relayed again. Before the fix, deliverHomeForward
// relayed on hasOtherHost alone and deliverNonHomeForward relayed
// unconditionally, both ignoring Deliver/DeliverCopy's ok return value
// (false for an already-stored message), so a duplicate forward was
// relayed every time, unbounded by allowUnstoredRelay. Checked both with
// messaging privacy wired (the production path) and unwired (the legacy
// path, which never relayed a duplicate either).
func TestDeliverForwardDuplicateAlreadyStoredNotRelayedAgain(t *testing.T) {
	for _, wired := range []bool{false, true} {
		store := newForwardTestStore(t)
		mgr := NewManager(ManagerConfig{Logger: slog.Default()})
		mgr.SetMsgStore(store)
		if wired {
			mgr.SetMessagingPolicy(MessagingPolicy{ForwardCopyTTLSeconds: ttlPtr(86400)})
		}
		relays := observeForwardRelays(t, mgr)
		senderKey, sender := newID(t)
		_, recipient := newID(t)
		msg := sampleMsg(sender, recipient)
		msg.MessageID = "dup-1"
		if ok, err := store.Deliver(msg, "sender"); err != nil || !ok {
			t.Fatalf("pre-store: %v %v", ok, err)
		}
		raw, err := json.Marshal(legacyForward(t, senderKey, msg))
		if err != nil {
			t.Fatal(err)
		}
		if err := mgr.onMsgForward("peer", raw); err != nil {
			t.Fatal(err)
		}
		if *relays != 0 {
			t.Fatalf("wired=%v: duplicate (already-stored) forward relayed %d time(s), want 0", wired, *relays)
		}
	}
}

// TestDeliverForwardHomeDuplicateAlreadyStoredNotRelayedAgain is the
// Home-row half of blocker B2's fix (handlers_msg_policy.go's deliverHomeForward,
// ":169"): a duplicate forward for a message already stored at a Home
// recipient that ALSO advertises another host must still not be relayed
// again — ok must gate the relay, not hasOtherHost alone. The sibling
// test above exercises the non-Home half of the same bug
// (deliverNonHomeForward, ":194").
func TestDeliverForwardHomeDuplicateAlreadyStoredNotRelayedAgain(t *testing.T) {
	store := newForwardTestStore(t)
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	mgr.SetMessagingPolicy(MessagingPolicy{
		Home:                  stubHomeResolver{state: messaging.Home, hasOtherHost: true},
		ForwardCopyTTLSeconds: ttlPtr(86400),
	})
	relays := observeForwardRelays(t, mgr)
	senderKey, sender := newID(t)
	_, recipient := newID(t)
	msg := sampleMsg(sender, recipient)
	msg.MessageID = "home-dup-1"
	if ok, err := store.Deliver(msg, "sender"); err != nil || !ok {
		t.Fatalf("pre-store: %v %v", ok, err)
	}
	raw, err := json.Marshal(legacyForward(t, senderKey, msg))
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.onMsgForward("peer", raw); err != nil {
		t.Fatal(err)
	}
	if *relays != 0 {
		t.Fatalf("Home duplicate (already-stored) forward with hasOtherHost=true relayed %d time(s), want 0", *relays)
	}
}

// TestDeliverForwardHomeQuotaRelaysOnlyWhenHasOtherHost is blocker B3's
// regression test (cold review R3): a Home recipient with NO other
// advertised host, whose store is quota-full, must not be relayed —
// decision 3's row says "relay only if the recipient also advertises a
// host that isn't this node", and there is no delivery reason to spread
// a Home-only message past this node. Before the fix, the quota branch
// relayed through allowUnstoredRelay without checking hasOtherHost at
// all, so every inbox/pair/store quota rejection for a Home-only
// recipient leaked the message to non-home nodes.
func TestDeliverForwardHomeQuotaRelaysOnlyWhenHasOtherHost(t *testing.T) {
	store, err := messaging.NewStore(t.TempDir(), messaging.Options{MaxInboxMessages: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	mgr.SetMessagingPolicy(MessagingPolicy{
		Home:                  stubHomeResolver{state: messaging.Home, hasOtherHost: false},
		ForwardCopyTTLSeconds: ttlPtr(86400),
	})
	relays := observeForwardRelays(t, mgr)
	senderKey, sender := newID(t)
	_, recipient := newID(t)
	fill := sampleMsg(sender, recipient)
	fill.MessageID = "fill-1"
	if ok, err := store.Deliver(fill, "sender"); err != nil || !ok {
		t.Fatalf("fill inbox: %v %v", ok, err)
	}
	msg := sampleMsg(sender, recipient)
	msg.MessageID = "over-quota-1"
	raw, err := json.Marshal(legacyForward(t, senderKey, msg))
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.onMsgForward("peer", raw); err != nil {
		t.Fatal(err)
	}
	if *relays != 0 {
		t.Fatalf("Home recipient with no other host was relayed %d time(s) after a quota rejection, want 0", *relays)
	}
}

// TestDeliverForwardNonHomeForwardCopyTTLZeroRelayedNotStored is the
// spec's "forward_copy_ttl = 0: the message is relayed but not stored."
func TestDeliverForwardNonHomeForwardCopyTTLZeroRelayedNotStored(t *testing.T) {
	store := newForwardTestStore(t)
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	mgr.SetMessagingPolicy(MessagingPolicy{ForwardCopyTTLSeconds: ttlPtr(0)})
	relays := observeForwardRelays(t, mgr)
	senderKey, sender := newID(t)
	_, recipient := newID(t)
	msg := sampleMsg(sender, recipient)
	msg.MessageID = "copy-ttl-zero"
	raw, err := json.Marshal(legacyForward(t, senderKey, msg))
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.onMsgForward("peer", raw); err != nil {
		t.Fatal(err)
	}
	if *relays != 1 {
		t.Fatalf("relays = %d, want 1 (relayed even though not stored)", *relays)
	}
	if store.Count() != 0 {
		t.Fatalf("store count = %d, want 0 (forward_copy_ttl=0 means never stored)", store.Count())
	}
}

// TestDeliverForwardNonHomeForwardCopyTTLPositiveStoredAndRelayed covers
// the same table row with forward_copy_ttl > 0: stored (at the shorter
// TTL — see internal/messaging/copy_ttl_test.go for the expiry itself)
// and relayed.
func TestDeliverForwardNonHomeForwardCopyTTLPositiveStoredAndRelayed(t *testing.T) {
	store := newForwardTestStore(t)
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	mgr.SetMessagingPolicy(MessagingPolicy{ForwardCopyTTLSeconds: ttlPtr(86400)})
	relays := observeForwardRelays(t, mgr)
	senderKey, sender := newID(t)
	_, recipient := newID(t)
	msg := sampleMsg(sender, recipient)
	msg.MessageID = "copy-ttl-positive"
	raw, err := json.Marshal(legacyForward(t, senderKey, msg))
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.onMsgForward("peer", raw); err != nil {
		t.Fatal(err)
	}
	if *relays != 1 || store.Count() != 1 {
		t.Fatalf("relays=%d stored=%d, want 1,1", *relays, store.Count())
	}
}

// TestDeliverForwardNonHomeForwardCopyTTLUsedNotStoreTTLSeconds is F3:
// the cold review's mutation M5b (swap forward_copy_ttl for the store's
// ttl_seconds at this call site, handlers_msg_policy.go's
// deliverNonHomeForward ":197") survived because no test inspected the
// stored copy's actual expiry basis, only that a copy existed (the
// sibling test above). forward_copy_ttl here (86400) is deliberately far
// from the store's ttl_seconds (604800, set explicitly rather than
// relying on quota.go's default so this test does not depend on that
// constant staying put) so the two bases are numerically
// distinguishable: copy_ttl.go's expiryBaseFor formula
// (ReceivedAt + forward_copy_ttl - ttl_seconds) gives ReceivedAt-518400
// when correct, and exactly ReceivedAt — the same value Home/Deliver's
// full-ttl_seconds row always produces — if the mutation swapped
// ttl_seconds back in.
func TestDeliverForwardNonHomeForwardCopyTTLUsedNotStoreTTLSeconds(t *testing.T) {
	const ttlSeconds = int64(604800)
	const forwardCopyTTL = int64(86400)
	store, err := messaging.NewStore(t.TempDir(), messaging.Options{TTLSeconds: ttlSeconds})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	mgr.SetMessagingPolicy(MessagingPolicy{ForwardCopyTTLSeconds: ttlPtr(forwardCopyTTL)})
	senderKey, sender := newID(t)
	_, recipient := newID(t)
	msg := sampleMsg(sender, recipient)
	msg.MessageID = "copy-ttl-expiry-basis"
	raw, err := json.Marshal(legacyForward(t, senderKey, msg))
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.onMsgForward("peer", raw); err != nil {
		t.Fatal(err)
	}
	msgs, err := store.List(recipient, "dex.swap")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("stored messages = %d, want 1", len(msgs))
	}
	want := msgs[0].ReceivedAt + forwardCopyTTL - ttlSeconds
	if msgs[0].ExpiryBase != want {
		t.Fatalf("ExpiryBase = %d, want %d (forward_copy_ttl-based; the store's ttl_seconds-based value would wrongly give %d)",
			msgs[0].ExpiryBase, want, msgs[0].ReceivedAt)
	}
}
