package gossip

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/messaging"
)

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

// TestAllowUnstoredRelayBoundsForwardCopyTTLZeroFlood proves decision
// 3's relay bound with forward_copy_ttl=0: a flood of distinct messages
// this node never stores is NOT all relayed — the manager-wide
// allowUnstoredRelay budget caps it at exactly its burst size (N9 —
// asserting only "fewer than the flood" would also pass for a bound
// that had quietly drifted, so this pins the exact number), even though
// the per-peer entry bucket (burst 100, default) lets all of them
// through to onMsgForward in the first place. The loop runs fast enough
// that no time-based refill meaningfully adds tokens back mid-flood, so
// the full flood is run before any single read of *relays.
func TestAllowUnstoredRelayBoundsForwardCopyTTLZeroFlood(t *testing.T) {
	store := newForwardTestStore(t)
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	mgr.SetMessagingPolicy(MessagingPolicy{ForwardCopyTTLSeconds: ttlPtr(0)})
	relays := observeForwardRelays(t, mgr)

	senderKey, sender := newID(t)
	_, recipient := newID(t)
	const flood = unstoredRelayBurst + 20
	for i := 0; i < flood; i++ {
		msg := sampleMsg(sender, recipient)
		msg.MessageID = fmt.Sprintf("flood-%d", i)
		raw, err := json.Marshal(legacyForward(t, senderKey, msg))
		if err != nil {
			t.Fatal(err)
		}
		if err := mgr.onMsgForward("peer", raw); err != nil {
			t.Fatal(err)
		}
	}
	if *relays != unstoredRelayBurst {
		t.Fatalf("relays = %d of %d forwards, want exactly unstoredRelayBurst=%d", *relays, flood, unstoredRelayBurst)
	}
	if store.Count() != 0 {
		t.Fatalf("store count = %d, want 0 (forward_copy_ttl=0 never stores)", store.Count())
	}
}

// TestPeerAllowedForForward is a direct unit test of decision 4's
// predicate: nil (no forward_peers configured) allows everyone; a
// configured filter allows only listed hex identity keys, matched
// case-insensitively.
func TestPeerAllowedForForward(t *testing.T) {
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	_, allowed := newID(t)
	_, denied := newID(t)

	if !mgr.peerAllowedForForward(allowed) || !mgr.peerAllowedForForward(denied) {
		t.Fatal("with no forward_peers configured, every peer must be allowed")
	}

	mgr.SetMessagingPolicy(MessagingPolicy{ForwardPeers: NewForwardPeerFilter([]string{allowed})})
	if !mgr.peerAllowedForForward(allowed) {
		t.Fatal("listed peer must be allowed")
	}
	if !mgr.peerAllowedForForward(strings.ToUpper(allowed)) {
		t.Fatal("comparison must be case-insensitive")
	}
	if mgr.peerAllowedForForward(denied) {
		t.Fatal("unlisted peer must be denied")
	}
}

// TestNewForwardPeerFilterEmptyListMeansEveryPeer pins
// NewForwardPeerFilter's "empty means every connected peer, as today"
// contract (decision 4) at the constructor level.
func TestNewForwardPeerFilterEmptyListMeansEveryPeer(t *testing.T) {
	if f := NewForwardPeerFilter(nil); f != nil {
		t.Fatal("nil hexKeys should produce a nil filter")
	}
	if f := NewForwardPeerFilter([]string{"", "  "}); f != nil {
		t.Fatal("blank-only hexKeys should produce a nil filter")
	}
}

// newForwardPeerTestHub builds a hub Manager with its mesh WebSocket
// server listening, and returns a connectPeer helper that connects a
// fresh peer (its own identity, envelope store and message store) to
// it. Shared scaffolding for forward_peers' two relay-path tests below:
// the API-send path (ForwardMessage's own loop) and the
// relay-received path (onMsgForward -> relayMessageForward's loop, F2).
func newForwardPeerTestHub(t *testing.T) (hub *Manager, connectPeer func(name string) (identityHex string, msgStore *messaging.Store)) {
	t.Helper()
	hubDir, err := os.MkdirTemp("", "anvil-fp-hub-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(hubDir) })
	hubEnv, err := envelope.NewStore(hubDir, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hubEnv.Close() })

	hubKey, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	hub = NewManager(ManagerConfig{
		Wallet:         wallet.NewTestWalletForRandomKey(t),
		Store:          hubEnv,
		LocalInterests: []string{""},
		MaxSeen:        100,
		IdentityKey:    hubKey,
	})
	t.Cleanup(func() { hub.Stop() })
	ts := httptest.NewServer(hub.MeshHandler())
	t.Cleanup(ts.Close)
	wsURL := "ws" + ts.URL[len("http"):]

	connectPeer = func(name string) (identityHex string, msgStore *messaging.Store) {
		dir, err := os.MkdirTemp("", "anvil-fp-"+name+"-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		env, err := envelope.NewStore(dir, 3600, 65536)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = env.Close() })
		msgStore, err = messaging.NewStore(t.TempDir(), messaging.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = msgStore.Close() })

		priv, err := ec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		identityHex = hex.EncodeToString(priv.PubKey().Compressed())
		mgr := NewManager(ManagerConfig{
			Wallet:         wallet.NewTestWallet(t, priv),
			Store:          env,
			LocalInterests: []string{""},
			MaxSeen:        100,
		})
		mgr.SetMsgStore(msgStore)
		t.Cleanup(func() { mgr.Stop() })
		if err := mgr.ConnectPeer(t.Context(), wsURL); err != nil {
			t.Fatal(err)
		}
		return identityHex, msgStore
	}
	return hub, connectPeer
}

// TestForwardPeersRestrictsForwardMessageToListedPeers is decision 4's
// required end-to-end test ("a forward reaches only listed peers"),
// using two real, independently-connected peers (mirroring
// multi_peer_test.go's pattern) rather than the relayForwardTestHook,
// since that hook short-circuits before the per-peer loop and so cannot
// observe WHICH peer receives a send. This covers ForwardMessage's own
// loop — the API-send path; F2's sibling test below covers the OTHER
// forward_peers-respecting loop, relayMessageForward's.
func TestForwardPeersRestrictsForwardMessageToListedPeers(t *testing.T) {
	hub, connectPeer := newForwardPeerTestHub(t)
	allowedHex, allowedStore := connectPeer("allowed")
	_, deniedStore := connectPeer("denied")

	time.Sleep(600 * time.Millisecond)
	if hub.PeerCount() != 2 {
		t.Fatalf("expected 2 peers on hub, got %d", hub.PeerCount())
	}

	hub.SetMessagingPolicy(MessagingPolicy{ForwardPeers: NewForwardPeerFilter([]string{allowedHex})})

	_, senderHex := newID(t)
	_, recipientHex := newID(t)
	msg := sampleMsg(senderHex, recipientHex)
	msg.MessageID = "forward-peers-e2e"
	hub.ForwardMessage(msg)

	time.Sleep(600 * time.Millisecond)

	if allowedStore.Count() != 1 {
		t.Fatalf("allowed peer store count = %d, want 1", allowedStore.Count())
	}
	if deniedStore.Count() != 0 {
		t.Fatalf("denied peer store count = %d, want 0 (forward_peers must exclude it)", deniedStore.Count())
	}
}

// TestForwardPeersRestrictsRelayMessageForwardToListedPeers is F2: the
// cold review's own M2b mutation (drop the forward_peers filter in the
// relay loop) survived because the only existing coverage used
// relayForwardTestHook, which returns before the peer loop
// (relay_budget.go's relayMessageForward) and so cannot see which peer
// actually receives a send. This drives a message through that OTHER
// loop instead — the one a RECEIVED forward takes on its way back out
// (onMsgForward -> deliverForward -> relayMessageForward) — with two
// real, independently-connected peers, exactly like the sibling test
// above covers ForwardMessage's own loop (the API-send path).
func TestForwardPeersRestrictsRelayMessageForwardToListedPeers(t *testing.T) {
	hub, connectPeer := newForwardPeerTestHub(t)
	allowedHex, allowedStore := connectPeer("allowed")
	_, deniedStore := connectPeer("denied")

	time.Sleep(600 * time.Millisecond)
	if hub.PeerCount() != 2 {
		t.Fatalf("expected 2 peers on hub, got %d", hub.PeerCount())
	}

	hub.SetMessagingPolicy(MessagingPolicy{ForwardPeers: NewForwardPeerFilter([]string{allowedHex})})

	// The hub itself never calls SetMsgStore, so onMsgForward's
	// relay-only branch fires (bounded only by the manager-wide
	// allowUnstoredRelay budget, N7, which a single message here is
	// nowhere near) — relayMessageForward is reached exactly as it
	// would be for a real received forward.
	senderKey, senderHex := newID(t)
	_, recipientHex := newID(t)
	msg := sampleMsg(senderHex, recipientHex)
	msg.MessageID = "relay-forward-peers-e2e"
	raw, err := json.Marshal(legacyForward(t, senderKey, msg))
	if err != nil {
		t.Fatal(err)
	}
	if err := hub.onMsgForward("not-a-connected-peer", raw); err != nil {
		t.Fatal(err)
	}

	time.Sleep(600 * time.Millisecond)

	if allowedStore.Count() != 1 {
		t.Fatalf("allowed peer store count = %d, want 1", allowedStore.Count())
	}
	if deniedStore.Count() != 0 {
		t.Fatalf("denied peer store count = %d, want 0 (forward_peers must exclude it)", deniedStore.Count())
	}
}

// TestRelayOnlyNodeBoundByUnstoredRelayBudget is N7: a node with no
// message store at all (SetMsgStore never called) used to relay every
// forward unconditionally, bypassing the manager-wide allowUnstoredRelay
// budget that every OTHER unstored-relay path (a stored node's
// non-home/quota branches) already respects. It must share the same
// bound.
func TestRelayOnlyNodeBoundByUnstoredRelayBudget(t *testing.T) {
	mgr := NewManager(ManagerConfig{Logger: slog.Default()}) // no SetMsgStore: relay-only
	relays := observeForwardRelays(t, mgr)

	senderKey, sender := newID(t)
	_, recipient := newID(t)
	const flood = unstoredRelayBurst + 20
	for i := 0; i < flood; i++ {
		msg := sampleMsg(sender, recipient)
		msg.MessageID = fmt.Sprintf("relay-only-flood-%d", i)
		raw, err := json.Marshal(legacyForward(t, senderKey, msg))
		if err != nil {
			t.Fatal(err)
		}
		if err := mgr.onMsgForward("peer", raw); err != nil {
			t.Fatal(err)
		}
	}
	if *relays != unstoredRelayBurst {
		t.Fatalf("relay-only node: relays = %d of %d forwards, want exactly unstoredRelayBurst=%d", *relays, flood, unstoredRelayBurst)
	}
}
