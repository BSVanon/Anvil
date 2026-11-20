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

// TestAllowUnstoredRelayBoundsForwardCopyTTLZeroFlood proves decision
// 3's relay bound with forward_copy_ttl=0: a flood of distinct messages
// this node never stores is NOT all relayed — the manager-wide
// allowUnstoredRelay budget (burst 50) caps it well below the flood
// size, even though the per-peer entry bucket (burst 100, default) lets
// all of them through to onMsgForward in the first place.
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
	if *relays >= flood {
		t.Fatalf("relays = %d of %d forwards, want it bounded below the flood size (unstoredRelayBurst=%d)", *relays, flood, unstoredRelayBurst)
	}
	if *relays < 1 {
		t.Fatalf("relays = %d, want at least the initial burst to go through", *relays)
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

// TestForwardPeersRestrictsForwardMessageToListedPeers is decision 4's
// required end-to-end test ("a forward reaches only listed peers"),
// using two real, independently-connected peers (mirroring
// multi_peer_test.go's pattern) rather than the relayForwardTestHook,
// since that hook short-circuits before the per-peer loop and so cannot
// observe WHICH peer receives a send.
func TestForwardPeersRestrictsForwardMessageToListedPeers(t *testing.T) {
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
	mgrHub := NewManager(ManagerConfig{
		Wallet:         wallet.NewTestWalletForRandomKey(t),
		Store:          hubEnv,
		LocalInterests: []string{""},
		MaxSeen:        100,
		IdentityKey:    hubKey,
	})
	t.Cleanup(func() { mgrHub.Stop() })
	ts := httptest.NewServer(mgrHub.MeshHandler())
	t.Cleanup(ts.Close)
	wsURL := "ws" + ts.URL[len("http"):]

	connectPeer := func(name string) (identityHex string, msgStore *messaging.Store) {
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

	allowedHex, allowedStore := connectPeer("allowed")
	_, deniedStore := connectPeer("denied")

	time.Sleep(600 * time.Millisecond)
	if mgrHub.PeerCount() != 2 {
		t.Fatalf("expected 2 peers on hub, got %d", mgrHub.PeerCount())
	}

	mgrHub.SetMessagingPolicy(MessagingPolicy{ForwardPeers: NewForwardPeerFilter([]string{allowedHex})})

	_, senderHex := newID(t)
	_, recipientHex := newID(t)
	msg := sampleMsg(senderHex, recipientHex)
	msg.MessageID = "forward-peers-e2e"
	mgrHub.ForwardMessage(msg)

	time.Sleep(600 * time.Millisecond)

	if allowedStore.Count() != 1 {
		t.Fatalf("allowed peer store count = %d, want 1", allowedStore.Count())
	}
	if deniedStore.Count() != 0 {
		t.Fatalf("denied peer store count = %d, want 0 (forward_peers must exclude it)", deniedStore.Count())
	}
}
