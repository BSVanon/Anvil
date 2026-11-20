package gossip

import (
	"encoding/hex"
	"encoding/json"
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

// The forward_peers seam (handlers_msg_policy.go,
// NewForwardPeerFilter/peerAllowedForForward): a nil filter allows every
// connected peer (today's default); a populated one restricts both
// relay paths — the API-send loop (ForwardMessage) and the
// relay-received loop (onMsgForward -> relayMessageForward, tested below).

// TestPeerAllowedForForward is a direct unit test of the forward_peers
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
// contract at the constructor level.
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
// relay-received path (onMsgForward -> relayMessageForward's loop, tested below).
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

// TestForwardPeersRestrictsForwardMessageToListedPeers is the
// forward_peers seam's required end-to-end test ("a forward reaches only listed peers"),
// using two real, independently-connected peers (mirroring
// multi_peer_test.go's pattern) rather than the relayForwardTestHook,
// since that hook short-circuits before the per-peer loop and so cannot
// observe WHICH peer receives a send. This covers ForwardMessage's own
// loop — the API-send path; the sibling test below covers the OTHER
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

// TestForwardPeersRestrictsRelayMessageForwardToListedPeers covers a bug
// a review found: a mutation test (drop the forward_peers filter in the
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
	// allowUnstoredRelay budget, which a single message here is
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
