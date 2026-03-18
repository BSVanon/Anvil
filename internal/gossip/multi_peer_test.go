package gossip

import (
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// TestMultiPeerDisconnectCleansUpCorrectPeer verifies that when multiple
// inbound peers are connected and one disconnects, only that specific
// peer is removed — not a random other inbound peer.
func TestMultiPeerDisconnectCleansUpCorrectPeer(t *testing.T) {
	dir, _ := os.MkdirTemp("", "anvil-multi-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	store, _ := envelope.NewStore(dir, 3600, 65536)
	defer store.Close()

	walletB := wallet.NewTestWalletForRandomKey(t)
	mgrB := NewManager(ManagerConfig{
		Wallet:         walletB,
		Store:          store,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
	})
	defer mgrB.Stop()

	// Start B's mesh listener
	ts := httptest.NewServer(mgrB.MeshHandler())
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	// Connect peer A1
	dirA1, _ := os.MkdirTemp("", "anvil-a1-*")
	t.Cleanup(func() { os.RemoveAll(dirA1) })
	storeA1, _ := envelope.NewStore(dirA1, 3600, 65536)
	defer storeA1.Close()

	walletA1 := wallet.NewTestWalletForRandomKey(t)
	mgrA1 := NewManager(ManagerConfig{
		Wallet:         walletA1,
		Store:          storeA1,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
	})
	defer mgrA1.Stop()

	if err := mgrA1.ConnectPeer(t.Context(), wsURL); err != nil {
		t.Fatalf("A1 ConnectPeer: %v", err)
	}

	// Connect peer A2
	dirA2, _ := os.MkdirTemp("", "anvil-a2-*")
	t.Cleanup(func() { os.RemoveAll(dirA2) })
	storeA2, _ := envelope.NewStore(dirA2, 3600, 65536)
	defer storeA2.Close()

	walletA2 := wallet.NewTestWalletForRandomKey(t)
	mgrA2 := NewManager(ManagerConfig{
		Wallet:         walletA2,
		Store:          storeA2,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
	})
	defer mgrA2.Stop()

	if err := mgrA2.ConnectPeer(t.Context(), wsURL); err != nil {
		t.Fatalf("A2 ConnectPeer: %v", err)
	}

	// Wait for both connections to establish
	time.Sleep(600 * time.Millisecond)

	initialPeers := mgrB.PeerCount()
	if initialPeers != 2 {
		t.Fatalf("expected 2 peers on B, got %d", initialPeers)
	}

	// Disconnect A1 only
	mgrA1.Stop()
	time.Sleep(600 * time.Millisecond)

	// B should have exactly 1 peer left (A2)
	remaining := mgrB.PeerCount()
	if remaining != 1 {
		t.Fatalf("expected 1 peer after A1 disconnect, got %d", remaining)
	}

	// Disconnect A2
	mgrA2.Stop()
	time.Sleep(600 * time.Millisecond)

	final := mgrB.PeerCount()
	if final != 0 {
		t.Fatalf("expected 0 peers after both disconnect, got %d", final)
	}

	t.Log("multi-peer disconnect cleanup correct: each disconnect removes only its own peer")
}
