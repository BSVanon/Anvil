package gossip

import (
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// TestTwoNodeMeshGossip proves end-to-end: node A submits a signed envelope
// via BroadcastEnvelope, node B receives it through a live WebSocket mesh.
//
// Both nodes use go-sdk TestWallet for authenticated identity, so the full
// auth.Peer handshake runs over a real WebSocket connection.
func TestTwoNodeMeshGossip(t *testing.T) {
	// --- Node B: the receiver ---
	dirB, _ := os.MkdirTemp("", "anvil-mesh-b-*")
	t.Cleanup(func() { os.RemoveAll(dirB) })
	storeB, err := envelope.NewStore(dirB, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer storeB.Close()

	var receivedEnv *envelope.Envelope
	var receivedMu sync.Mutex
	receivedCh := make(chan struct{}, 1)

	walletB := wallet.NewTestWalletForRandomKey(t)
	mgrB := NewManager(ManagerConfig{
		Wallet:         walletB,
		Store:          storeB,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
		OnEnvelope: func(env *envelope.Envelope) {
			receivedMu.Lock()
			receivedEnv = env
			receivedMu.Unlock()
			select {
			case receivedCh <- struct{}{}:
			default:
			}
		},
	})
	defer mgrB.Stop()

	// Start B's mesh listener on a test HTTP server
	ts := httptest.NewServer(mgrB.MeshHandler())
	defer ts.Close()

	// Convert http://host:port to ws://host:port for the WebSocket client
	wsURL := "ws" + ts.URL[len("http"):]

	// --- Node A: the sender ---
	dirA, _ := os.MkdirTemp("", "anvil-mesh-a-*")
	t.Cleanup(func() { os.RemoveAll(dirA) })
	storeA, err := envelope.NewStore(dirA, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer storeA.Close()

	walletA := wallet.NewTestWalletForRandomKey(t)
	mgrA := NewManager(ManagerConfig{
		Wallet:         walletA,
		Store:          storeA,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
	})
	defer mgrA.Stop()

	// A connects to B
	if err := mgrA.ConnectPeer(t.Context(), wsURL); err != nil {
		t.Fatalf("ConnectPeer: %v", err)
	}

	// Wait for the connection to establish and interests to be exchanged
	time.Sleep(500 * time.Millisecond)

	if mgrA.PeerCount() == 0 {
		t.Fatal("node A should have at least 1 peer after ConnectPeer")
	}

	// Create a signed envelope on node A
	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "oracle:rates:bsv",
		Payload:   `{"rate":42,"source":"node-a"}`,
		TTL:       60,
		Timestamp: time.Now().Unix(),
	}
	env.Sign(key)

	// Broadcast from A — should reach B through the mesh
	mgrA.BroadcastEnvelope(env)

	// Wait for B to receive it
	select {
	case <-receivedCh:
		// success
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for node B to receive envelope from mesh")
	}

	receivedMu.Lock()
	got := receivedEnv
	receivedMu.Unlock()

	if got == nil {
		t.Fatal("node B did not receive any envelope")
	}
	if got.Topic != "oracle:rates:bsv" {
		t.Fatalf("expected topic oracle:rates:bsv, got %s", got.Topic)
	}
	if got.Payload != `{"rate":42,"source":"node-a"}` {
		t.Fatalf("payload mismatch: %s", got.Payload)
	}

	// Verify B stored it
	results, err := storeB.QueryByTopic("oracle:rates:bsv", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("node B should have stored the envelope")
	}

	t.Logf("e2e mesh success: envelope gossiped from A to B via authenticated WebSocket")
}

// TestMonetizedEnvelopeGossipIntegrity proves that envelopes with monetization
// metadata survive mesh gossip with full integrity: the monetization fields
// arrive intact on the receiving node, and the signature still verifies
// (because monetization is part of the signing digest).
//
// This is the end-to-end proof that the non-custodial payment policy
// is tamper-proof across the Foundry mesh.
func TestMonetizedEnvelopeGossipIntegrity(t *testing.T) {
	// --- Node B: receiver ---
	dirB, _ := os.MkdirTemp("", "anvil-mesh-mon-b-*")
	t.Cleanup(func() { os.RemoveAll(dirB) })
	storeB, err := envelope.NewStore(dirB, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer storeB.Close()

	var receivedEnv *envelope.Envelope
	var receivedMu sync.Mutex
	receivedCh := make(chan struct{}, 1)

	walletB := wallet.NewTestWalletForRandomKey(t)
	mgrB := NewManager(ManagerConfig{
		Wallet:         walletB,
		Store:          storeB,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
		OnEnvelope: func(env *envelope.Envelope) {
			receivedMu.Lock()
			receivedEnv = env
			receivedMu.Unlock()
			select {
			case receivedCh <- struct{}{}:
			default:
			}
		},
	})
	defer mgrB.Stop()

	ts := httptest.NewServer(mgrB.MeshHandler())
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	// --- Node A: sender ---
	dirA, _ := os.MkdirTemp("", "anvil-mesh-mon-a-*")
	t.Cleanup(func() { os.RemoveAll(dirA) })
	storeA, err := envelope.NewStore(dirA, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer storeA.Close()

	walletA := wallet.NewTestWalletForRandomKey(t)
	mgrA := NewManager(ManagerConfig{
		Wallet:         walletA,
		Store:          storeA,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
	})
	defer mgrA.Stop()

	if err := mgrA.ConnectPeer(t.Context(), wsURL); err != nil {
		t.Fatalf("ConnectPeer: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// Create a monetized envelope: split model, app charges 50 sats
	appPayeeScript := "76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac"
	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "oracle:rates:bsv",
		Payload:   `{"rate":42,"source":"node-a"}`,
		TTL:       60,
		Timestamp: time.Now().Unix(),
		Monetization: &envelope.Monetization{
			Model:                 envelope.MonetizationSplit,
			PayeeLockingScriptHex: appPayeeScript,
			PriceSats:             50,
		},
	}
	env.Sign(key)

	// Verify it's valid before sending
	if err := env.Validate(); err != nil {
		t.Fatalf("envelope invalid before broadcast: %v", err)
	}

	mgrA.BroadcastEnvelope(env)

	// Wait for B to receive
	select {
	case <-receivedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for monetized envelope on node B")
	}

	receivedMu.Lock()
	got := receivedEnv
	receivedMu.Unlock()

	if got == nil {
		t.Fatal("node B did not receive envelope")
	}

	// Verify monetization metadata survived gossip intact
	if got.Monetization == nil {
		t.Fatal("monetization metadata lost in gossip")
	}
	if got.Monetization.Model != envelope.MonetizationSplit {
		t.Fatalf("model: expected split, got %s", got.Monetization.Model)
	}
	if got.Monetization.PayeeLockingScriptHex != appPayeeScript {
		t.Fatalf("payee script: expected %s, got %s", appPayeeScript, got.Monetization.PayeeLockingScriptHex)
	}
	if got.Monetization.PriceSats != 50 {
		t.Fatalf("price: expected 50, got %d", got.Monetization.PriceSats)
	}

	// Verify signature STILL validates after gossip (proves monetization
	// wasn't tampered with in transit — any change would break the signature)
	if err := got.Validate(); err != nil {
		t.Fatalf("signature invalid after gossip (monetization tampered?): %v", err)
	}

	// Verify B stored it with monetization
	results, err := storeB.QueryByTopic("oracle:rates:bsv", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("node B should have stored the monetized envelope")
	}
	if results[0].Monetization == nil {
		t.Fatal("stored envelope lost monetization metadata")
	}

	t.Logf("monetized envelope (split, 50 sats) gossiped A→B with full integrity")
}

// TestConnectPeerRequiresWallet verifies that ConnectPeer fails cleanly
// when no wallet is configured.
func TestConnectPeerRequiresWallet(t *testing.T) {
	m := NewManager(ManagerConfig{
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
		// No Wallet
	})
	defer m.Stop()

	err := m.ConnectPeer(t.Context(), "ws://localhost:9999")
	if err == nil {
		t.Fatal("expected error when connecting without wallet")
	}
	if err.Error() != "cannot connect to peer: no wallet configured (identity.wif required)" {
		t.Fatalf("unexpected error: %v", err)
	}
}
