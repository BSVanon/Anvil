package gossip

// BroadcastACMEChallenge's eligibility check must key off
// hex(peer.IdentityPK) itself, never the string a peer happens to be
// stored under in m.peers. See acme_relay_admission_test.go for the
// shared identity/transport test helpers this file reuses
// (newIdentity, newIdentityWithKey, newAllowlistTestManager,
// newRawCountingPeerOn).

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	"golang.org/x/net/websocket"
)

// TestBroadcastACMEChallenge_ChecksIdentityHexNotMapKey proves the
// eligibility check keys off hex(peer.IdentityPK), not whatever string
// the peer happens to be stored under in m.peers. By construction
// (AcceptPeer's reactive re-key, establishAndAuthorizePeer's proactive
// one) the two always agree in production, but nothing in
// BroadcastACMEChallenge itself should depend on that agreement holding.
// This test builds the one state where a map-key check and an
// identity-hex check disagree: a peer re-keyed to a map entry that IS in
// [mesh] allowed_peers, while its own IdentityPK is an identity that is
// NOT.
//
// Mutation check for item 4: check the map key (the range variable)
// instead of hex(peer.IdentityPK) and this test's "sent" assertion
// fails, since the mismatched map key is in allowed_peers.
func TestBroadcastACMEChallenge_ChecksIdentityHexNotMapKey(t *testing.T) {
	walletB, _ := newIdentity(t)
	attackerWallet, attackerHex, attackerKey := newIdentityWithKey(t)
	const mismatchedMapKey = "02cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	// allowed_peers lists the map key we're about to (mis)use, never the
	// attacker's real identity hex -- the one state a check against the
	// map key and a check against hex(IdentityPK) disagree about.
	mgrB := newAllowlistTestManager(t, "acme-idkey-b", walletB, []string{mismatchedMapKey})

	registered := make(chan string, 1)
	handler := websocket.Handler(func(conn *websocket.Conn) {
		transport := NewServerWSTransport(conn)
		tempKey, err := mgrB.AcceptPeer(transport)
		if err != nil {
			t.Errorf("AcceptPeer: %v", err)
			close(registered)
			return
		}
		registered <- tempKey
		<-transport.Done()
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	transport, err := NewWSTransportAdapter(wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer transport.Close()
	attacker := newRawCountingPeerOn(t, transport, auth.PeerOptions{Wallet: attackerWallet, Transport: transport})

	var tempKey string
	select {
	case tempKey = <-registered:
	case <-time.After(5 * time.Second):
		t.Fatal("AcceptPeer never returned")
	}
	if tempKey == "" {
		t.Fatal("AcceptPeer failed")
	}

	// Re-key to the attacker's real identity, but relocate the entry to
	// mismatchedMapKey instead of attackerHex -- the mismatch this test
	// exists to create, bypassing AcceptPeer's own reactive re-key
	// entirely (the same direct-manipulation technique
	// acme_relay_admission_test.go's test (b) uses).
	mgrB.mu.Lock()
	mp, ok := mgrB.peers[tempKey]
	if !ok {
		mgrB.mu.Unlock()
		t.Fatal("peer not found under its temp key")
	}
	mp.IdentityPK = attackerKey.PubKey()
	mgrB.peers[mismatchedMapKey] = mp
	delete(mgrB.peers, tempKey)
	mgrB.mu.Unlock()

	if mgrB.allowlist.allows(attackerHex) {
		t.Fatal("test setup error: attackerHex must not be in allowed_peers")
	}
	if !mgrB.allowlist.allows(mismatchedMapKey) {
		t.Fatal("test setup error: mismatchedMapKey must be in allowed_peers")
	}

	sent := mgrB.BroadcastACMEChallenge("challenge.example.org+token", []byte("secret"), time.Now().Add(time.Minute))
	if sent != 0 {
		t.Fatalf("BroadcastACMEChallenge sent to %d peer(s), want 0 -- the peer's identity hex is not in allowed_peers, even though it is stored under a map key that is", sent)
	}
	if got := attacker.received.Load(); got != 0 {
		t.Fatalf("the peer received %d message(s), want 0", got)
	}
}
