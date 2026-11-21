package gossip

// BroadcastACMEChallenge's own admission gate: a connected mesh peer
// must be both identified and allowed before it ever receives a
// replicated ACME challenge entry, independent of whatever
// connection-time admission elsewhere in this package has or hasn't
// done yet. Split into its own file, alongside acme_relay.go, to keep
// allowlist_transport_test.go scoped to its own existing concern.

import (
	"context"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"golang.org/x/net/websocket"
)

// newIdentityWithKey is newIdentity (allowlist_test.go), but also
// returns the raw private key: the two tests below that place a
// *MeshPeer into m.peers directly, bypassing the normal admission flow,
// need the actual *ec.PublicKey to set MeshPeer.IdentityPK with --
// wallet.Interface's own GetPublicKey is the BRC-100 RPC-shaped method,
// not a plain accessor, so getting the key this way (once, at identity
// creation) is far simpler than calling through it.
func newIdentityWithKey(t *testing.T) (w wallet.Interface, hex string, key *ec.PrivateKey) {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate identity key: %v", err)
	}
	w = wallet.NewTestWallet(t, key)
	return w, fmt.Sprintf("%x", key.PubKey().Compressed()), key
}

// TestBroadcastACMEChallenge_SilentInboundPeerReceivesNothing is test (a):
// a peer that completes the transport-level connection and starts its own
// auth.Peer, but never sends a single application message, stays in
// m.peers under AcceptPeer's temporary key with IdentityPK == nil
// forever — it has no occasion to be re-keyed. This is the reviewer's
// shape: a bare auth.Peer (not a Manager) that dials in and only
// listens, so the count it observes is independent of any Manager-side
// bookkeeping.
//
// Mutation check for item 2: drop the "peer.IdentityPK == nil" guard in
// BroadcastACMEChallenge's eligibility filter and this test's "sent"
// assertion fails (the silent peer would be sent to, since peer.Peer is
// still non-nil).
func TestBroadcastACMEChallenge_SilentInboundPeerReceivesNothing(t *testing.T) {
	walletB, _ := newIdentity(t)
	attackerWallet, _ := newIdentity(t)
	mgrB := newAllowlistTestManager(t, "acme-silent-b", walletB, nil) // no allowlist configured at all

	registered := make(chan struct{})
	handler := websocket.Handler(func(conn *websocket.Conn) {
		transport := NewServerWSTransport(conn)
		if _, err := mgrB.AcceptPeer(transport); err != nil {
			t.Errorf("AcceptPeer: %v", err)
		}
		close(registered)
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
	_ = attacker // deliberately never sends anything -- the point of this test

	select {
	case <-registered:
	case <-time.After(5 * time.Second):
		t.Fatal("AcceptPeer never returned")
	}
	if got := mgrB.PeerCount(); got != 1 {
		t.Fatalf("PeerCount() = %d, want 1 (the silent peer is connected, just unidentified)", got)
	}

	sent := mgrB.BroadcastACMEChallenge("challenge.example.org+token", []byte("secret"), time.Now().Add(time.Minute))
	if sent != 0 {
		t.Fatalf("BroadcastACMEChallenge sent to %d peer(s), want 0 (the only connected peer has never sent a message)", sent)
	}
	if got := attacker.received.Load(); got != 0 {
		t.Fatalf("the silent, unidentified peer received %d message(s), want 0", got)
	}
}

// TestBroadcastACMEChallenge_IdentifiedButDisallowedPeerReceivesNothing
// is test (b): a peer whose identity IS known but is not in
// [mesh] allowed_peers must still receive nothing from
// BroadcastACMEChallenge, independent of checkAllowedPeer's own cleanup
// (which removes such a peer from m.peers as soon as its first message
// reveals a disallowed identity — see allowlist.go). This test builds
// the "identified but disallowed, still present" state directly, the
// same way a race between that cleanup and a concurrent broadcast
// could, rather than relying on the production race window to land it:
// BroadcastACMEChallenge's own check must hold regardless of whether
// the admission callback's cleanup has run yet, which is exactly what
// the fix spec calls for ("don't rely on the first-message admission
// callback having run").
//
// Mutation check for item 2: drop the "m.allowlist.allows(pkHex)" check
// and this test's "sent" assertion fails.
func TestBroadcastACMEChallenge_IdentifiedButDisallowedPeerReceivesNothing(t *testing.T) {
	walletB, _ := newIdentity(t)
	attackerWallet, attackerHex, attackerKey := newIdentityWithKey(t)
	// allowed_peers lists only "stranger" -- attackerHex is deliberately
	// excluded, so m.allowlist.allows(attackerHex) is false.
	mgrB := newAllowlistTestManager(t, "acme-disallowed-b", walletB, []string{strangerHex})

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

	// Re-key to the attacker's real identity directly, bypassing
	// checkAllowedPeer entirely -- simulating "identified, disallowed,
	// still in m.peers" without depending on the production refusal
	// path's own cleanup timing.
	attackerPK := attackerKey.PubKey()
	mgrB.mu.Lock()
	mp, ok := mgrB.peers[tempKey]
	if !ok {
		mgrB.mu.Unlock()
		t.Fatal("peer not found under its temp key")
	}
	mp.IdentityPK = attackerPK
	mgrB.peers[attackerHex] = mp
	delete(mgrB.peers, tempKey)
	mgrB.mu.Unlock()

	if mgrB.allowlist.allows(attackerHex) {
		t.Fatal("test setup error: attackerHex must not be in allowed_peers")
	}

	sent := mgrB.BroadcastACMEChallenge("challenge.example.org+token", []byte("secret"), time.Now().Add(time.Minute))
	if sent != 0 {
		t.Fatalf("BroadcastACMEChallenge sent to %d peer(s), want 0 (identified but not in allowed_peers)", sent)
	}
	if got := attacker.received.Load(); got != 0 {
		t.Fatalf("the disallowed peer received %d message(s), want 0", got)
	}
}

// TestBroadcastACMEChallenge_AllowedPeerReceivesEntry is test (c): the
// positive case, proving the fix isn't over-restrictive. The ally sends
// one message to establish its identity with mgrB through the real
// AcceptPeer/checkAllowedPeer path; mgrB only replies with its own
// announces (announceInterests etc.) once that check has passed, so
// receiving anything back is a deterministic, non-sleep signal that the
// ally is now registered under its identity key and allowed -- not a
// race-prone assumption about timing.
func TestBroadcastACMEChallenge_AllowedPeerReceivesEntry(t *testing.T) {
	walletB, _ := newIdentity(t)
	allyWallet, allyHex := newIdentity(t)
	mgrB := newAllowlistTestManager(t, "acme-allowed-b", walletB, []string{allyHex})
	ts := httptest.NewServer(mgrB.MeshHandler())
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	transport, err := NewWSTransportAdapter(wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer transport.Close()

	received := make(chan []byte, 4)
	ally := auth.NewPeer(&auth.PeerOptions{Wallet: allyWallet, Transport: transport})
	ally.ListenForGeneralMessages(func(ctx context.Context, senderPK *ec.PublicKey, payload []byte) error {
		received <- payload
		return nil
	})
	if err := ally.Start(); err != nil {
		t.Fatalf("ally start: %v", err)
	}
	go transport.StartReceive()

	if err := ally.ToPeer(t.Context(), []byte("hello"), nil, 5000); err != nil {
		t.Fatalf("ally ToPeer: %v", err)
	}

	// mgrB's AcceptPeer callback re-keys the ally to its identity hex
	// and runs checkAllowedPeer synchronously while handling that first
	// message (manager.go), but announceInterests/announceSHIP/
	// requestCatchUp can each independently queue a reply in "received"
	// around the same time -- so retrying the call under test is the
	// deterministic way to wait for "now eligible," rather than trying
	// to infer it from which announce happens to arrive first.
	deadline := time.Now().Add(5 * time.Second)
	var sent int
	for {
		sent = mgrB.BroadcastACMEChallenge("challenge.example.org+token", []byte("secret"), time.Now().Add(time.Minute))
		if sent > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if sent != 1 {
		t.Fatalf("BroadcastACMEChallenge sent to %d peer(s), want 1", sent)
	}

	// The burst from admission (topics, SHIP, catch-up) may have put
	// other messages ahead of the challenge in the channel -- skip past
	// anything that isn't MsgACMEChallenge specifically, rather than
	// assuming it's the next (or only) thing queued.
findChallenge:
	for {
		select {
		case payload := <-received:
			msg, err := Decode(payload)
			if err != nil {
				continue findChallenge // e.g. the un-decodable "hello" echoed back, if any
			}
			if msg.Type == MsgACMEChallenge {
				break findChallenge
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the allowed peer never received the broadcasted entry")
		}
	}
}

// TestBroadcastACMEChallenge_LockNotHeldDuringSend is test (d): while a
// send to a slow, non-responding fake peer is in flight (blocked inside
// ToPeer's handshake wait, which the production code bounds at 5000ms),
// a separate goroutine that needs m.mu's write lock must still complete
// quickly -- proving the lock is released before any send starts, not
// held for the whole broadcast.
//
// Mutation check for item 2: wrap the send loop in the same RLock the
// snapshot uses (restoring the original defer m.mu.RUnlock() over the
// whole function) and this test's deadline assertion fails, since the
// write-lock attempt would then queue behind the 5000ms send.
func TestBroadcastACMEChallenge_LockNotHeldDuringSend(t *testing.T) {
	walletB, _ := newIdentity(t)
	slowWallet, slowHex, slowKey := newIdentityWithKey(t)
	mgrB := newAllowlistTestManager(t, "acme-lock-b", walletB, []string{slowHex})

	// A server that accepts the TCP/WS connection (so a real auth.Peer
	// handshake begins) but reads exactly one frame and then blocks
	// forever -- never responding, so the ally-side ToPeer call on
	// mgrB's side (triggered by BroadcastACMEChallenge) can't complete
	// until its own 5000ms timeout.
	gotFrame := make(chan struct{})
	handler := websocket.Handler(func(conn *websocket.Conn) {
		var buf []byte
		if err := websocket.Message.Receive(conn, &buf); err == nil {
			close(gotFrame)
		}
		<-make(chan struct{}) // block forever; the test closes the listener on cleanup
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	// mgrB dials the slow fake peer as an outbound connection it
	// believes is a real mesh peer, bypassing the handshake-and-allow
	// flow (which would block on this slow remote) by inserting the
	// MeshPeer entry directly -- this test is only about
	// BroadcastACMEChallenge's own locking, not about how a peer gets
	// admitted.
	slowTransport, err := NewWSTransportAdapter(wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer slowTransport.Close()
	slowPeer := auth.NewPeer(&auth.PeerOptions{Wallet: slowWallet, Transport: slowTransport})
	if err := slowPeer.Start(); err != nil {
		t.Fatalf("slow peer start: %v", err)
	}
	go slowTransport.StartReceive()

	mgrB.mu.Lock()
	mgrB.peers[slowHex] = &MeshPeer{Peer: slowPeer, IdentityPK: slowKey.PubKey()}
	mgrB.mu.Unlock()

	broadcastDone := make(chan struct{})
	go func() {
		mgrB.BroadcastACMEChallenge("challenge.example.org+token", []byte("secret"), time.Now().Add(time.Minute))
		close(broadcastDone)
	}()

	// Wait for the slow peer to actually be mid-handshake (it received
	// at least one frame from mgrB's side) before testing the lock --
	// otherwise this could race ahead of BroadcastACMEChallenge even
	// starting its send.
	select {
	case <-gotFrame:
	case <-time.After(5 * time.Second):
		t.Fatal("the slow fake peer never received anything from mgrB")
	}

	// While the send above is still in flight (broadcastDone hasn't
	// fired -- confirmed below), a write-lock operation must complete
	// quickly, not queue behind the blocked send.
	select {
	case <-broadcastDone:
		t.Fatal("BroadcastACMEChallenge already returned -- the send wasn't actually in flight when the lock was tested")
	default:
	}

	lockAcquired := make(chan struct{})
	go func() {
		mgrB.mu.Lock()
		mgrB.mu.Unlock()
		close(lockAcquired)
	}()

	select {
	case <-lockAcquired:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("a write-lock operation did not complete within 500ms while a slow send was in flight -- the lock is being held during the send")
	}

	// Cleanup: the broadcast goroutine still has up to ~5s left on its
	// own ToPeer timeout; let the test finish without waiting on it.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-broadcastDone
	}()
	t.Cleanup(wg.Wait)
}
