package gossip

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// newID returns a fresh private key + its compressed-pubkey hex.
func newID(t *testing.T) (*ec.PrivateKey, string) {
	t.Helper()
	k, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k, hex.EncodeToString(k.PubKey().Compressed())
}

// originAttest builds a v3.2.0 forward payload: node `nodeKey` attests `msg`
// (whose Sender is the BRC-31 user) by signing the origin-bound digest.
func originAttest(t *testing.T, nodeKey *ec.PrivateKey, msg *messaging.Message) MsgForwardPayload {
	t.Helper()
	origin := hex.EncodeToString(nodeKey.PubKey().Compressed())
	d := messageForwardDigest(msg, origin)
	sig, err := nodeKey.Sign(d[:])
	if err != nil {
		t.Fatal(err)
	}
	return MsgForwardPayload{Message: *msg, Signature: hex.EncodeToString(sig.Serialize()), OriginNode: origin}
}

func sampleMsg(sender, recipient string) *messaging.Message {
	return &messaging.Message{
		Sender:     sender,
		Recipient:  recipient,
		MessageBox: "dex.swap",
		Body:       "offer-123",
		MessageID:  "mid-1",
		Timestamp:  1700000000,
	}
}

// TestForward_OriginNodeAttestation_RoundTrip is the regression for Codex's High
// finding: a message whose Sender is a BRC-31 user (NOT the node) must cross the
// mesh. Node A attests the user and signs the forward; node B accepts it and
// delivers, preserving the user identity as sender.
func TestForward_OriginNodeAttestation_RoundTrip(t *testing.T) {
	nodeA, _ := newID(t)
	_, aliceHex := newID(t) // the BRC-31 sender
	_, bobHex := newID(t)   // recipient hosted on node B

	msg := sampleMsg(aliceHex, bobHex)
	fwd := originAttest(t, nodeA, msg)

	// Sanity: signature verifies (the pre-fix code verified against msg.Sender
	// and would have rejected this node-signed forward).
	if !verifyForwardSignature(&fwd) {
		t.Fatal("origin-node-attested forward must verify")
	}

	// Node B receives and delivers it.
	mgrB := NewManager(ManagerConfig{Logger: slog.Default()})
	ms, err := messaging.NewStore(t.TempDir(), messaging.Options{TTLSeconds: 86400})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.Close() })
	mgrB.SetMsgStore(ms)

	raw, _ := json.Marshal(fwd)
	if err := mgrB.onMsgForward("some-peer-node", raw); err != nil {
		t.Fatalf("onMsgForward: %v", err)
	}

	got, err := ms.List(bobHex, "dex.swap")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 delivered message, got %d", len(got))
	}
	if got[0].Sender != aliceHex {
		t.Errorf("delivered sender must be the BRC-31 user %s, got %s", aliceHex, got[0].Sender)
	}
	if got[0].AttestedBy != fwd.OriginNode {
		t.Errorf("attestation = %q, want %q", got[0].AttestedBy, fwd.OriginNode)
	}
}

func TestForwardRejectsUncompressedOriginNodeWithoutMarkingSeen(t *testing.T) {
	node, compressed := newID(t)
	_, sender := newID(t)
	_, recipient := newID(t)
	msg := sampleMsg(sender, recipient)
	uncompressed := hex.EncodeToString(node.PubKey().Uncompressed())
	digest := messageForwardDigest(msg, uncompressed)
	signature, err := node.Sign(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	invalid := MsgForwardPayload{
		Message:    *msg,
		Signature:  hex.EncodeToString(signature.Serialize()),
		OriginNode: uncompressed,
	}

	store, err := messaging.NewStore(t.TempDir(), messaging.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	raw, _ := json.Marshal(invalid)
	if err := mgr.onMsgForward("peer", raw); err != nil {
		t.Fatal(err)
	}
	dedupKey := "msg:" + msg.MessageID
	mgr.seenMu.Lock()
	_, seen := mgr.msgSeen[dedupKey]
	mgr.seenMu.Unlock()
	if seen || store.Count() != 0 {
		t.Fatalf("uncompressed origin was accepted: seen=%v stored=%d", seen, store.Count())
	}

	valid := originAttest(t, node, msg)
	raw, _ = json.Marshal(valid)
	if err := mgr.onMsgForward("peer", raw); err != nil {
		t.Fatal(err)
	}
	got, err := store.List(recipient, msg.MessageBox)
	if err != nil || len(got) != 1 || got[0].AttestedBy != compressed {
		t.Fatalf("compressed origin delivery = %+v, err=%v", got, err)
	}
}

// TestForward_RejectsTamperedSender ensures a relay cannot swap the attested
// sender: the origin digest binds Sender, so changing it breaks the signature.
func TestForward_RejectsTamperedSender(t *testing.T) {
	nodeA, _ := newID(t)
	_, aliceHex := newID(t)
	_, bobHex := newID(t)
	_, malloryHex := newID(t)

	fwd := originAttest(t, nodeA, sampleMsg(aliceHex, bobHex))
	fwd.Message.Sender = malloryHex // tamper

	if verifyForwardSignature(&fwd) {
		t.Fatal("tampered sender must NOT verify")
	}
}

// TestForward_RejectsWrongOriginNode ensures the OriginNode field can't be
// swapped to impersonate another node's attestation.
func TestForward_RejectsWrongOriginNode(t *testing.T) {
	nodeA, _ := newID(t)
	_, otherNode := newID(t)
	_, aliceHex := newID(t)
	_, bobHex := newID(t)

	fwd := originAttest(t, nodeA, sampleMsg(aliceHex, bobHex))
	fwd.OriginNode = otherNode // claim a different origin

	if verifyForwardSignature(&fwd) {
		t.Fatal("wrong OriginNode must NOT verify")
	}
}

// TestForward_RejectsNodeSignedUserSenderWithoutOrigin reproduces the exact
// pre-fix bug shape and proves it is rejected: Sender is the user, the node
// signed the legacy digest, but OriginNode is empty so verification falls to the
// legacy "sender-signed" path and fails (node sig vs user pubkey).
func TestForward_RejectsNodeSignedUserSenderWithoutOrigin(t *testing.T) {
	nodeA, _ := newID(t)
	_, aliceHex := newID(t)
	_, bobHex := newID(t)

	msg := sampleMsg(aliceHex, bobHex)
	d := messageDigest(msg) // legacy digest
	sig, _ := nodeA.Sign(d[:])
	fwd := MsgForwardPayload{
		Message:   *msg,
		Signature: hex.EncodeToString(sig.Serialize()),
		// OriginNode intentionally empty → legacy verify against msg.Sender
	}
	if verifyForwardSignature(&fwd) {
		t.Fatal("node-signed forward with user sender and no OriginNode must be rejected")
	}
}

// TestForward_AnyPeerCanAttestArbitrarySender_DocumentsTrustAssumption locks in
// the KNOWN trust limitation Codex flagged (review ff263b37, Medium): the mesh
// forward proves only that *some* peer with a valid OriginNode signature vouched
// for the sender — it does NOT prove that peer is authoritative for that user.
// Here a peer (mallory's node) attests a Sender (alice) who never sent anything,
// and verification ACCEPTS it. This is intentional for the bespoke multi-node
// path (federation-operator trust; on-chain enforces the actual swap). If this
// test ever starts FAILING, the trust model was tightened — make that a conscious
// decision (e.g. BRC-34 overlay-routed forwarding), don't just "fix" the test.
func TestForward_AnyPeerCanAttestArbitrarySender_DocumentsTrustAssumption(t *testing.T) {
	malloryNode, _ := newID(t) // a mesh peer that is NOT alice's node
	_, aliceHex := newID(t)    // a user who never authored this message
	_, bobHex := newID(t)

	// mallory's node attests "alice sent this" and signs with its own key.
	fwd := originAttest(t, malloryNode, sampleMsg(aliceHex, bobHex))

	if !verifyForwardSignature(&fwd) {
		t.Fatal("documents current trust model: a peer-attested arbitrary sender is accepted; " +
			"if this now rejects, the cross-node trust model changed — confirm it was intended (BRC-34)")
	}
}

// TestForward_LegacySenderSignedStillVerifies preserves backward compatibility:
// a pre-v3.2.0 forward where the sender signed their own message (OriginNode
// empty) still verifies against msg.Sender.
func TestForward_LegacySenderSignedStillVerifies(t *testing.T) {
	alice, aliceHex := newID(t)
	_, bobHex := newID(t)

	msg := sampleMsg(aliceHex, bobHex)
	d := messageDigest(msg)
	sig, _ := alice.Sign(d[:])
	fwd := MsgForwardPayload{Message: *msg, Signature: hex.EncodeToString(sig.Serialize())}

	if !verifyForwardSignature(&fwd) {
		t.Fatal("legacy sender-signed forward must still verify")
	}
}

func legacyForward(t *testing.T, senderKey *ec.PrivateKey, msg *messaging.Message) MsgForwardPayload {
	t.Helper()
	digest := messageDigest(msg)
	sig, err := senderKey.Sign(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return MsgForwardPayload{Message: *msg, Signature: hex.EncodeToString(sig.Serialize())}
}

func observeForwardRelays(t *testing.T, manager *Manager) *int {
	t.Helper()
	count := new(int)
	previous := relayForwardTestHook
	relayForwardTestHook = func(got *Manager, _ string, _ MsgForwardPayload) {
		if got == manager {
			*count++
		}
	}
	t.Cleanup(func() { relayForwardTestHook = previous })
	return count
}

func TestMsgForwardRateLimitRunsBeforeSignatureVerification(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mgr := NewManager(ManagerConfig{Logger: logger, RatePerSec: 0.000001, RateBurst: 1})
	relays := observeForwardRelays(t, mgr)
	senderKey, sender := newID(t)
	_, recipient := newID(t)
	first := sampleMsg(sender, recipient)
	first.MessageID = "rate-1"
	raw, _ := json.Marshal(legacyForward(t, senderKey, first))
	if err := mgr.onMsgForward("limited-peer", raw); err != nil {
		t.Fatal(err)
	}
	second := sampleMsg(sender, recipient)
	second.MessageID = "rate-2"
	invalid := MsgForwardPayload{Message: *second, Signature: "00"}
	raw, _ = json.Marshal(invalid)
	if err := mgr.onMsgForward("limited-peer", raw); err != nil {
		t.Fatal(err)
	}
	if *relays != 1 {
		t.Fatalf("relays = %d, want only the first forward", *relays)
	}
	if got := logs.String(); !strings.Contains(got, "peer rate-limited") || strings.Contains(got, "signature invalid") {
		t.Fatalf("rate-limit/signature logs = %q", got)
	}
}

func TestMsgForwardDuplicateMissingFromMsgSeenIsNotRelayed(t *testing.T) {
	store, err := messaging.NewStore(t.TempDir(), messaging.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	relays := observeForwardRelays(t, mgr)
	senderKey, sender := newID(t)
	_, recipient := newID(t)
	msg := sampleMsg(sender, recipient)
	msg.MessageID = "duplicate-after-eviction"
	raw, _ := json.Marshal(legacyForward(t, senderKey, msg))
	if err := mgr.onMsgForward("peer", raw); err != nil {
		t.Fatal(err)
	}
	mgr.seenMu.Lock()
	clear(mgr.msgSeen)
	mgr.seenMu.Unlock()
	if err := mgr.onMsgForward("peer", raw); err != nil {
		t.Fatal(err)
	}
	if *relays != 1 || store.Count() != 1 {
		t.Fatalf("duplicate outcome: relays=%d stored=%d", *relays, store.Count())
	}
}

func TestMsgForwardQuotaRejectedRelayUsesManagerBudget(t *testing.T) {
	store, err := messaging.NewStore(t.TempDir(), messaging.Options{MaxPairMessages: 1, MaxStoreMessages: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	senderKey, sender := newID(t)
	_, recipient := newID(t)
	seed := sampleMsg(sender, recipient)
	seed.MessageID = "stored-first"
	if ok, err := store.Deliver(seed, "sender"); err != nil || !ok {
		t.Fatalf("seed deliver = %v, %v", ok, err)
	}
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	relays := observeForwardRelays(t, mgr)
	bucket := relayBucketFor(mgr)
	bucket.mu.Lock()
	bucket.tokens = 1
	bucket.lastRefill = time.Now().Add(time.Hour)
	bucket.mu.Unlock()
	for i, peer := range []string{"peer-a", "peer-b"} {
		msg := sampleMsg(sender, recipient)
		msg.MessageID = "quota-" + string(rune('1'+i))
		raw, _ := json.Marshal(legacyForward(t, senderKey, msg))
		if err := mgr.onMsgForward(peer, raw); err != nil {
			t.Fatal(err)
		}
	}
	if *relays != 1 {
		t.Fatalf("quota-rejected relays = %d, want one allowed and one budget drop", *relays)
	}
}

func TestMsgForwardNewlyStoredIsRelayed(t *testing.T) {
	store, err := messaging.NewStore(t.TempDir(), messaging.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	relays := observeForwardRelays(t, mgr)
	senderKey, sender := newID(t)
	_, recipient := newID(t)
	msg := sampleMsg(sender, recipient)
	msg.MessageID = "newly-stored"
	raw, _ := json.Marshal(legacyForward(t, senderKey, msg))
	if err := mgr.onMsgForward("peer", raw); err != nil {
		t.Fatal(err)
	}
	if *relays != 1 || store.Count() != 1 {
		t.Fatalf("new forward outcome: relays=%d stored=%d", *relays, store.Count())
	}
}

func TestMsgForwardNonQuotaStoreErrorIsNotRelayed(t *testing.T) {
	store, err := messaging.NewStore(t.TempDir(), messaging.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	relays := observeForwardRelays(t, mgr)
	senderKey, sender := newID(t)
	_, recipient := newID(t)
	msg := sampleMsg(sender, recipient)
	msg.MessageID = "closed-store"
	raw, _ := json.Marshal(legacyForward(t, senderKey, msg))
	if err := mgr.onMsgForward("peer", raw); err != nil {
		t.Fatal(err)
	}
	if *relays != 0 {
		t.Fatalf("non-quota store error relays = %d", *relays)
	}
}
