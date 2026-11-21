package gossip

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestUnknownMeshMessageTypeIsIgnoredNotDropped is the wire-compatibility
// check required before adding a new mesh message type: an older peer
// (or, symmetrically, this code receiving a type it predates)
// must ignore an unrecognised MessageType rather than treat it as a
// reason to drop the connection. handleMessage's switch (handlers.go)
// logs and falls through to a nil return for its default case — this
// pins that behaviour so a future change to the dispatch can't silently
// turn an unknown type into a dropped connection.
func TestUnknownMeshMessageTypeIsIgnoredNotDropped(t *testing.T) {
	m := NewManager(ManagerConfig{Wallet: wallet.NewTestWalletForRandomKey(t)})
	payload, err := Encode(MessageType("some_future_message_type"), map[string]string{"x": "y"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := m.handleMessage("deadbeef", nil, payload); err != nil {
		t.Fatalf("handleMessage returned an error for an unknown type, want nil (ignored, not dropped): %v", err)
	}
}

// TestOnACMEChallengeDispatchesToHook proves MsgACMEChallenge reaches the
// registered hook with the decoded fields intact, through the real
// handleMessage dispatch (not by calling onACMEChallenge directly).
func TestOnACMEChallengeDispatchesToHook(t *testing.T) {
	m := NewManager(ManagerConfig{Wallet: wallet.NewTestWalletForRandomKey(t)})

	type got struct {
		sender  string
		key     string
		value   []byte
		expires time.Time
	}
	var received *got
	m.SetACMEChallengeHook(func(senderPKHex, key string, value []byte, expires time.Time) {
		received = &got{sender: senderPKHex, key: key, value: value, expires: expires}
	})

	expires := time.Now().Add(300 * time.Second).Truncate(time.Second)
	payload, err := Encode(MsgACMEChallenge, ACMEChallengePayload{
		Key:     "example.org+token",
		Value:   []byte("token-cert-bytes"),
		Expires: expires.Unix(),
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := m.handleMessage("senderhex", nil, payload); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}
	if received == nil {
		t.Fatal("hook was not called")
	}
	if received.sender != "senderhex" || received.key != "example.org+token" || string(received.value) != "token-cert-bytes" {
		t.Fatalf("hook got %+v, want key=example.org+token value=token-cert-bytes sender=senderhex", received)
	}
	if !received.expires.Equal(expires) {
		t.Fatalf("expires = %v, want %v", received.expires, expires)
	}
}

// TestOnACMEChallengeNoHookIsSilentlyDropped proves a node with gateway
// mode off (no hook registered) neither errors nor panics on a received
// MsgACMEChallenge.
func TestOnACMEChallengeNoHookIsSilentlyDropped(t *testing.T) {
	m := NewManager(ManagerConfig{Wallet: wallet.NewTestWalletForRandomKey(t)})
	payload, err := Encode(MsgACMEChallenge, ACMEChallengePayload{Key: "k+http-01", Value: []byte("v"), Expires: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := m.handleMessage("senderhex", nil, payload); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}
}

// TestOnACMEChallengeRejectsMalformedPayload proves a payload that fails
// to decode, or decodes with no key/expires, never reaches the hook.
func TestOnACMEChallengeRejectsMalformedPayload(t *testing.T) {
	m := NewManager(ManagerConfig{Wallet: wallet.NewTestWalletForRandomKey(t)})
	called := false
	m.SetACMEChallengeHook(func(string, string, []byte, time.Time) { called = true })

	// Not valid JSON for ACMEChallengePayload.
	if err := m.onACMEChallenge("x", json.RawMessage(`"not-an-object"`)); err != nil {
		t.Fatalf("onACMEChallenge: %v", err)
	}
	// Valid JSON, but an empty key.
	if err := m.onACMEChallenge("x", json.RawMessage(`{"key":"","value":"dg==","expires":123}`)); err != nil {
		t.Fatalf("onACMEChallenge: %v", err)
	}
	// Valid JSON, but a non-positive expiry.
	if err := m.onACMEChallenge("x", json.RawMessage(`{"key":"k","value":"dg==","expires":0}`)); err != nil {
		t.Fatalf("onACMEChallenge: %v", err)
	}
	if called {
		t.Fatal("hook was called for a malformed/incomplete payload")
	}
}

// TestBroadcastACMEChallengeReachesConnectedPeer is an end-to-end proof,
// over a real authenticated mesh connection (the same two-manager
// harness multi_peer_test.go uses), that BroadcastACMEChallenge actually
// reaches a connected peer's onACMEChallenge/hook, and that an
// unreachable (zero-peer) manager returns 0 rather than erroring.
func TestBroadcastACMEChallengeReachesConnectedPeer(t *testing.T) {
	mgrB := NewManager(ManagerConfig{Wallet: wallet.NewTestWalletForRandomKey(t)})
	defer mgrB.Stop()

	received := make(chan ACMEChallengePayload, 1)
	mgrB.SetACMEChallengeHook(func(_ string, key string, value []byte, expires time.Time) {
		received <- ACMEChallengePayload{Key: key, Value: value, Expires: expires.Unix()}
	})

	ts := httptest.NewServer(mgrB.MeshHandler())
	defer ts.Close()
	wsURL := "ws" + ts.URL[len("http"):]

	mgrA := NewManager(ManagerConfig{Wallet: wallet.NewTestWalletForRandomKey(t)})
	defer mgrA.Stop()

	if sent := mgrA.BroadcastACMEChallenge("nobody+http-01", []byte("x"), time.Now().Add(time.Minute)); sent != 0 {
		t.Fatalf("BroadcastACMEChallenge with zero peers sent = %d, want 0", sent)
	}

	if err := mgrA.ConnectPeer(t.Context(), wsURL); err != nil {
		t.Fatalf("ConnectPeer: %v", err)
	}

	expires := time.Now().Add(120 * time.Second).Truncate(time.Second)
	sent := mgrA.BroadcastACMEChallenge("example.org+token", []byte("cert-bytes"), expires)
	if sent != 1 {
		t.Fatalf("BroadcastACMEChallenge sent = %d, want 1", sent)
	}

	select {
	case got := <-received:
		if got.Key != "example.org+token" || string(got.Value) != "cert-bytes" || got.Expires != expires.Unix() {
			t.Fatalf("peer B received %+v, want key=example.org+token value=cert-bytes expires=%d", got, expires.Unix())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("peer B never received the broadcast ACME challenge")
	}
}
