package gossip

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// TestOnACMEChallenge_OversizePayloadNeverUnmarshalled verifies that an
// required oversize test: a payload bigger than
// acmeChallengeMaxPayloadBytes is refused before json.Unmarshal ever
// runs on it — proved through the acmeOversizeDropped seam, not just by
// the hook never firing, since a payload this test crafts would
// otherwise unmarshal just fine and reach the hook: a well-formed
// ACMEChallengePayload with a valid key and expires, padded past the
// cap purely by an oversized (but validly encoded) value.
func TestOnACMEChallenge_OversizePayloadNeverUnmarshalled(t *testing.T) {
	w, _ := newIdentity(t)
	m := newAllowlistTestManager(t, "oversize", w, nil)

	hookCalls := 0
	m.SetACMEChallengeHook(func(senderPKHex, key string, value []byte, expires time.Time) {
		hookCalls++
	})

	huge := make([]byte, acmeChallengeMaxPayloadBytes)
	raw, err := json.Marshal(ACMEChallengePayload{
		Key:     "gateway.example.org+token",
		Value:   huge,
		Expires: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= acmeChallengeMaxPayloadBytes {
		t.Fatalf("test setup: encoded payload is %d bytes, want it to exceed the %d-byte cap", len(raw), acmeChallengeMaxPayloadBytes)
	}

	before := acmeOversizeDropped.Load()
	if err := m.onACMEChallenge(strangerHex, json.RawMessage(raw)); err != nil {
		t.Fatalf("onACMEChallenge: %v", err)
	}
	after := acmeOversizeDropped.Load()

	if after != before+1 {
		t.Errorf("acmeOversizeDropped moved by %d, want exactly 1 for one oversize payload", after-before)
	}
	if hookCalls != 0 {
		t.Errorf("hook called %d time(s) for an oversize payload, want 0 — a payload this size would otherwise have unmarshalled and fired it", hookCalls)
	}
}

// TestOnACMEChallenge_UndersizePayloadStillReachesTheHook is the
// oversize test's control: the same shape, two bytes under the cap
// instead of over it, still reaches the hook — confirming the boundary
// in the test above is the cap doing its job, not some other rejection.
func TestOnACMEChallenge_UndersizePayloadStillReachesTheHook(t *testing.T) {
	w, _ := newIdentity(t)
	m := newAllowlistTestManager(t, "undersize", w, nil)

	hookCalls := 0
	m.SetACMEChallengeHook(func(senderPKHex, key string, value []byte, expires time.Time) {
		hookCalls++
	})

	raw, err := json.Marshal(ACMEChallengePayload{
		Key:     "gateway.example.org+token",
		Value:   []byte("a small, legitimately-sized value"),
		Expires: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) >= acmeChallengeMaxPayloadBytes {
		t.Fatalf("test setup: encoded payload is %d bytes, want it under the %d-byte cap", len(raw), acmeChallengeMaxPayloadBytes)
	}

	before := acmeOversizeDropped.Load()
	if err := m.onACMEChallenge(strangerHex, json.RawMessage(raw)); err != nil {
		t.Fatalf("onACMEChallenge: %v", err)
	}
	if acmeOversizeDropped.Load() != before {
		t.Error("acmeOversizeDropped moved for a payload under the cap")
	}
	if hookCalls != 1 {
		t.Errorf("hook called %d time(s) for a well-formed, under-cap payload, want 1", hookCalls)
	}
}

// newRateLimitedTestManager is newAllowlistTestManager's counterpart
// with an explicit, tiny rate limit — burst 2, refill slow enough that
// a handful of calls made back-to-back in a test never see a token
// come back — so a burst test can be both fast and deterministic
// instead of needing the default 30/s burst 100 and either a real
// sleep or hundreds of calls.
func newRateLimitedTestManager(t *testing.T, name string, w wallet.Interface) *Manager {
	t.Helper()
	dir, err := os.MkdirTemp("", "anvil-acme-rate-"+name+"-*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	store, err := envelope.NewStore(dir, 3600, 65536)
	if err != nil {
		t.Fatalf("new envelope store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	m := NewManager(ManagerConfig{
		Wallet:     w,
		Store:      store,
		MaxSeen:    100,
		RateBurst:  2,
		RatePerSec: 0.0001,
	})
	t.Cleanup(m.Stop)
	return m
}

// TestOnACMEChallenge_BurstBeyondRateIsDropped verifies that a burst beyond
// rate-limit test: with burst 2, a third well-formed, under-cap
// payload from the same peer in the same instant is dropped — reusing
// the data path's own per-peer limiter (allowPeerMessage,
// manager_seed.go), the same bucket onData already draws from, rather
// than a second one just for this message type.
func TestOnACMEChallenge_BurstBeyondRateIsDropped(t *testing.T) {
	w, _ := newIdentity(t)
	m := newRateLimitedTestManager(t, "burst", w)

	var hookCalls int
	m.SetACMEChallengeHook(func(senderPKHex, key string, value []byte, expires time.Time) {
		hookCalls++
	})

	wellFormed := func(n int) json.RawMessage {
		raw, err := json.Marshal(ACMEChallengePayload{
			Key:     "gateway.example.org+token",
			Value:   []byte("ok"),
			Expires: time.Now().Add(time.Minute).Unix(),
		})
		if err != nil {
			t.Fatalf("marshal payload %d: %v", n, err)
		}
		return json.RawMessage(raw)
	}

	// Burst 2: the first two calls from this peer are within budget.
	for i := 0; i < 2; i++ {
		if err := m.onACMEChallenge(strangerHex, wellFormed(i)); err != nil {
			t.Fatalf("onACMEChallenge call %d: %v", i, err)
		}
	}
	if hookCalls != 2 {
		t.Fatalf("hook called %d time(s) after 2 calls within burst, want 2", hookCalls)
	}

	// The third call in the same instant has nothing left in the
	// bucket and the refill rate is far too slow to have added any —
	// dropped silently, same as onData's own rate-limited envelopes.
	if err := m.onACMEChallenge(strangerHex, wellFormed(2)); err != nil {
		t.Fatalf("onACMEChallenge call 2: %v", err)
	}
	if hookCalls != 2 {
		t.Errorf("hook called %d time(s) after a burst beyond the rate limit, want still 2 (the 3rd call dropped)", hookCalls)
	}

	// A different peer has its own, untouched bucket.
	otherHex := "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := m.onACMEChallenge(otherHex, wellFormed(3)); err != nil {
		t.Fatalf("onACMEChallenge for a different peer: %v", err)
	}
	if hookCalls != 3 {
		t.Errorf("hook called %d time(s) after a different peer's call, want 3 — a different peer's bucket must be independent", hookCalls)
	}
}
