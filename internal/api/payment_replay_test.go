package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/chainhash"
)

// replayTxID returns a distinct txid for n.
func replayTxID(n int) chainhash.Hash {
	var h chainhash.Hash
	h[0], h[1], h[2], h[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return h
}

func TestPaymentReplaySetRefusesAcceptedAndInFlightTxids(t *testing.T) {
	s := newPaymentReplaySet(time.Hour, 10, time.Now)
	a, b := replayTxID(1), replayTxID(2)
	if !s.begin(a) {
		t.Fatal("a new txid must be claimable")
	}
	if s.begin(a) {
		t.Fatal("a txid being verified must not be claimable by a second request")
	}
	s.end(a, true)
	if s.begin(a) {
		t.Fatal("an accepted txid must not be claimable again")
	}
	if !s.begin(b) {
		t.Fatal("a new txid must be claimable")
	}
	s.end(b, false)
	if !s.begin(b) {
		t.Fatal("a refused payment's txid must be claimable again, so the payer can retry")
	}
	s.end(b, false)
}

func TestPaymentReplaySetForgetsAfterWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newPaymentReplaySet(24*time.Hour, 10, func() time.Time { return now })
	a := replayTxID(1)
	s.begin(a)
	s.end(a, true)
	now = now.Add(24*time.Hour - time.Second)
	if s.begin(a) {
		t.Fatal("a txid accepted less than the window ago must be refused")
	}
	now = now.Add(time.Second)
	if !s.begin(a) {
		t.Fatal("a txid accepted the window ago must be forgotten")
	}
}

func TestPaymentReplaySetEvictsOldestAtCapacity(t *testing.T) {
	const capacity = 100
	s := newPaymentReplaySet(time.Hour, capacity, time.Now)
	for i := 0; i <= capacity; i++ { // one more than the capacity
		s.begin(replayTxID(i))
		s.end(replayTxID(i), true)
	}
	if s.size != capacity || len(s.accepted) != capacity {
		t.Fatalf("the set must hold %d txids, holds %d (map %d)", capacity, s.size, len(s.accepted))
	}
	if !s.begin(replayTxID(0)) {
		t.Fatal("the oldest txid must be the one evicted")
	}
	if s.begin(replayTxID(1)) {
		t.Fatal("only the oldest txid may be evicted")
	}
}

// A capacity below 1 is taken as 1, so the set still remembers its newest
// txid instead of failing to evict from an empty ring.
func TestPaymentReplaySetCapacityIsAtLeastOne(t *testing.T) {
	for _, capacity := range []int{0, -1} {
		s := newPaymentReplaySet(time.Hour, capacity, time.Now)
		for i := 0; i < 2; i++ {
			if !s.begin(replayTxID(i)) {
				t.Fatalf("capacity %d: new txid %d refused", capacity, i)
			}
			s.end(replayTxID(i), true)
		}
		if s.begin(replayTxID(1)) {
			t.Fatalf("capacity %d: the newest txid must still be remembered", capacity)
		}
		if !s.begin(replayTxID(0)) {
			t.Fatalf("capacity %d: the older txid must have been evicted for the newest", capacity)
		}
	}
}

// TestDirectPaymentReplaySetMemory measures the set at its production window
// and capacity, the figure quoted in payment_replay.go.
func TestDirectPaymentReplaySetMemory(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	s := newPaymentReplaySet(directPaymentReplayWindow, directPaymentReplayCapacity, time.Now)
	for i := 0; i < directPaymentReplayCapacity; i++ {
		s.begin(replayTxID(i))
		s.end(replayTxID(i), true)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	heap := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	runtime.KeepAlive(s)
	t.Logf("%d txids: %d bytes of heap (%.1f MiB)", s.size, heap, float64(heap)/(1<<20))
	if s.size != directPaymentReplayCapacity {
		t.Fatalf("the set holds %d txids, want %d", s.size, directPaymentReplayCapacity)
	}
	if heap > 16<<20 {
		t.Fatalf("a full set takes %d bytes, want under 16 MiB", heap)
	}
}

// TestDirectPaymentReplayRefused: one direct payment pays for one request.
// Its replays are refused with ERR_PAYMENT_REPLAYED, even though ARC answers
// SEEN_ON_NETWORK again for a transaction it already knows.
func TestDirectPaymentReplayRefused(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	srv.paymentGate.arcClient = mockARCServer(t)
	ef, err := buildSignedDirectPaymentTx(t, testPayeeScript(t), 100).EFHex()
	if err != nil {
		t.Fatalf("serialize extended format: %v", err)
	}
	if w := serveDirectPayment(srv, "/stats", ef); w.Code != http.StatusOK {
		t.Fatalf("the first use of a payment: got %d %s, want 200", w.Code, w.Body.String())
	}
	for i := 0; i < 3; i++ {
		requirePaymentCode(t, serveDirectPayment(srv, "/stats", ef), codePaymentReplayed)
	}
}

// TestDirectPaymentRetryAfterRefusedStatus: a payment ARC did not yet report
// as accepted is not remembered, so the same transaction can pay once ARC
// does.
func TestDirectPaymentRetryAfterRefusedStatus(t *testing.T) {
	var status atomic.Value
	status.Store("SENT_TO_NETWORK")
	arc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(txrelay.ARCResponse{TxID: "mock", Status: status.Load().(string)})
	}))
	t.Cleanup(arc.Close)
	srv := testServerWithPaymentGate(t, 100)
	srv.paymentGate.arcClient = txrelay.NewARCClient(arc.URL, "")
	ef, err := buildSignedDirectPaymentTx(t, testPayeeScript(t), 100).EFHex()
	if err != nil {
		t.Fatalf("serialize extended format: %v", err)
	}
	requirePaymentCode(t, serveDirectPayment(srv, "/stats", ef), codePaymentNotAccepted)
	status.Store("SEEN_ON_NETWORK")
	if w := serveDirectPayment(srv, "/stats", ef); w.Code != http.StatusOK {
		t.Fatalf("the retry once ARC reports SEEN_ON_NETWORK: got %d %s, want 200", w.Code, w.Body.String())
	}
}

// TestDirectPaymentMinedDepth: a payment ARC reports as MINED is accepted
// only when the node can see it is at most maxDirectPaymentDepth blocks below
// its header tip. A height more than maxPaymentHeightAboveTip blocks above the
// tip means the node's headers are behind, and is refused as such, not as too
// old: a stale tip must not let any height above it through.
func TestDirectPaymentMinedDepth(t *testing.T) {
	payee := testPayeeScript(t)
	payees := []Payee{{Role: "infrastructure", LockingScriptHex: payee, AmountSats: 100}}
	pay := func(minedAt, tip uint32, haveTip bool) error {
		cfg := PaymentGateConfig{
			PriceSats: 100, PayeeScriptHex: payee, NonceProvider: &DevNonceProvider{},
			ARCClient: mockARCWithStatus(t, "MINED", minedAt),
		}
		if haveTip {
			cfg.HeaderTip = func() uint32 { return tip }
		}
		ef, err := buildSignedDirectPaymentTx(t, payee, 100).EFHex()
		if err != nil {
			t.Fatalf("serialize extended format: %v", err)
		}
		_, err = NewPaymentGate(cfg).verifyDirectPayment(context.Background(), ef, payees)
		return err
	}
	const tip = 900_000
	accepted := []struct {
		name         string
		minedAt, tip uint32
		haveTip      bool
	}{
		{"mined at the tip", tip, tip, true},
		{"mined maxDirectPaymentDepth blocks deep", tip - maxDirectPaymentDepth, tip, true},
		{"mined one block above this node's tip", tip + 1, tip, true},
		{"mined maxPaymentHeightAboveTip blocks above this node's tip", tip + maxPaymentHeightAboveTip, tip, true},
	}
	for _, tc := range accepted {
		if err := pay(tc.minedAt, tc.tip, tc.haveTip); err != nil {
			t.Fatalf("%s: want accepted, got %v", tc.name, err)
		}
	}
	refused := []struct {
		name         string
		minedAt, tip uint32
		haveTip      bool
		code         string
	}{
		{"mined one block deeper than maxDirectPaymentDepth", tip - maxDirectPaymentDepth - 1, tip, true, codePaymentTooOld},
		{"mined a year ago", tip - 52_560, tip, true, codePaymentTooOld},
		{"mined with no block height", 0, tip, true, codePaymentTooOld},
		{"mined, and the node's tip is 0", tip, 0, true, codePaymentTooOld},
		{"mined, and the node has no header tip", tip, 0, false, codePaymentTooOld},
		{"mined three blocks above this node's tip", tip + 3, tip, true, codePaymentHeadersBehind},
		{"mined far above a header tip that stopped 20,000 blocks back", tip, tip - 20_000, true, codePaymentHeadersBehind},
	}
	for _, tc := range refused {
		err := pay(tc.minedAt, tc.tip, tc.haveTip)
		var refusal *paymentRefusal
		if !errors.As(err, &refusal) || refusal.code != tc.code {
			t.Fatalf("%s: want a %s refusal, got %v", tc.name, tc.code, err)
		}
	}
}

// TestServerPaymentGateUsesHeaderTip: the server's gate reads its header
// store's tip for the depth check.
func TestServerPaymentGateUsesHeaderTip(t *testing.T) {
	srv := testServer(t)
	pg := newServerPaymentGate(ServerConfig{
		HeaderStore: srv.headerStore, PaymentSatoshis: 100,
		PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{},
	}, nil)
	if pg.headerTip == nil || pg.headerTip() != srv.headerStore.Tip() {
		t.Fatal("the server's payment gate must read the header store's tip")
	}
}
