package v3engine

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// verifyDeadline is Handlers.SubmitTimeout in the verification case. Without
// a deadline, spv.Verify of the costly BEEF below runs about 6.9 s and finds
// it valid (measured once, without -race), so a 500 ms deadline always
// expires during verification, in the guard's own verification before the
// engine sees the BEEF, before admission or any write.
const verifyDeadline = 500 * time.Millisecond

// costlyRounds is how many times the costly scripts copy and hash their
// 1 MiB element: three instructions a round, within routeguard.MaxScriptOps,
// so the guard lets the BEEF through to the deadline instead of refusing it
// as too complex.
const costlyRounds = 16_000

// costlyUHRPBEEF returns a V1 BEEF whose tip advertises hashHex for tm_uhrp
// but spends an output whose locking script pushes 1 MiB and hashes it
// costlyRounds times (OP_DUP OP_SHA256 OP_DROP), so spv.Verify runs for seconds.
// Verified to the end it is valid, and tm_uhrp would admit the advertisement.
func costlyUHRPBEEF(t *testing.T, hashHex string) []byte {
	t.Helper()
	lock := &script.Script{}
	if err := lock.AppendPushData(bytes.Repeat([]byte{0x01}, 1<<20)); err != nil {
		t.Fatalf("AppendPushData: %v", err)
	}
	for i := 0; i < costlyRounds; i++ {
		_ = lock.AppendOpcodes(script.OpDUP, script.OpSHA256, script.OpDROP)
	}
	costly := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: lock, Satoshis: 1})
	tip := transaction.NewTransaction()
	tip.AddInputFromTx(costly, 0, nil)
	tip.Inputs[0].UnlockingScript = &script.Script{}
	tip.AddOutput(uhrpOutput(t, hashHex))
	return encodeFixtureBEEF(t, tip, false)
}

// TestSubmit_DeadlineBeforeTheCommitLeavesNoState: the deadline still stops a
// submit, but only before its first write. Expiring during spv.Verify, or
// during admission (a held pre-admission read, after which a topic adapter's
// context check fails), the submit must fail with the deadline and leave both
// databases exactly as they were.
func TestSubmit_DeadlineBeforeTheCommitLeavesNoState(t *testing.T) {
	t.Run("during verification, through POST /submit", func(t *testing.T) {
		se := newStallingEngine(t)
		admitOffer(t, se.eng, newCommitFixture(t))
		h := NewHandlers(se.eng)
		h.SubmitTimeout = verifyDeadline
		mux := http.NewServeMux()
		h.Register(mux, nil)
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		beef := costlyUHRPBEEF(t, strings.Repeat("d5", 32))

		before := stateDigest(t, se)
		start := time.Now()
		status, raw := postTopics(t, srv.URL, beef, []string{topics.UHRPTopicName})
		elapsed := time.Since(start)
		t.Logf("%d-byte BEEF answered %d after %v (deadline %v)", len(beef), status, elapsed, verifyDeadline)
		if status != http.StatusGatewayTimeout {
			t.Fatalf("expected 504 at the deadline, got %d: %s", status, raw)
		}
		assertCanonicalErrorEnvelope(t, bytes.NewReader(raw), "context deadline exceeded")
		if elapsed > verifyDeadline+3*time.Second {
			t.Errorf("the reply took %v, more than the %v deadline plus 3 s", elapsed, verifyDeadline)
		}
		if after := stateDigest(t, se); after != before {
			t.Errorf("a submit stopped in verification changed state:\nbefore %s\nafter  %s", before, after)
		}
	})

	t.Run("during admission", func(t *testing.T) {
		se := newStallingEngine(t)
		fx := newCommitFixture(t)
		admitOffer(t, se.eng, fx)
		ctx, cancel := context.WithTimeout(context.Background(), commitDeadline)
		defer cancel()
		heldLive := false
		se.stall.arm("DoesAppliedTransactionExist", func() {
			heldLive = ctx.Err() == nil
			<-ctx.Done()
		})

		before := stateDigest(t, se)
		_, err := se.eng.Submit(ctx, overlay.TaggedBEEF{Beef: fx.spendBEEF, Topics: commitTopics}, engine.SubmitModeCurrent, nil)
		if !heldLive {
			t.Fatal("the pre-admission read was not held before the deadline")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a submit whose deadline expired before admission returned %v, want the deadline", err)
		}
		if after := stateDigest(t, se); after != before {
			t.Errorf("a submit stopped in admission changed state:\nbefore %s\nafter  %s", before, after)
		}
	})
}
