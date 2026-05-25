package txrelay

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// silentLogger discards all logger output so tests don't spam stdout.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// minimalTx builds a syntactically valid *transaction.Transaction —
// minimum required for Bytes()/TxID()/local mempool admission. The
// canonical wallet pipeline would never produce something this trivial
// in production, but the adapter's contract only cares that the tx
// is non-nil and serializable.
func minimalTx(t *testing.T) *transaction.Transaction {
	t.Helper()
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      0,
		LockingScript: script.NewFromBytes([]byte{0x51}), // OP_1
	})
	return tx
}

// TestSDKBroadcaster_ARCUnconfigured_StillReturnsSuccess pins the
// "ARC absent ≠ admission failure" contract. Codex review
// eea841a080448a49 caught the original adapter returning
// BroadcastFailure when the inner broadcaster had no ARC client —
// which would cascade through engine.Submit and abort EVERY canonical
// /submit (not just SHIP/SLAP, but UHRP/DEX/OrdLock too) on any node
// running without ARC.
//
// Correct semantic: ARC is best-effort. Local mempool admission
// (BroadcastRaw) is the success boundary; ARC propagation failures
// get logged but never abort.
func TestSDKBroadcaster_ARCUnconfigured_StillReturnsSuccess(t *testing.T) {
	mempool := NewMempool()
	// No ARC — most common operator config (single-node Anvil mesh
	// without an ARC backend).
	inner := NewBroadcaster(mempool, nil, silentLogger())
	adapter := NewSDKBroadcasterWithLogger(inner, silentLogger())

	tx := minimalTx(t)
	success, failure := adapter.Broadcast(tx)
	if failure != nil {
		t.Fatalf("ARC-unconfigured node must NOT return BroadcastFailure (would abort engine.Submit): code=%q desc=%q",
			failure.Code, failure.Description)
	}
	if success == nil {
		t.Fatal("expected BroadcastSuccess when local mempool accepts")
	}
	if success.Txid != tx.TxID().String() {
		t.Fatalf("Success.Txid mismatch: want %s, got %s", tx.TxID().String(), success.Txid)
	}
}

// TestSDKBroadcaster_NilInner_ReturnsFailure pins the one path that
// MUST fail: a nil inner broadcaster is a wiring bug, not a runtime
// availability issue. Surface it loudly so the engine's Submit aborts
// before committing.
func TestSDKBroadcaster_NilInner_ReturnsFailure(t *testing.T) {
	adapter := NewSDKBroadcaster(nil)
	tx := minimalTx(t)
	success, failure := adapter.Broadcast(tx)
	if success != nil {
		t.Fatal("nil inner broadcaster must return BroadcastFailure")
	}
	if failure == nil {
		t.Fatal("expected BroadcastFailure")
	}
	if failure.Code != "broadcaster-nil" {
		t.Fatalf("expected code broadcaster-nil, got %q", failure.Code)
	}
}

// TestSDKBroadcaster_NilTx_ReturnsFailure mirrors the nil-inner path
// for nil tx — another wiring-level error that must abort.
func TestSDKBroadcaster_NilTx_ReturnsFailure(t *testing.T) {
	inner := NewBroadcaster(NewMempool(), nil, silentLogger())
	adapter := NewSDKBroadcasterWithLogger(inner, silentLogger())
	success, failure := adapter.Broadcast(nil)
	if success != nil {
		t.Fatal("nil tx must return BroadcastFailure")
	}
	if failure == nil || failure.Code != "tx-nil" {
		t.Fatalf("expected code tx-nil, got %+v", failure)
	}
}

// TestSDKBroadcaster_CtxAwareVariantMatchesBroadcast verifies the
// ctx-aware variant returns the same shape as the non-ctx variant.
// Context cancellation isn't currently honored (Anvil's ARC client
// doesn't wire ctx through) but the canonical interface requires both
// methods, and tests should pin their behavior.
func TestSDKBroadcaster_CtxAwareVariantMatchesBroadcast(t *testing.T) {
	inner := NewBroadcaster(NewMempool(), nil, silentLogger())
	adapter := NewSDKBroadcasterWithLogger(inner, silentLogger())
	tx := minimalTx(t)
	success, failure := adapter.BroadcastCtx(context.Background(), tx)
	if failure != nil {
		t.Fatalf("expected success: %+v", failure)
	}
	if success == nil || success.Txid != tx.TxID().String() {
		t.Fatalf("BroadcastCtx returned wrong success: %+v", success)
	}
}

// TestSDKBroadcaster_LocalMempoolAdmitIsTheSuccessBoundary verifies
// the broader policy: regardless of ARC state, the tx ends up in the
// local mempool. This is what the engine's Submit relies on for the
// admission to be committed.
func TestSDKBroadcaster_LocalMempoolAdmitIsTheSuccessBoundary(t *testing.T) {
	mempool := NewMempool()
	inner := NewBroadcaster(mempool, nil, silentLogger())
	adapter := NewSDKBroadcasterWithLogger(inner, silentLogger())
	tx := minimalTx(t)

	_, failure := adapter.Broadcast(tx)
	if failure != nil {
		t.Fatalf("local admission must succeed: %+v", failure)
	}

	// Verify the tx actually landed in the local mempool.
	txid := tx.TxID().String()
	if _, ok := mempool.Get(txid); !ok {
		t.Fatalf("tx %s missing from local mempool after Broadcast success", txid)
	}
}
