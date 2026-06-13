package txrelay

import (
	"context"
	"log/slog"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// SDKBroadcaster adapts Anvil's *Broadcaster to the canonical
// transaction.Broadcaster interface from
// bsv-blockchain/go-sdk/transaction. Used by the v3 overlay engine's
// federation pipeline (engine.go:568 broadcastIfNeeded) so admitted
// transactions — including SHIP/SLAP advertisements — propagate
// outbound after local admission.
//
// Admission-success semantics
// --------------------------
//
// The upstream engine treats broadcaster failure as a fatal Submit
// error: engine.go:377 calls broadcastIfNeeded BEFORE commitAdmittedOutputs
// (engine.go:580), so any *BroadcastFailure aborts the submit and
// admission never commits. Anvil deliberately does NOT want that
// coupling — operators running without ARC, or with ARC temporarily
// failing, must still be able to admit transactions and serve them via
// the local mempool + mesh + federation. The right success boundary is
// LOCAL ADMISSION (BroadcastRaw → local mempool, always succeeds for a
// valid tx), and ARC propagation is best-effort: failures are logged
// but never surface as Broadcast errors. Codex review eea841a080448a49
// caught the original implementation conflating ARC availability with
// admission success.
//
// Failure modes mapped to canonical types:
//
//   - Local mempool admission fails (malformed tx, full mempool, etc.)
//     → BroadcastFailure. This is a real reason to abort the engine's
//     Submit because the tx couldn't even be staged.
//   - ARC unconfigured                  → log + Success (local-only OK).
//   - ARC submit fails (network, etc.)  → log + Success (local-only OK).
//   - ARC rejects (DOUBLE_SPEND, etc.)  → log + Success (the local
//     mempool already accepted; we trust the local admit even when ARC
//     disagrees so the engine doesn't refuse admits that conflict with
//     ARC's view of the mempool). Operators see the ARC status in the
//     logs and via BroadcastResult metrics.
type SDKBroadcaster struct {
	inner  *Broadcaster
	logger *slog.Logger
}

// NewSDKBroadcaster wraps an Anvil Broadcaster for use by go-sdk
// consumers. Caller retains ownership of the inner broadcaster; the
// adapter holds no goroutines and adds no lifecycle.
func NewSDKBroadcaster(inner *Broadcaster) *SDKBroadcaster {
	return &SDKBroadcaster{inner: inner, logger: slog.Default()}
}

// NewSDKBroadcasterWithLogger lets callers (tests, multi-tenant boots)
// supply a structured logger instead of slog.Default().
func NewSDKBroadcasterWithLogger(inner *Broadcaster, logger *slog.Logger) *SDKBroadcaster {
	if logger == nil {
		logger = slog.Default()
	}
	return &SDKBroadcaster{inner: inner, logger: logger}
}

// Compile-time assertion that SDKBroadcaster satisfies the canonical
// go-sdk interface. Breaks the build if go-sdk adds a method or
// changes a signature.
var _ transaction.Broadcaster = (*SDKBroadcaster)(nil)

// Broadcast forwards a canonical *transaction.Transaction through
// Anvil's broadcaster, returning the canonical success / failure pair.
func (a *SDKBroadcaster) Broadcast(tx *transaction.Transaction) (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
	return a.BroadcastCtx(context.Background(), tx)
}

// BroadcastCtx is the ctx-aware variant. Anvil's underlying ARC client
// doesn't currently honor context cancellation (HTTP request without
// ctx plumbing); ctx is accepted to satisfy the canonical interface
// and to be wired through when the underlying client gains support.
func (a *SDKBroadcaster) BroadcastCtx(_ context.Context, tx *transaction.Transaction) (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
	if a == nil || a.inner == nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "broadcaster-nil",
			Description: "txrelay.SDKBroadcaster: nil inner broadcaster",
		}
	}
	if tx == nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "tx-nil",
			Description: "txrelay.SDKBroadcaster: nil transaction",
		}
	}

	raw := tx.Bytes()
	txid := tx.TxID().String()

	// Local mempool admission — the canonical success boundary.
	// BroadcastRaw adds to the local mempool + mesh-announces; only
	// fails for malformed tx bytes (which a *Transaction by definition
	// shouldn't have). A real local-admit failure is the right reason
	// to surface BroadcastFailure and abort the engine's submit.
	localResult, err := a.inner.BroadcastRaw(raw)
	if err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "local-admit-failed",
			Description: err.Error(),
		}
	}
	if localResult == nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "local-admit-no-result",
			Description: "BroadcastRaw returned no result",
		}
	}

	// ARC propagation is best-effort AND fire-and-forget. The engine calls
	// this synchronously inside Submit (before admission is signalled), so a
	// slow or unreachable ARC must never add latency to — let alone hang —
	// /overlay/submit. The tx is already in the local mempool; ARC
	// failures/rejections are logged only and do not affect admission. Running
	// it in a goroutine keeps the admission response independent of ARC health.
	go func() {
		if arcResult, arcErr := a.inner.BroadcastToARC(raw); arcErr != nil {
			if a.logger != nil {
				a.logger.Warn("ARC propagation failed (admission unaffected)",
					"txid", txid,
					"error", arcErr)
			}
		} else if arcResult != nil && !arcResult.Accepted {
			if a.logger != nil {
				a.logger.Warn("ARC rejected tx (admission unaffected)",
					"txid", txid,
					"status", arcResult.Status,
					"message", arcResult.Message)
			}
		}
	}()

	return &transaction.BroadcastSuccess{
		Txid:    localResult.TxID,
		Message: localResult.Message,
	}, nil
}
