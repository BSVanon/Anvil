package v3engine

import (
	"context"

	"github.com/BSVanon/Anvil/internal/overlay/overlayctx"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// go-overlay-services v1.3.1's engine.Submit runs verify, admission, spend
// marking, broadcast, onSteakReady, the commit and propagation without ever
// checking its context between them. The context reached the commit only
// through the storage and lookup-service methods the engine calls, and Anvil's
// return early once it is done. So a submit deadline that expired after
// MarkUTXOsAsSpent, or after one topic's InsertOutputs, left durable partial
// state behind a 504.
//
// detachedStorage and detachedLookup are the engine's views of Anvil's store
// and lookup services. Every storage call and every lookup-service
// notification runs under context.WithoutCancel(ctx): once the engine starts
// writing, a deadline or a client disconnect can no longer stop it part-way.
// What still checks the context is what runs before the first write
// (spv.Verify and the topic adapters' entry check) and the propagation after
// the commit, whose failure the engine only logs. WithoutCancel keeps the
// context's values, so the legacy shim's per-topic commit notifier
// (internal/overlay/overlayctx) still reaches the store.
//
// The one exception is a read for a request that only reads: a lookup or a
// GASP reply, whose handler marks its context overlayctx.ReadOnly. Such a
// read keeps the caller's context, so a lookup whose client has gone away
// stops hydrating at its next read rather than reading on for nobody. Reads
// stay detached otherwise, as the engine reads
// between the writes of a commit too (deleteUTXODeep's FindOutput, the merkle
// updates, GASP sync), and writes stay detached whatever the mark.
//
// Neither type embeds the interface it implements. A method added upstream
// fails to compile here instead of silently keeping the cancellable context.

// detachedStorage passes every call to inner with the context's cancellation
// and deadline removed, but for the reads of a request marked
// overlayctx.ReadOnly. Anvil code that holds the store itself, outside the
// engine, still has its context honored.
type detachedStorage struct {
	inner engine.Storage
}

var _ engine.Storage = detachedStorage{}

// reading is the context a storage read runs under: ctx itself when it is a
// read-only request's (overlayctx.ReadOnly), ctx without its cancellation
// otherwise.
func reading(ctx context.Context) context.Context {
	if overlayctx.IsReadOnly(ctx) {
		return ctx
	}
	return context.WithoutCancel(ctx)
}

// InsertOutputs implements engine.Storage without cancellation.
func (s detachedStorage) InsertOutputs(ctx context.Context, topic string, txid *chainhash.Hash, outputs []uint32, outpointsConsumed []*transaction.Outpoint, beef *transaction.Beef, ancillaryTxids []*chainhash.Hash) error {
	return s.inner.InsertOutputs(context.WithoutCancel(ctx), topic, txid, outputs, outpointsConsumed, beef, ancillaryTxids)
}

// FindOutput implements engine.Storage as a read (see reading). The commit
// calls it from deleteUTXODeep.
func (s detachedStorage) FindOutput(ctx context.Context, outpoint *transaction.Outpoint, topic *string, spent *bool, includeBEEF bool) (*engine.Output, error) {
	return s.inner.FindOutput(reading(ctx), outpoint, topic, spent, includeBEEF)
}

// FindOutputs implements engine.Storage as a read (see reading).
func (s detachedStorage) FindOutputs(ctx context.Context, outpoints []*transaction.Outpoint, topic string, spent *bool, includeBEEF bool) ([]*engine.Output, error) {
	return s.inner.FindOutputs(reading(ctx), outpoints, topic, spent, includeBEEF)
}

// FindOutputsForTransaction implements engine.Storage as a read (see
// reading).
func (s detachedStorage) FindOutputsForTransaction(ctx context.Context, txid *chainhash.Hash, includeBEEF bool) ([]*engine.Output, error) {
	return s.inner.FindOutputsForTransaction(reading(ctx), txid, includeBEEF)
}

// FindUTXOsForTopic implements engine.Storage as a read (see reading).
func (s detachedStorage) FindUTXOsForTopic(ctx context.Context, topic string, since float64, limit uint32, includeBEEF bool) ([]*engine.Output, error) {
	return s.inner.FindUTXOsForTopic(reading(ctx), topic, since, limit, includeBEEF)
}

// DeleteOutput implements engine.Storage without cancellation.
func (s detachedStorage) DeleteOutput(ctx context.Context, outpoint *transaction.Outpoint, topic string) error {
	return s.inner.DeleteOutput(context.WithoutCancel(ctx), outpoint, topic)
}

// MarkUTXOsAsSpent implements engine.Storage without cancellation.
func (s detachedStorage) MarkUTXOsAsSpent(ctx context.Context, outpoints []*transaction.Outpoint, topic string, spendTxid *chainhash.Hash) error {
	return s.inner.MarkUTXOsAsSpent(context.WithoutCancel(ctx), outpoints, topic, spendTxid)
}

// UpdateConsumedBy implements engine.Storage without cancellation.
func (s detachedStorage) UpdateConsumedBy(ctx context.Context, outpoint *transaction.Outpoint, topic string, consumedBy []*transaction.Outpoint) error {
	return s.inner.UpdateConsumedBy(context.WithoutCancel(ctx), outpoint, topic, consumedBy)
}

// UpdateTransactionBEEF implements engine.Storage without cancellation.
func (s detachedStorage) UpdateTransactionBEEF(ctx context.Context, txid *chainhash.Hash, beef *transaction.Beef) error {
	return s.inner.UpdateTransactionBEEF(context.WithoutCancel(ctx), txid, beef)
}

// UpdateOutputBlockHeight implements engine.Storage without cancellation.
func (s detachedStorage) UpdateOutputBlockHeight(ctx context.Context, outpoint *transaction.Outpoint, topic string, blockHeight uint32, blockIndex uint64) error {
	return s.inner.UpdateOutputBlockHeight(context.WithoutCancel(ctx), outpoint, topic, blockHeight, blockIndex)
}

// InsertAppliedTransaction implements engine.Storage without cancellation.
func (s detachedStorage) InsertAppliedTransaction(ctx context.Context, tx *overlay.AppliedTransaction) error {
	return s.inner.InsertAppliedTransaction(context.WithoutCancel(ctx), tx)
}

// DoesAppliedTransactionExist implements engine.Storage as a read (see
// reading).
func (s detachedStorage) DoesAppliedTransactionExist(ctx context.Context, tx *overlay.AppliedTransaction) (bool, error) {
	return s.inner.DoesAppliedTransactionExist(reading(ctx), tx)
}

// UpdateLastInteraction implements engine.Storage without cancellation.
func (s detachedStorage) UpdateLastInteraction(ctx context.Context, host, topic string, since float64) error {
	return s.inner.UpdateLastInteraction(context.WithoutCancel(ctx), host, topic, since)
}

// GetLastInteraction implements engine.Storage as a read (see reading).
func (s detachedStorage) GetLastInteraction(ctx context.Context, host, topic string) (float64, error) {
	return s.inner.GetLastInteraction(reading(ctx), host, topic)
}

// FindOutpointsByMerkleState implements engine.Storage as a read (see
// reading).
func (s detachedStorage) FindOutpointsByMerkleState(ctx context.Context, topic string, state engine.MerkleState, limit uint32) ([]*transaction.Outpoint, error) {
	return s.inner.FindOutpointsByMerkleState(reading(ctx), topic, state, limit)
}

// ReconcileMerkleRoot implements engine.Storage without cancellation.
func (s detachedStorage) ReconcileMerkleRoot(ctx context.Context, topic string, blockHeight uint32, merkleRoot *chainhash.Hash) error {
	return s.inner.ReconcileMerkleRoot(context.WithoutCancel(ctx), topic, blockHeight, merkleRoot)
}

// LoadAncillaryBeef implements engine.Storage as a read (see reading).
func (s detachedStorage) LoadAncillaryBeef(ctx context.Context, output *engine.Output) error {
	return s.inner.LoadAncillaryBeef(reading(ctx), output)
}

// detachedLookup passes the five notification callbacks to inner with the
// context's cancellation and deadline removed, so a commit cannot stop
// between the store and a lookup index. Lookup keeps the caller's context: a
// client that disconnects still stops a query at the service's own check.
type detachedLookup struct {
	inner engine.LookupService
}

var _ engine.LookupService = detachedLookup{}

// OutputAdmittedByTopic implements engine.LookupService without cancellation.
func (l detachedLookup) OutputAdmittedByTopic(ctx context.Context, payload *engine.OutputAdmittedByTopic) error {
	return l.inner.OutputAdmittedByTopic(context.WithoutCancel(ctx), payload)
}

// OutputSpent implements engine.LookupService without cancellation.
func (l detachedLookup) OutputSpent(ctx context.Context, payload *engine.OutputSpent) error {
	return l.inner.OutputSpent(context.WithoutCancel(ctx), payload)
}

// OutputNoLongerRetainedInHistory implements engine.LookupService without
// cancellation.
func (l detachedLookup) OutputNoLongerRetainedInHistory(ctx context.Context, outpoint *transaction.Outpoint, topic string) error {
	return l.inner.OutputNoLongerRetainedInHistory(context.WithoutCancel(ctx), outpoint, topic)
}

// OutputEvicted implements engine.LookupService without cancellation.
func (l detachedLookup) OutputEvicted(ctx context.Context, outpoint *transaction.Outpoint) error {
	return l.inner.OutputEvicted(context.WithoutCancel(ctx), outpoint)
}

// OutputBlockHeightUpdated implements engine.LookupService without
// cancellation.
func (l detachedLookup) OutputBlockHeightUpdated(ctx context.Context, txid *chainhash.Hash, blockHeight uint32, blockIndex uint64) error {
	return l.inner.OutputBlockHeightUpdated(context.WithoutCancel(ctx), txid, blockHeight, blockIndex)
}

// Lookup implements engine.LookupService with the caller's context.
func (l detachedLookup) Lookup(ctx context.Context, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	return l.inner.Lookup(ctx, question)
}

// GetDocumentation implements engine.LookupService.
func (l detachedLookup) GetDocumentation() string { return l.inner.GetDocumentation() }

// GetMetaData implements engine.LookupService.
func (l detachedLookup) GetMetaData() *overlay.MetaData { return l.inner.GetMetaData() }
