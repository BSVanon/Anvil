package lookups

// This file holds the UHRP lookup's write path: the engine's event
// callbacks (OutputAdmittedByTopic / OutputSpent /
// OutputNoLongerRetainedInHistory / OutputEvicted /
// OutputBlockHeightUpdated), the one-time migration backfill, and the
// shared removeOutpoint helper they end up calling. Split out of
// uhrp.go, which was growing past this package's established per-file
// size after adding Outpoint, HostIdentityKey, and ExpiryTime; this file and uhrp.go
// together replace what was one file, with no behaviour change. uhrp.go
// keeps the type definitions, constructor, and query path (Lookup);
// uhrp_filter.go keeps the read-side iteration/filtering the query path
// needs.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// --- event handlers --------------------------------------------------------

// BackfillFromLegacyMetadata populates this service's local lk_uhrp
// indexes for a single legacy AdmittedOutput. Used by migration
// migration to make migrated records visible through engine.Lookup
// without going through the OutputAdmittedByTopic event (which
// requires AtomicBEEF the migration doesn't have).
//
// metadata is the JSON blob the legacy engine stored on each admitted
// output — for UHRP topics it's a marshalled topics.UHRPEntry.
//
// NOTE: even after backfill, canonical /lookup will drop migrated
// records at engine-hydration time because storage has no beef3 entry
// for them (legacy engine never stored BEEF). The backfilled lk_*
// entries are still useful for: (a) preventing re-admission of the
// same outpoint, (b) being immediately queryable once BEEF arrives via
// a future fetch (e.g. JungleBus). Tracked in operator docs as a known
// post-migration limitation.
func (s *UHRPLookupService) BackfillFromLegacyMetadata(outpoint *transaction.Outpoint, metadata json.RawMessage) error {
	if outpoint == nil {
		return errors.New("uhrp backfill: nil outpoint")
	}
	if len(metadata) == 0 {
		return errors.New("uhrp backfill: empty metadata")
	}
	var entry topics.UHRPEntry
	if err := json.Unmarshal(metadata, &entry); err != nil {
		return fmt.Errorf("uhrp backfill: decode metadata: %w", err)
	}
	if entry.ContentHash == "" {
		return errors.New("uhrp backfill: metadata missing content_hash")
	}
	item := uhrpItem{
		ContentHash: strings.ToLower(entry.ContentHash),
		URL:         entry.URL,
		ContentType: entry.ContentType,
		AdmittedAt:  nowUnix(),
		BRC26:       entry.BRC26,
		IdentityKey: entry.IdentityKey,
		Expiry:      entry.Expiry,
	}
	body, err := json.Marshal(&item)
	if err != nil {
		return fmt.Errorf("uhrp backfill: marshal item: %w", err)
	}
	batch := new(leveldb.Batch)
	batch.Put(uhrpItemKey(&outpoint.Txid, outpoint.Index), body)
	batch.Put(uhrpHashKey(item.ContentHash, &outpoint.Txid, outpoint.Index), nil)
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("uhrp backfill: write index: %w", err)
	}
	return nil
}

// OutputAdmittedByTopic ingests a freshly-admitted output. The payload's
// AtomicBEEF carries the focus tx; we extract that tx's locking script at
// OutputIndex, parse it via the canonical UHRP parser, and store the
// metadata in our local indexes. Non-UHRP topics are ignored — the engine
// fans every admission out to every registered lookup service, so the
// per-service topic filter is the lookup's responsibility.
func (s *UHRPLookupService) OutputAdmittedByTopic(ctx context.Context, payload *engine.OutputAdmittedByTopic) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.UHRPTopicName {
		return nil
	}
	// Version-agnostic parse via the shared helper (accepts Atomic / V1 / V2) —
	// the engine forwards whatever BEEF the submitter sent. Parsing atomic-only
	// here (as this path used to) rejected real-world V1 submits.
	tx, focusTxid, err := loadFocusTx(payload.AtomicBEEF)
	if err != nil {
		return fmt.Errorf("uhrp lookup: %w", err)
	}
	if int(payload.OutputIndex) >= len(tx.Outputs) {
		return fmt.Errorf("uhrp lookup: output index %d out of range for tx %s", payload.OutputIndex, focusTxid.String())
	}
	out := tx.Outputs[payload.OutputIndex]
	if out.LockingScript == nil {
		return nil
	}
	entry := topics.ParseUHRPOutput(out.LockingScript.Bytes())
	if entry == nil {
		// Not a UHRP advertisement of either format. Admission already
		// verified a BRC-26 output's shape and signature; a re-parse miss
		// here is non-fatal, mirroring the KVStore lookup.
		return nil
	}

	item := uhrpItem{
		ContentHash: strings.ToLower(entry.ContentHash),
		URL:         entry.URL,
		ContentType: entry.ContentType,
		AdmittedAt:  nowUnix(),
		BRC26:       entry.BRC26,
		IdentityKey: entry.IdentityKey,
		Expiry:      entry.Expiry,
	}
	body, err := json.Marshal(&item)
	if err != nil {
		return fmt.Errorf("uhrp lookup: marshal item: %w", err)
	}

	batch := new(leveldb.Batch)
	batch.Put(uhrpItemKey(focusTxid, payload.OutputIndex), body)
	batch.Put(uhrpHashKey(item.ContentHash, focusTxid, payload.OutputIndex), nil)
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("uhrp lookup: write index: %w", err)
	}
	return nil
}

// OutputSpent removes the outpoint from both indexes when the engine
// notifies us that a UHRP UTXO was spent.
func (s *UHRPLookupService) OutputSpent(ctx context.Context, payload *engine.OutputSpent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.UHRPTopicName || payload.Outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&payload.Outpoint.Txid, payload.Outpoint.Index)
}

// OutputNoLongerRetainedInHistory is treated identically to OutputSpent
// for UHRP — the service doesn't retain history.
func (s *UHRPLookupService) OutputNoLongerRetainedInHistory(ctx context.Context, outpoint *transaction.Outpoint, topic string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if topic != topics.UHRPTopicName || outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&outpoint.Txid, outpoint.Index)
}

// OutputEvicted removes the outpoint regardless of topic — the canonical
// LookupService contract is "permanently remove from all indices."
// Because the UHRP service only stores UHRP entries, a per-outpoint
// removal can safely target the single index family.
func (s *UHRPLookupService) OutputEvicted(ctx context.Context, outpoint *transaction.Outpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&outpoint.Txid, outpoint.Index)
}

// OutputBlockHeightUpdated is a no-op: UHRP results aren't ordered by
// block height (queries are by content hash or list-all).
func (s *UHRPLookupService) OutputBlockHeightUpdated(ctx context.Context, txid *chainhash.Hash, blockHeight uint32, blockIndex uint64) error {
	return nil
}

// --- shared write-path helper -----------------------------------------

func (s *UHRPLookupService) removeOutpoint(txid *chainhash.Hash, vout uint32) error {
	itemKey := uhrpItemKey(txid, vout)
	body, err := s.db.Get(itemKey, nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("uhrp lookup: read item for remove: %w", err)
	}
	var item uhrpItem
	if err := json.Unmarshal(body, &item); err != nil {
		// Corrupt record — drop the primary key but skip the hash key
		// because we can't decode it.
		return s.db.Delete(itemKey, nil)
	}
	batch := new(leveldb.Batch)
	batch.Delete(itemKey)
	batch.Delete(uhrpHashKey(item.ContentHash, txid, vout))
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("uhrp lookup: delete batch: %w", err)
	}
	return nil
}
