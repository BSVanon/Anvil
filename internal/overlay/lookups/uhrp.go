// Package lookups holds the canonical engine.LookupService implementations
// for Anvil's overlay lookups. Each service maintains its own LevelDB
// sub-prefix index keyed by the metadata it cares about, hydrated by the
// engine's OutputAdmittedByTopic / OutputSpent / OutputEvicted callbacks.
//
// W-3 phase A (2026-05-13): UHRP shipped as the first end-to-end example.
// Phases B+ port DEX-swap, OrdLock listings, and OrdLock buy following
// the same pattern.
//
// Per the canonical model (verified against go-overlay-services
// pkg/core/engine/engine.go:723-744), lookups return LookupAnswer with
// Type=AnswerTypeFormula and a Formulas slice of outpoint references; the
// engine hydrates BEEF from its registered Storage layer (Anvil's
// internal/overlay/storage in W-5). Lookups never store BEEF locally —
// only the metadata indexes their queries need.
package lookups

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/storage"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// uhrpItemPrefix and uhrpHashPrefix are the LevelDB sub-prefixes for the
// UHRP lookup's local indexes. They live under a single root namespace
// (`lk_uhrp:`) so the lookup can share a database with the overlay
// storage adapter without collisions.
const (
	uhrpItemPrefix = "lk_uhrp:item:" // lk_uhrp:item:<txid-hex>:<vout> → item JSON
	uhrpHashPrefix = "lk_uhrp:hash:" // lk_uhrp:hash:<hash-hex>:<txid-hex>:<vout> → sentinel
)

// uhrpItem is the per-output record kept by the UHRP lookup. Stored as
// JSON under uhrpItemPrefix. AdmittedAt is Unix-seconds for stable
// ordering when callers want time-sorted results (not yet exposed in the
// query interface; reserved for future expansion).
type uhrpItem struct {
	ContentHash string `json:"content_hash"`
	URL         string `json:"url,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	AdmittedAt  int64  `json:"admitted_at"`
	// BRC26, IdentityKey and Expiry mirror topics.UHRPEntry — see there
	// for field meaning. A record written before these fields existed
	// decodes with BRC26 false (legacy), exactly as intended.
	BRC26       bool   `json:"brc26,omitempty"`
	IdentityKey string `json:"identity_key,omitempty"`
	Expiry      int64  `json:"expiry,omitempty"`
}

// UHRPLookupService implements engine.LookupService for the BRC-26 UHRP
// content-availability topic.
type UHRPLookupService struct {
	db   *leveldb.DB
	docs string
	meta *overlay.MetaData
}

// NewUHRPLookupService constructs a UHRP lookup backed by the given
// LevelDB handle. The caller retains ownership of the handle.
func NewUHRPLookupService(db *leveldb.DB) *UHRPLookupService {
	return &UHRPLookupService{
		db: db,
		docs: "UHRP Lookup (BRC-26): resolve content by SHA-256 hash (content_hash) " +
			"or by canonical uhrp:// URL (uhrpUrl), or list all advertised content (list).",
		meta: &overlay.MetaData{
			Name:        topics.UHRPLookupServiceName,
			Description: "UHRP content resolution by SHA-256 hash",
			Version:     "1.0.0",
		},
	}
}

// Compile-time assertion that the type satisfies engine.LookupService.
var _ engine.LookupService = (*UHRPLookupService)(nil)

// --- event handlers --------------------------------------------------------

// BackfillFromLegacyMetadata populates this service's local lk_uhrp
// indexes for a single legacy AdmittedOutput. Used by the W-4 phase B
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

// --- query path ------------------------------------------------------------

// Lookup answers a UHRP query. Returns a LookupAnswer with
// Type=AnswerTypeFormula referencing the matching outpoints — the
// canonical engine hydrates BEEF via the registered Storage layer on the
// response path. List-by-hashes returns a freeform map of hash → count.
func (s *UHRPLookupService) Lookup(ctx context.Context, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if question == nil {
		return nil, errors.New("uhrp lookup: nil question")
	}
	if question.Service != topics.UHRPLookupServiceName {
		return nil, fmt.Errorf("uhrp lookup: service %q not supported", question.Service)
	}

	var q topics.UHRPLookupQuery
	if len(question.Query) > 0 {
		if err := json.Unmarshal(question.Query, &q); err != nil {
			return nil, fmt.Errorf("uhrp lookup: invalid query: %w", err)
		}
	}

	// Canonical @bsv/sdk StorageDownloader clients resolve content by its
	// uhrp:// URL, not by raw hash. Decode the URL to the content hash so
	// those queries hit the same hash index — accept what canonical clients
	// send (same lesson as V1/atomic BEEF on submit). An explicit
	// content_hash takes precedence when both are supplied.
	if q.ContentHash == "" && q.UhrpUrl != "" {
		hashBytes, err := storage.GetHashFromURL(q.UhrpUrl)
		if err != nil {
			return nil, fmt.Errorf("uhrp lookup: invalid uhrpUrl %q: %w", q.UhrpUrl, err)
		}
		q.ContentHash = hex.EncodeToString(hashBytes)
	}

	switch {
	case q.ContentHash != "":
		formulas, err := s.scanByHash(strings.ToLower(q.ContentHash))
		if err != nil {
			return nil, err
		}
		return &lookup.LookupAnswer{
			Type:     lookup.AnswerTypeFormula,
			Formulas: formulas,
		}, nil

	case q.List == "all":
		formulas, err := s.scanAllItems()
		if err != nil {
			return nil, err
		}
		return &lookup.LookupAnswer{
			Type:     lookup.AnswerTypeFormula,
			Formulas: formulas,
		}, nil

	case q.List == "hashes":
		counts, err := s.countByHash()
		if err != nil {
			return nil, err
		}
		return &lookup.LookupAnswer{
			Type:   lookup.AnswerTypeFreeform,
			Result: counts,
		}, nil

	default:
		return nil, errors.New("uhrp lookup: query must specify content_hash, uhrpUrl, or list")
	}
}

// GetDocumentation returns the human-readable description.
func (s *UHRPLookupService) GetDocumentation() string { return s.docs }

// GetMetaData returns the typed canonical metadata block.
func (s *UHRPLookupService) GetMetaData() *overlay.MetaData { return s.meta }

// --- internal helpers ------------------------------------------------------

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

// --- key encoding ----------------------------------------------------------
//
// The read-path counterparts (decodeItemKey, decodeHashIndexKey) live in
// uhrp_filter.go, next to the iteration code that's their only caller.

func uhrpItemKey(txid *chainhash.Hash, vout uint32) []byte {
	return []byte(uhrpItemPrefix + txid.String() + ":" + strconv.FormatUint(uint64(vout), 10))
}

func uhrpHashKey(contentHash string, txid *chainhash.Hash, vout uint32) []byte {
	return []byte(uhrpHashPrefix + contentHash + ":" + txid.String() + ":" + strconv.FormatUint(uint64(vout), 10))
}

// nowUnix is a package-level indirection so tests can inject a fixed
// clock. Defaults to time.Now().Unix().
var nowUnix = func() int64 { return time.Now().Unix() }
