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
	"log/slog"
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

// The event handlers (BackfillFromLegacyMetadata, OutputAdmittedByTopic,
// OutputSpent, OutputNoLongerRetainedInHistory, OutputEvicted,
// OutputBlockHeightUpdated) and the removeOutpoint helper they share live
// in uhrp_events.go — split out to hold this file under the package's
// per-file size norm once the fix pass's query-path additions landed
// here, no behaviour change.

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

	// Fix pass (spec item 5): Outpoint is canonical's direct single-
	// record key and short-circuits before every other key is even
	// inspected — UHRPLookupService.ts's lookup() returns on this path
	// first, so Anvil's does too.
	if q.Outpoint != "" {
		return s.lookupByOutpoint(q.Outpoint)
	}

	// Canonical @bsv/sdk StorageDownloader clients resolve content by its
	// uhrp:// URL, not by raw hash. Decode the URL to the content hash so
	// those queries hit the same hash index — accept what canonical clients
	// send (same lesson as V1/atomic BEEF on submit). An explicit
	// content_hash takes precedence when both are supplied.
	//
	// Fix pass (cold review B1 / spec item 1): capture viaUhrpUrl BEFORE
	// rewriting ContentHash below. A uhrpUrl-originated query must only
	// ever answer with BRC-26 records — StorageDownloader.resolve()
	// PushDrop-decodes every returned output with no try/catch
	// (ts-sdk storage/StorageDownloader.ts) — while a direct content_hash
	// query keeps returning both formats (filterUHRPRecords' canonicalOnly
	// parameter, uhrp_filter.go).
	viaUhrpUrl := q.ContentHash == "" && q.UhrpUrl != ""
	if viaUhrpUrl {
		hashBytes, err := storage.GetHashFromURL(q.UhrpUrl)
		if err != nil {
			return nil, fmt.Errorf("uhrp lookup: invalid uhrpUrl %q: %w", q.UhrpUrl, err)
		}
		q.ContentHash = hex.EncodeToString(hashBytes)
	}

	// Fix pass (spec item 5): HostIdentityKey / ExpiryTime AND-combine
	// with whatever base set ContentHash/UhrpUrl/List selects below, or —
	// supplied alone with no hash and no list — scan every entry the way
	// List:"all" does. Mirrors canonical UHRPLookupService.ts's
	// `records.find(query)` Mongo-style multi-field exact match.
	extra := uhrpQueryFilter{hostIdentityKey: q.HostIdentityKey, expiryTime: q.ExpiryTime}

	switch {
	case q.ContentHash != "":
		formulas, err := s.scanByHash(strings.ToLower(q.ContentHash), viaUhrpUrl, extra)
		if err != nil {
			return nil, err
		}
		return &lookup.LookupAnswer{
			Type:     lookup.AnswerTypeFormula,
			Formulas: formulas,
		}, nil

	case q.List == "all":
		formulas, err := s.scanAllItems(extra)
		if err != nil {
			return nil, err
		}
		return &lookup.LookupAnswer{
			Type:     lookup.AnswerTypeFormula,
			Formulas: formulas,
		}, nil

	case q.List == "hashes":
		counts, err := s.countByHash(extra)
		if err != nil {
			return nil, err
		}
		return &lookup.LookupAnswer{
			Type:   lookup.AnswerTypeFreeform,
			Result: counts,
		}, nil

	case extra.active():
		formulas, err := s.scanAllItems(extra)
		if err != nil {
			return nil, err
		}
		return &lookup.LookupAnswer{
			Type:     lookup.AnswerTypeFormula,
			Formulas: formulas,
		}, nil

	default:
		return nil, errors.New("uhrp lookup: query must specify content_hash, uhrpUrl, outpoint, hostIdentityKey, expiryTime, or list")
	}
}

// lookupByOutpoint answers the Outpoint query key: a direct single-record
// lookup, independent of (and ignoring) every other field on the query —
// matching canonical UHRPLookupService.ts's short-circuit (fix pass, spec
// item 5).
//
// Unlike every other query path, this one does NOT filter an expired
// BRC-26 record: canonical UHRPLookupService.ts:62-67's outpoint branch
// is a bare findOne with no expiry check at all, so Anvil matches that
// exactly here (fix pass, re-review RISKS item 2). The other paths'
// server-side expiry filtering (uhrpExpired, filterUHRPRecords rule 1,
// uhrp_filter.go) is a separate, pre-existing, deliberate Anvil-only
// hardening choice that canonical doesn't apply on ITS non-outpoint path
// either (UHRPLookupService.ts:68-72's records.find(query) has no expiry
// check) — this change only removes Anvil's own expiry check from the
// one path (outpoint) where canonical's behavior is unambiguous and
// directly comparable; it leaves the other, already-divergent paths
// exactly as they were.
func (s *UHRPLookupService) lookupByOutpoint(raw string) (*lookup.LookupAnswer, error) {
	op, err := parseUHRPOutpointQuery(raw)
	if err != nil {
		return nil, fmt.Errorf("uhrp lookup: invalid outpoint %q: %w", raw, err)
	}
	_, ok, err := s.loadItem(op)
	if err != nil {
		if errors.Is(err, errUHRPCorruptRecord) {
			// Fix pass, re-review BLOCKER: a corrupt record must be
			// skipped here exactly as itemsByHash and allItemRecords skip
			// one during a scan (uhrp_filter.go) — propagating it as a
			// hard error would turn a single bit-rotted record into a
			// failure for the one query shape that names it directly,
			// while the same corruption is already silently skipped by a
			// content_hash, uhrpUrl, or list=all query over the same data.
			slog.Warn("uhrp lookup: skipping corrupt record in outpoint lookup",
				"txid", op.Txid.String(), "vout", op.Index, "error", err)
			return &lookup.LookupAnswer{Type: lookup.AnswerTypeFormula, Formulas: []lookup.LookupFormula{}}, nil
		}
		return nil, err
	}
	if !ok {
		return &lookup.LookupAnswer{Type: lookup.AnswerTypeFormula, Formulas: []lookup.LookupFormula{}}, nil
	}
	return &lookup.LookupAnswer{
		Type:     lookup.AnswerTypeFormula,
		Formulas: []lookup.LookupFormula{{Outpoint: op}},
	}, nil
}

// GetDocumentation returns the human-readable description.
func (s *UHRPLookupService) GetDocumentation() string { return s.docs }

// GetMetaData returns the typed canonical metadata block.
func (s *UHRPLookupService) GetMetaData() *overlay.MetaData { return s.meta }

// removeOutpoint (shared by the write-path event handlers that delete an
// entry) lives in uhrp_events.go, next to the handlers that are its only
// callers.

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

// parseUHRPOutpointQuery decodes canonical UHRPLookupService.ts's
// Outpoint query key: "<txid-hex>.<output-index>", dot-separated (fix
// pass, spec item 5). This is the wire format an external canonical
// client sends inside its query object — distinct from uhrpItemKey /
// uhrpHashKey above, which encode Anvil's own internal LevelDB keys
// using ':' and never appear on the wire.
func parseUHRPOutpointQuery(s string) (*transaction.Outpoint, error) {
	txidHex, idxStr, ok := strings.Cut(s, ".")
	if !ok {
		return nil, errors.New(`want "<txid-hex>.<output-index>"`)
	}
	h, err := chainhash.NewHashFromHex(txidHex)
	if err != nil {
		return nil, fmt.Errorf("invalid txid: %w", err)
	}
	idx, err := strconv.ParseUint(idxStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid output index: %w", err)
	}
	return &transaction.Outpoint{Txid: *h, Index: uint32(idx)}, nil
}

// nowUnix is a package-level indirection so tests can inject a fixed
// clock. Defaults to time.Now().Unix().
var nowUnix = func() int64 { return time.Now().Unix() }
