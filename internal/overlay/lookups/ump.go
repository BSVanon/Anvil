package lookups

// Canonical upstream primitive — UMP Lookup Service (ls_users).
//
// Pragmatic transitional placement: hosted in Anvil today; will be
// re-exported from `bsv-blockchain/go-overlay-discovery-services` once
// that repo gains a topic-impl partition for non-SHIP/SLAP canonical
// primitives. Port source: `bsv-blockchain/overlay-express-examples`
// → `ts-stack/packages/overlays/topics/src/ump/UMPLookupService.ts`.
// Semantic preserved: single-filter queries (presentationHash OR
// recoveryHash OR outpoint), returns at most one most-recent record.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// LevelDB sub-prefixes for the UMP lookup's local indexes. Lookup keys
// (presentationHash, recoveryHash) get their own secondary index so we
// can resolve a query without scanning every record.
const (
	umpItemPrefix         = "lk_users:item:"   // lk_users:item:<txid>:<vout> → JSON UMPRecord
	umpPresentationPrefix = "lk_users:pres:"   // lk_users:pres:<hash>:<txid>:<vout> → sentinel
	umpRecoveryPrefix     = "lk_users:rec:"    // lk_users:rec:<hash>:<txid>:<vout> → sentinel
)

// umpRecord is the per-output state the lookup keeps in LevelDB. Stored
// as JSON under umpItemPrefix and referenced by sentinel entries in the
// two hash prefixes for O(1) query-by-hash. Lookup order is
// most-recently-admitted-first via AdmittedAt (Unix-nanos so two
// admissions in the same second still order deterministically).
type umpRecord struct {
	PresentationHash string `json:"presentation_hash"`
	RecoveryHash     string `json:"recovery_hash"`
	UMPVersion       uint8  `json:"ump_version,omitempty"`
	KDFAlgorithm     string `json:"kdf_algorithm,omitempty"`
	KDFIterations    uint32 `json:"kdf_iterations,omitempty"`
	AdmittedAt       int64  `json:"admitted_at"`
}

// UMPLookupService implements engine.LookupService for tm_users.
type UMPLookupService struct {
	db   *leveldb.DB
	docs string
	meta *overlay.MetaData
}

// NewUMPLookupService constructs a UMP lookup backed by the supplied
// LevelDB handle.
func NewUMPLookupService(db *leveldb.DB) *UMPLookupService {
	return &UMPLookupService{
		db: db,
		docs: "UMP Lookup Service (BRC-100): resolve User Management Protocol tokens by " +
			"presentationHash (returning-user same-passkey rehydrate), recoveryHash " +
			"(lost-passkey + recovery-key restore), or outpoint (republish / health check).",
		meta: &overlay.MetaData{
			Name:        topics.UMPLookupServiceName,
			Description: "User Management Protocol token resolution by presentation/recovery hash",
			Version:     "1.0.0",
		},
	}
}

// Compile-time assertion that the type satisfies engine.LookupService.
var _ engine.LookupService = (*UMPLookupService)(nil)

// --- event handlers --------------------------------------------------------

// OutputAdmittedByTopic indexes a freshly-admitted UMP output. Non-UMP
// topics are silently ignored — the engine fans every admission out to
// every lookup service.
func (s *UMPLookupService) OutputAdmittedByTopic(ctx context.Context, payload *engine.OutputAdmittedByTopic) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.UMPTopicName {
		return nil
	}
	tx, focusTxid, err := loadFocusTx(payload.AtomicBEEF)
	if err != nil {
		return fmt.Errorf("ump lookup: %w", err)
	}
	if int(payload.OutputIndex) >= len(tx.Outputs) {
		return fmt.Errorf("ump lookup: output index %d out of range for tx %s", payload.OutputIndex, focusTxid.String())
	}
	out := tx.Outputs[payload.OutputIndex]
	if out.LockingScript == nil {
		return nil
	}
	entry, err := topics.ParseUMPOutput(out.LockingScript.Bytes())
	if err != nil || entry == nil {
		// Topic manager already filtered admissibility; a re-parse miss
		// here is non-fatal (admit pipeline can race with index churn).
		return nil
	}
	rec := umpRecord{
		PresentationHash: strings.ToLower(entry.PresentationHash),
		RecoveryHash:     strings.ToLower(entry.RecoveryHash),
		UMPVersion:       entry.UMPVersion,
		KDFAlgorithm:     entry.KDFAlgorithm,
		KDFIterations:    entry.KDFIterations,
		AdmittedAt:       nowUnixNano(),
	}
	body, err := json.Marshal(&rec)
	if err != nil {
		return fmt.Errorf("ump lookup: marshal record: %w", err)
	}
	batch := new(leveldb.Batch)
	batch.Put(itemKey(umpItemPrefix, focusTxid, payload.OutputIndex), body)
	if rec.PresentationHash != "" {
		batch.Put(umpHashKey(umpPresentationPrefix, rec.PresentationHash, focusTxid, payload.OutputIndex), nil)
	}
	if rec.RecoveryHash != "" {
		batch.Put(umpHashKey(umpRecoveryPrefix, rec.RecoveryHash, focusTxid, payload.OutputIndex), nil)
	}
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("ump lookup: write index: %w", err)
	}
	return nil
}

// OutputSpent removes the record on spend (UMP rotates tokens by
// spending the previous one).
func (s *UMPLookupService) OutputSpent(ctx context.Context, payload *engine.OutputSpent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.UMPTopicName || payload.Outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&payload.Outpoint.Txid, payload.Outpoint.Index)
}

// OutputNoLongerRetainedInHistory is treated like OutputSpent — UMP
// doesn't retain history.
func (s *UMPLookupService) OutputNoLongerRetainedInHistory(ctx context.Context, outpoint *transaction.Outpoint, topic string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if topic != topics.UMPTopicName || outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&outpoint.Txid, outpoint.Index)
}

// OutputEvicted removes the record regardless of topic.
func (s *UMPLookupService) OutputEvicted(ctx context.Context, outpoint *transaction.Outpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&outpoint.Txid, outpoint.Index)
}

// OutputBlockHeightUpdated is a no-op: UMP queries aren't height-sorted.
func (s *UMPLookupService) OutputBlockHeightUpdated(ctx context.Context, txid *chainhash.Hash, blockHeight uint32, blockIndex uint64) error {
	return nil
}

// --- query path ------------------------------------------------------------

// Lookup answers a UMP query. Returns at most one formula (the most
// recent admit matching the filter), matching UMPLookupService.ts's
// findOne({ sort: { _id: -1 } }) semantic.
func (s *UMPLookupService) Lookup(ctx context.Context, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if question == nil {
		return nil, errors.New("ump lookup: nil question")
	}
	if question.Service != topics.UMPLookupServiceName {
		return nil, fmt.Errorf("ump lookup: service %q not supported", question.Service)
	}
	var q topics.UMPLookupQuery
	if err := jsonUnmarshalQuery(question.Query, &q); err != nil {
		return nil, fmt.Errorf("ump lookup: %w", err)
	}

	switch {
	case q.PresentationHash != "":
		op, err := s.findByHash(umpPresentationPrefix, strings.ToLower(q.PresentationHash))
		if err != nil {
			return nil, err
		}
		return formulaList(opSlice(op)), nil

	case q.RecoveryHash != "":
		op, err := s.findByHash(umpRecoveryPrefix, strings.ToLower(q.RecoveryHash))
		if err != nil {
			return nil, err
		}
		return formulaList(opSlice(op)), nil

	case q.Outpoint != "":
		op, err := parseOutpointString(q.Outpoint)
		if err != nil {
			return nil, fmt.Errorf("ump lookup: %w", err)
		}
		// Verify the outpoint is actually present in our index before
		// returning it (matches TS behavior — findOne returns null for
		// missing outpoint queries).
		if _, err := s.db.Get(itemKey(umpItemPrefix, &op.Txid, op.Index), nil); err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				return formulaList(nil), nil
			}
			return nil, fmt.Errorf("ump lookup: probe outpoint: %w", err)
		}
		return formulaList([]*transaction.Outpoint{op}), nil

	default:
		return nil, errors.New("ump lookup: query must include presentationHash, recoveryHash, or outpoint")
	}
}

// GetDocumentation returns the human-readable description.
func (s *UMPLookupService) GetDocumentation() string { return s.docs }

// GetMetaData returns the canonical metadata block.
func (s *UMPLookupService) GetMetaData() *overlay.MetaData { return s.meta }

// --- internal helpers ------------------------------------------------------

// findByHash returns the most-recently-admitted outpoint matching the
// given hash under the given hash-prefix index, or nil if no match.
// Most-recent-first by AdmittedAt on the underlying record.
func (s *UMPLookupService) findByHash(prefix, hashHex string) (*transaction.Outpoint, error) {
	fullPrefix := []byte(prefix + hashHex + ":")
	var bestOutpoint *transaction.Outpoint
	var bestAt int64
	err := scanPrefix(s.db, fullPrefix, func(key, _ []byte) error {
		op, ok := decodeHashIndexKeyUMP(key, len(fullPrefix))
		if !ok {
			return nil
		}
		body, err := s.db.Get(itemKey(umpItemPrefix, &op.Txid, op.Index), nil)
		if err != nil {
			return nil // sentinel without backing record — index drift, skip
		}
		var rec umpRecord
		if err := json.Unmarshal(body, &rec); err != nil {
			return nil
		}
		if bestOutpoint == nil || rec.AdmittedAt > bestAt {
			bestOutpoint = op
			bestAt = rec.AdmittedAt
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ump lookup: scan %s: %w", prefix, err)
	}
	return bestOutpoint, nil
}

// removeOutpoint deletes the record + both secondary indexes.
func (s *UMPLookupService) removeOutpoint(txid *chainhash.Hash, vout uint32) error {
	primary := itemKey(umpItemPrefix, txid, vout)
	body, err := s.db.Get(primary, nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("ump lookup: read record for remove: %w", err)
	}
	var rec umpRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return s.db.Delete(primary, nil) // corrupt — drop primary, skip sentinels
	}
	batch := new(leveldb.Batch)
	batch.Delete(primary)
	if rec.PresentationHash != "" {
		batch.Delete(umpHashKey(umpPresentationPrefix, rec.PresentationHash, txid, vout))
	}
	if rec.RecoveryHash != "" {
		batch.Delete(umpHashKey(umpRecoveryPrefix, rec.RecoveryHash, txid, vout))
	}
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("ump lookup: delete batch: %w", err)
	}
	return nil
}

// umpHashKey assembles a hash-index key:
// <prefix><hash-hex>:<txid-hex>:<vout-decimal>.
func umpHashKey(prefix, hashHex string, txid *chainhash.Hash, vout uint32) []byte {
	return []byte(prefix + hashHex + ":" + txid.String() + ":" + strconv.FormatUint(uint64(vout), 10))
}

// decodeHashIndexKeyUMP parses keys produced by umpHashKey, returning
// the trailing outpoint. prefixLen is len(prefix + hashHex + ":") —
// callers compute it once before iteration.
func decodeHashIndexKeyUMP(key []byte, prefixLen int) (*transaction.Outpoint, bool) {
	if len(key) < prefixLen {
		return nil, false
	}
	rest := string(key[prefixLen:])
	idx := strings.LastIndexByte(rest, ':')
	if idx != 64 {
		return nil, false
	}
	h, err := chainhash.NewHashFromHex(rest[:64])
	if err != nil {
		return nil, false
	}
	v, err := strconv.ParseUint(rest[idx+1:], 10, 32)
	if err != nil {
		return nil, false
	}
	return &transaction.Outpoint{Txid: *h, Index: uint32(v)}, true
}

// opSlice is a tiny convenience: nil-tolerant single-element slice.
func opSlice(op *transaction.Outpoint) []*transaction.Outpoint {
	if op == nil {
		return nil
	}
	return []*transaction.Outpoint{op}
}

// parseOutpointString decodes a "txid.vout" string into an Outpoint.
// Used by query.Outpoint resolution in Lookup.
func parseOutpointString(s string) (*transaction.Outpoint, error) {
	op, err := transaction.OutpointFromString(s)
	if err != nil {
		return nil, fmt.Errorf("parse outpoint %q: %w", s, err)
	}
	return op, nil
}
