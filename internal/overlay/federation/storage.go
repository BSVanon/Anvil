// Package federation provides Anvil's canonical BRC-88 federation
// surface. It wraps `bsv-blockchain/go-overlay-discovery-services`'s
// SHIP/SLAP topic managers, lookup services, and WalletAdvertiser —
// the canonical Go reference implementations — with Anvil-specific
// LevelDB storage so we don't depend on MongoDB.
//
// Canonical adoption strategy:
//
//   - SHIP topic manager + lookup service: go-overlay-discovery-services/pkg/ship
//   - SLAP topic manager + lookup service: go-overlay-discovery-services/pkg/slap
//   - WalletAdvertiser:                    go-overlay-discovery-services/pkg/advertiser
//   - Default SHIP/SLAP tracker URLs:      go-sdk/overlay/lookup.DEFAULT_SLAP_TRACKERS
//   - LookupResolver:                      go-sdk/overlay/lookup.NewLookupResolver
//
// Anvil contributes:
//
//   - SHIPStorage / SLAPStorage implementations of the canonical
//     ship.StorageInterface and slap.StorageInterface, backed by
//     Anvil's existing LevelDB instance (sub-prefixes lk_ship: and
//     lk_slap:). MongoDB is the canonical package's default backend,
//     not its contract.
//   - cmd/anvil/main.go wiring that injects all of the above into the
//     v3engine.Config (Advertiser, SyncConfiguration, SHIPTrackers,
//     SLAPTrackers, LookupResolver, Broadcaster).
//
// See docs/internal/W10_FEDERATION_PLAN.md for the workstream context.
package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/types"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// LevelDB key prefixes for SHIP/SLAP records. Records are stored as
// JSON-encoded SHIPRecord / SLAPRecord values keyed by outpoint
// (txid:vout). All filtering and pagination happens via prefix iteration
// + in-memory predicate evaluation: SHIP/SLAP record sets are O(low
// hundreds) per overlay node in practice, so a full-scan filter is
// simpler and cheaper than per-attribute index maintenance.
const (
	shipRecordPrefix = "lk_ship:rec:"
	slapRecordPrefix = "lk_slap:rec:"
)

// SHIPStorage implements ship.StorageInterface from
// github.com/bsv-blockchain/go-overlay-discovery-services/pkg/ship over
// Anvil's LevelDB. Drop-in alternative to the canonical MongoDB-backed
// ship.NewStorage; the canonical ship.LookupService + ship.TopicManager
// accept any StorageInterface implementation.
type SHIPStorage struct {
	db *leveldb.DB
}

// NewSHIPStorage constructs a LevelDB-backed SHIP storage adapter
// against an existing LevelDB handle (Anvil's overlay directory).
func NewSHIPStorage(db *leveldb.DB) *SHIPStorage {
	return &SHIPStorage{db: db}
}

// shipKey builds the LevelDB key for a SHIP record by outpoint.
// Keying by outpoint guarantees one record per UTXO, mirroring the
// canonical MongoDB schema's compound (txid, outputIndex) primary key.
func shipKey(txid string, outputIndex int) []byte {
	return []byte(fmt.Sprintf("%s%s:%d", shipRecordPrefix, txid, outputIndex))
}

// StoreSHIPRecord persists a SHIP record. Called by the canonical
// ship.TopicManager when admitting a new tm_ship output.
func (s *SHIPStorage) StoreSHIPRecord(_ context.Context, txid string, outputIndex int, identityKey, domain, topic string) error {
	rec := types.SHIPRecord{
		Txid:        txid,
		OutputIndex: outputIndex,
		IdentityKey: identityKey,
		Domain:      domain,
		Topic:       topic,
		CreatedAt:   clock(),
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("federation: marshal SHIP record: %w", err)
	}
	if err := s.db.Put(shipKey(txid, outputIndex), body, nil); err != nil {
		return fmt.Errorf("federation: store SHIP record: %w", err)
	}
	return nil
}

// DeleteSHIPRecord removes a SHIP record. Called by the canonical
// ship.TopicManager when a tm_ship output gets spent (advertisement
// revocation).
func (s *SHIPStorage) DeleteSHIPRecord(_ context.Context, txid string, outputIndex int) error {
	if err := s.db.Delete(shipKey(txid, outputIndex), nil); err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("federation: delete SHIP record: %w", err)
	}
	return nil
}

// FindRecord returns UTXOReferences matching the SHIP query filters.
// Pagination + sorting honor the canonical contract.
func (s *SHIPStorage) FindRecord(_ context.Context, query types.SHIPQuery) ([]types.UTXOReference, error) {
	matched, err := s.scanSHIP(func(rec *types.SHIPRecord) bool {
		if query.Domain != nil && rec.Domain != *query.Domain {
			return false
		}
		if len(query.Topics) > 0 && !contains(query.Topics, rec.Topic) {
			return false
		}
		if query.IdentityKey != nil && rec.IdentityKey != *query.IdentityKey {
			return false
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	return paginate(matched, query.Limit, query.Skip, query.SortOrder), nil
}

// FindAll returns every SHIP record's outpoint, honoring limit/skip/sortOrder.
func (s *SHIPStorage) FindAll(_ context.Context, limit, skip *int, sortOrder *types.SortOrder) ([]types.UTXOReference, error) {
	all, err := s.scanSHIP(func(*types.SHIPRecord) bool { return true })
	if err != nil {
		return nil, err
	}
	return paginate(all, limit, skip, sortOrder), nil
}

// EnsureIndexes is a no-op on LevelDB — prefix iteration handles
// filtering for the volumes we expect (low hundreds of advertisements
// per node). The canonical contract requires the method to exist; we
// satisfy it without doing index work.
func (s *SHIPStorage) EnsureIndexes(_ context.Context) error { return nil }

// lookupRecord fetches a single SHIPRecord by outpoint. Returns
// (nil, nil) for not-found. Used by the federation advertiser's
// BEEF-empty fallback path: when an output's BEEF isn't in anvilstorage
// (typical post-W-4-B migration state), we still need TopicOrService +
// IdentityKey + Domain to satisfy engine.SyncAdvertisements'
// "already advertised" filter — those fields live in our local SHIP
// record even when on-chain BEEF is absent.
func (s *SHIPStorage) lookupRecord(_ context.Context, txid string, outputIndex int) (*types.SHIPRecord, error) {
	body, err := s.db.Get(shipKey(txid, outputIndex), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("federation: lookup SHIP record: %w", err)
	}
	var rec types.SHIPRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, fmt.Errorf("federation: decode SHIP record: %w", err)
	}
	return &rec, nil
}

// scanSHIP iterates every SHIP record and applies the predicate. Sorted
// ascending by CreatedAt before returning (pagination applies the final
// sort direction).
func (s *SHIPStorage) scanSHIP(pred func(*types.SHIPRecord) bool) ([]*types.SHIPRecord, error) {
	iter := s.db.NewIterator(util.BytesPrefix([]byte(shipRecordPrefix)), nil)
	defer iter.Release()
	var matched []*types.SHIPRecord
	for iter.Next() {
		var rec types.SHIPRecord
		if err := json.Unmarshal(iter.Value(), &rec); err != nil {
			continue
		}
		if pred(&rec) {
			matched = append(matched, &rec)
		}
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("federation: iterate SHIP records: %w", err)
	}
	return matched, nil
}

// SLAPStorage implements slap.StorageInterface, mirroring SHIPStorage
// but for the SLAP record schema (Service instead of Topic field). See
// the canonical slap.StorageInterface in go-overlay-discovery-services
// for the exact contract.
type SLAPStorage struct {
	db *leveldb.DB
}

// NewSLAPStorage constructs a LevelDB-backed SLAP storage adapter.
func NewSLAPStorage(db *leveldb.DB) *SLAPStorage {
	return &SLAPStorage{db: db}
}

func slapKey(txid string, outputIndex int) []byte {
	return []byte(fmt.Sprintf("%s%s:%d", slapRecordPrefix, txid, outputIndex))
}

// StoreSLAPRecord persists a SLAP record.
func (s *SLAPStorage) StoreSLAPRecord(_ context.Context, txid string, outputIndex int, identityKey, domain, service string) error {
	rec := types.SLAPRecord{
		Txid:        txid,
		OutputIndex: outputIndex,
		IdentityKey: identityKey,
		Domain:      domain,
		Service:     service,
		CreatedAt:   clock(),
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("federation: marshal SLAP record: %w", err)
	}
	if err := s.db.Put(slapKey(txid, outputIndex), body, nil); err != nil {
		return fmt.Errorf("federation: store SLAP record: %w", err)
	}
	return nil
}

// DeleteSLAPRecord removes a SLAP record on UTXO spend.
func (s *SLAPStorage) DeleteSLAPRecord(_ context.Context, txid string, outputIndex int) error {
	if err := s.db.Delete(slapKey(txid, outputIndex), nil); err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("federation: delete SLAP record: %w", err)
	}
	return nil
}

// FindRecord returns UTXOReferences matching the SLAP query filters.
func (s *SLAPStorage) FindRecord(_ context.Context, query types.SLAPQuery) ([]types.UTXOReference, error) {
	matched, err := s.scanSLAP(func(rec *types.SLAPRecord) bool {
		if query.Domain != nil && rec.Domain != *query.Domain {
			return false
		}
		if query.Service != nil && rec.Service != *query.Service {
			return false
		}
		if query.IdentityKey != nil && rec.IdentityKey != *query.IdentityKey {
			return false
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	return paginateSLAP(matched, query.Limit, query.Skip, query.SortOrder), nil
}

// FindAll returns every SLAP record's outpoint.
func (s *SLAPStorage) FindAll(_ context.Context, limit, skip *int, sortOrder *types.SortOrder) ([]types.UTXOReference, error) {
	all, err := s.scanSLAP(func(*types.SLAPRecord) bool { return true })
	if err != nil {
		return nil, err
	}
	return paginateSLAP(all, limit, skip, sortOrder), nil
}

// EnsureIndexes is a no-op on LevelDB.
func (s *SLAPStorage) EnsureIndexes(_ context.Context) error { return nil }

// lookupRecord mirrors SHIPStorage.lookupRecord for SLAP records.
// Used by the federation advertiser's BEEF-empty fallback path.
func (s *SLAPStorage) lookupRecord(_ context.Context, txid string, outputIndex int) (*types.SLAPRecord, error) {
	body, err := s.db.Get(slapKey(txid, outputIndex), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("federation: lookup SLAP record: %w", err)
	}
	var rec types.SLAPRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, fmt.Errorf("federation: decode SLAP record: %w", err)
	}
	return &rec, nil
}

func (s *SLAPStorage) scanSLAP(pred func(*types.SLAPRecord) bool) ([]*types.SLAPRecord, error) {
	iter := s.db.NewIterator(util.BytesPrefix([]byte(slapRecordPrefix)), nil)
	defer iter.Release()
	var matched []*types.SLAPRecord
	for iter.Next() {
		var rec types.SLAPRecord
		if err := json.Unmarshal(iter.Value(), &rec); err != nil {
			continue
		}
		if pred(&rec) {
			matched = append(matched, &rec)
		}
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("federation: iterate SLAP records: %w", err)
	}
	return matched, nil
}

// Helpers — shared between SHIP + SLAP storage.

// contains is a small string-slice membership helper. Inlined here
// rather than imported from slices.Contains so we don't bind to a
// Go-version-specific API surface.
func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// paginate slices a matched-record list per the canonical
// limit/skip/sortOrder semantics and returns the UTXO refs.
//
// Sort contract (matches canonical MongoDB backend in
// go-overlay-discovery-services/pkg/shared/storage.go:24-31):
//   - Default (sortOrder == nil): descending by CreatedAt (newest first)
//   - SortOrderDesc explicit:     same as default
//   - SortOrderAsc explicit:      ascending by CreatedAt (oldest first)
//
// Tie-breaker on identical CreatedAt: outpoint string (txid:vout)
// ascending. Keeps results deterministic when multiple records land in
// the same timestamp bucket (common in tests + fast-admit bursts).
//
// Codex review 6daa58cb1a6f43e4 caught the original implementation
// just reversing LevelDB key order without ever sorting by CreatedAt,
// which diverged silently from the canonical contract.
func paginate(records []*types.SHIPRecord, limit, skip *int, sortOrder *types.SortOrder) []types.UTXOReference {
	asc := sortOrder != nil && *sortOrder == types.SortOrderAsc
	sort.SliceStable(records, func(i, j int) bool {
		if !records[i].CreatedAt.Equal(records[j].CreatedAt) {
			if asc {
				return records[i].CreatedAt.Before(records[j].CreatedAt)
			}
			return records[i].CreatedAt.After(records[j].CreatedAt)
		}
		return shipOutpoint(records[i]) < shipOutpoint(records[j])
	})
	start := 0
	if skip != nil && *skip > 0 {
		start = *skip
		if start > len(records) {
			start = len(records)
		}
	}
	end := len(records)
	if limit != nil && *limit > 0 && start+*limit < end {
		end = start + *limit
	}
	out := make([]types.UTXOReference, 0, end-start)
	for _, r := range records[start:end] {
		out = append(out, types.UTXOReference{Txid: r.Txid, OutputIndex: r.OutputIndex})
	}
	return out
}

// paginateSLAP mirrors paginate for SLAP records. Same canonical sort
// contract: default descending CreatedAt, opt-in ascending, outpoint
// tie-breaker.
func paginateSLAP(records []*types.SLAPRecord, limit, skip *int, sortOrder *types.SortOrder) []types.UTXOReference {
	asc := sortOrder != nil && *sortOrder == types.SortOrderAsc
	sort.SliceStable(records, func(i, j int) bool {
		if !records[i].CreatedAt.Equal(records[j].CreatedAt) {
			if asc {
				return records[i].CreatedAt.Before(records[j].CreatedAt)
			}
			return records[i].CreatedAt.After(records[j].CreatedAt)
		}
		return slapOutpoint(records[i]) < slapOutpoint(records[j])
	})
	start := 0
	if skip != nil && *skip > 0 {
		start = *skip
		if start > len(records) {
			start = len(records)
		}
	}
	end := len(records)
	if limit != nil && *limit > 0 && start+*limit < end {
		end = start + *limit
	}
	out := make([]types.UTXOReference, 0, end-start)
	for _, r := range records[start:end] {
		out = append(out, types.UTXOReference{Txid: r.Txid, OutputIndex: r.OutputIndex})
	}
	return out
}

// shipOutpoint + slapOutpoint produce a deterministic tie-breaker key
// for records with identical CreatedAt timestamps.
func shipOutpoint(r *types.SHIPRecord) string {
	return fmt.Sprintf("%s:%d", r.Txid, r.OutputIndex)
}

func slapOutpoint(r *types.SLAPRecord) string {
	return fmt.Sprintf("%s:%d", r.Txid, r.OutputIndex)
}

// clock is overridable for tests. Kept as a package-level var so test
// files can pin time to a deterministic value before exercising the
// adapter's CreatedAt field.
var clock = func() time.Time { return time.Now().UTC() }
