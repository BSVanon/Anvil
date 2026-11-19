package lookups

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// errUHRPCorruptRecord marks an item that failed to JSON-decode — data
// already written to the index that is no longer valid uhrpItem JSON.
// itemsByHash and allItemRecords both treat this identically: skip the
// single record and log a warning, never fail the whole scan over one bad
// entry (fix pass, cold review B3 — mirrors storage.go's
// safeNewBeefFromBytes skip-and-log treatment of an unparseable BEEF
// blob). A genuine LevelDB read error is a different, infrastructural
// failure and still propagates as-is.
var errUHRPCorruptRecord = errors.New("uhrp lookup: corrupt record")

// This file holds the UHRP lookup's read path: loading and filtering the
// local index into the result sets Lookup (uhrp.go) returns. Split out of
// uhrp.go, which was growing past this package's established per-file size
// (every sibling lookup service stays under ~460 lines); this file and
// uhrp.go together replace what was one file, with no behavior change.

// uhrpItemRecord pairs a decoded uhrpItem with the outpoint it was stored
// under — the shape every result-building path needs once results must be
// filtered (expiry, legacy/BRC-26 dedup) before formulas are built, not
// just streamed straight from an index scan.
type uhrpItemRecord struct {
	uhrpItem
	outpoint *transaction.Outpoint
}

// uhrpExpired reports whether a BRC-26 item's absolute Unix-seconds expiry
// has passed. Legacy items (BRC26 false) and BRC-26 items with no expiry
// recorded (zero — should not happen post-admission, but defensive) are
// never considered expired here.
func uhrpExpired(it uhrpItem, now int64) bool {
	return it.BRC26 && it.Expiry != 0 && it.Expiry < now
}

// uhrpQueryFilter is the optional AND-filter canonical
// UHRPLookupService.ts applies on top of whatever base set (by-hash or
// list-all) a query selects: HostIdentityKey and ExpiryTime each narrow
// the result when supplied, the same way Mongo's implicit multi-field
// exact match (`records.find(query)`) would. The zero value matches
// everything (fix pass, cold review RISKS / spec item 5).
//
// expiryTime == 0 means "not supplied," matching UHRPLookupQuery's wire
// contract (topics/uhrp_lookup.go): a stored advertisement's expiry is
// always >= 1 (admission enforces it), so a query can never legitimately
// mean "find expiryTime exactly 0."
type uhrpQueryFilter struct {
	hostIdentityKey string
	expiryTime      int64
}

// active reports whether this filter has anything to apply — used by
// Lookup (uhrp.go) to decide whether hostIdentityKey/expiryTime supplied
// with no hash and no list should trigger a full scan the way List:"all"
// does.
func (f uhrpQueryFilter) active() bool {
	return f.hostIdentityKey != "" || f.expiryTime != 0
}

// matches reports whether a record satisfies every field this filter has
// set. The zero value (no fields set) matches every record.
func (f uhrpQueryFilter) matches(it uhrpItem) bool {
	if f.hostIdentityKey != "" && !strings.EqualFold(it.IdentityKey, f.hostIdentityKey) {
		return false
	}
	if f.expiryTime != 0 && it.Expiry != f.expiryTime {
		return false
	}
	return true
}

// filterUHRPRecords applies the cross-cutting UHRP display rules to a
// candidate result set, in place of the engine's raw index contents:
//
//  1. Skip an expired BRC-26 advert. Canonical semantics per
//     ts-sdk storage/StorageDownloader.ts, which skips a decoded result
//     once `expiryTime < currentTime` — the same strict less-than.
//  2. Hide a legacy entry when a BRC-26 advert exists for the same
//     (content hash, URL) pair, so a superseded legacy advertisement
//     stops shadowing its canonical replacement. (Not reached when
//     canonicalOnly already dropped every legacy entry — rule 3.)
//  3. (Fix pass, cold review B1 / spec item 1) When canonicalOnly is
//     set — the uhrpUrl query path only, never content_hash or list —
//     drop every legacy (non-BRC26) record outright, not just ones a
//     BRC-26 advert happens to supersede. A canonical @bsv/sdk
//     StorageDownloader client resolving by uhrpUrl PushDrop-decodes
//     every returned output with no try/catch
//     (storage/StorageDownloader.ts, resolve()); a legacy OP_RETURN
//     record isn't PushDrop-shaped at all and would make that decode
//     throw.
//  4. (Fix pass, cold review RISKS / spec item 5) Apply extra as an
//     AND-filter (hostIdentityKey / expiryTime), matching canonical
//     UHRPLookupService.ts's `records.find(query)` Mongo-style
//     multi-field exact match.
//
// Divergence: canonical's reference ls_uhrp (UHRPLookupService.ts) does
// none of rules 1-2 server-side for its content_hash path — rule 1 is
// left to each resolving client (StorageDownloader.resolve), and rule 2
// has no canonical equivalent at all (legacy OP_RETURN adverts are an
// Anvil-only compatibility format). Filtering server-side here is an
// Anvil choice: it keeps a request for "resolve this URL" from
// describing dead or shadowed hosts, in addition to whatever filtering a
// canonical client already does itself. Rule 3, by contrast, IS load-
// bearing for canonical correctness, not just a convenience — a BRC-26
// client literally cannot decode what rule 3 holds back.
func filterUHRPRecords(recs []uhrpItemRecord, now int64, canonicalOnly bool, extra uhrpQueryFilter) []uhrpItemRecord {
	dupKey := func(it uhrpItem) string { return it.ContentHash + "\x00" + it.URL }
	brc26Keys := make(map[string]struct{}, len(recs))
	for _, r := range recs {
		if !extra.matches(r.uhrpItem) {
			continue
		}
		if r.BRC26 && !uhrpExpired(r.uhrpItem, now) {
			brc26Keys[dupKey(r.uhrpItem)] = struct{}{}
		}
	}
	out := make([]uhrpItemRecord, 0, len(recs))
	for _, r := range recs {
		if !extra.matches(r.uhrpItem) {
			continue
		}
		if r.BRC26 {
			if uhrpExpired(r.uhrpItem, now) {
				continue
			}
			out = append(out, r)
			continue
		}
		if canonicalOnly {
			continue
		}
		if _, superseded := brc26Keys[dupKey(r.uhrpItem)]; superseded {
			continue
		}
		out = append(out, r)
	}
	return out
}

// formulasFromRecords builds the canonical formula-answer shape from a
// (already filtered) set of records.
func formulasFromRecords(recs []uhrpItemRecord) []lookup.LookupFormula {
	formulas := make([]lookup.LookupFormula, 0, len(recs))
	for _, r := range recs {
		formulas = append(formulas, lookup.LookupFormula{Outpoint: r.outpoint})
	}
	return formulas
}

// scanByHash returns formulas for every outpoint indexed under the given
// content hash, after applying filterUHRPRecords. canonicalOnly (fix
// pass, cold review B1) is set by the one caller — the uhrpUrl query
// path — that needs BRC-26-only answers; a direct content_hash query
// passes false and keeps seeing both formats.
func (s *UHRPLookupService) scanByHash(hashHex string, canonicalOnly bool, extra uhrpQueryFilter) ([]lookup.LookupFormula, error) {
	recs, err := s.itemsByHash(hashHex)
	if err != nil {
		return nil, err
	}
	return formulasFromRecords(filterUHRPRecords(recs, nowUnix(), canonicalOnly, extra)), nil
}

// itemsByHash loads the full record (not just the outpoint) for every
// entry indexed under the given content hash, so callers can apply
// filterUHRPRecords before deciding what to return.
func (s *UHRPLookupService) itemsByHash(hashHex string) ([]uhrpItemRecord, error) {
	prefix := []byte(uhrpHashPrefix + hashHex + ":")
	iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()
	var recs []uhrpItemRecord
	for iter.Next() {
		op, ok := decodeHashIndexKey(iter.Key(), len(prefix))
		if !ok {
			continue
		}
		item, ok, err := s.loadItem(op)
		if err != nil {
			if errors.Is(err, errUHRPCorruptRecord) {
				// Fix pass, cold review B3: one corrupt record must not
				// fail the whole hash scan.
				slog.Warn("uhrp lookup: skipping corrupt record in hash scan",
					"txid", op.Txid.String(), "vout", op.Index, "error", err)
				continue
			}
			return nil, err
		}
		if !ok {
			continue // hash-index entry with no item body — defensive, shouldn't happen
		}
		recs = append(recs, uhrpItemRecord{uhrpItem: item, outpoint: op})
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("uhrp lookup: iterate hash index: %w", err)
	}
	return recs, nil
}

// loadItem reads and decodes one item record by its outpoint.
func (s *UHRPLookupService) loadItem(op *transaction.Outpoint) (uhrpItem, bool, error) {
	body, err := s.db.Get(uhrpItemKey(&op.Txid, op.Index), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return uhrpItem{}, false, nil
		}
		return uhrpItem{}, false, fmt.Errorf("uhrp lookup: read item: %w", err)
	}
	var item uhrpItem
	if err := json.Unmarshal(body, &item); err != nil {
		return uhrpItem{}, false, fmt.Errorf("uhrp lookup: decode item: %w: %w", errUHRPCorruptRecord, err)
	}
	return item, true, nil
}

// allItemRecords loads every item in the local index, decoded. Shared by
// scanAllItems and countByHash so both apply the identical filter.
func (s *UHRPLookupService) allItemRecords() ([]uhrpItemRecord, error) {
	prefix := []byte(uhrpItemPrefix)
	iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()
	var recs []uhrpItemRecord
	for iter.Next() {
		op, ok := decodeItemKey(iter.Key())
		if !ok {
			continue
		}
		var item uhrpItem
		if err := json.Unmarshal(iter.Value(), &item); err != nil {
			// Fix pass, cold review B3: same skip-and-log treatment as
			// itemsByHash's errUHRPCorruptRecord path above — never fail
			// the whole list scan over one bad entry.
			slog.Warn("uhrp lookup: skipping corrupt record in list scan",
				"key", string(iter.Key()), "error", err)
			continue
		}
		recs = append(recs, uhrpItemRecord{uhrpItem: item, outpoint: op})
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("uhrp lookup: iterate items: %w", err)
	}
	return recs, nil
}

// scanAllItems returns one formula per surviving item in the local index,
// after applying filterUHRPRecords. extra (fix pass, spec item 5)
// AND-combines hostIdentityKey/expiryTime into this base set, matching
// canonical UHRPLookupService.ts's query semantics; the zero value
// matches everything.
func (s *UHRPLookupService) scanAllItems(extra uhrpQueryFilter) ([]lookup.LookupFormula, error) {
	recs, err := s.allItemRecords()
	if err != nil {
		return nil, err
	}
	return formulasFromRecords(filterUHRPRecords(recs, nowUnix(), false, extra)), nil
}

// countByHash returns a hash→count map computed over the surviving items
// (after filterUHRPRecords and extra), so an expired, superseded-legacy,
// or filtered-out advert doesn't inflate a hash's reported host count.
func (s *UHRPLookupService) countByHash(extra uhrpQueryFilter) (map[string]int, error) {
	recs, err := s.allItemRecords()
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int)
	for _, r := range filterUHRPRecords(recs, nowUnix(), false, extra) {
		counts[r.ContentHash]++
	}
	return counts, nil
}

// decodeItemKey parses a uhrpItemPrefix key back into its outpoint.
func decodeItemKey(key []byte) (*transaction.Outpoint, bool) {
	s := string(key)
	if !strings.HasPrefix(s, uhrpItemPrefix) {
		return nil, false
	}
	rest := s[len(uhrpItemPrefix):]
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

// decodeHashIndexKey parses a uhrpHashPrefix key's suffix (after the
// already-known prefix + hash) back into its outpoint.
func decodeHashIndexKey(key []byte, prefixLen int) (*transaction.Outpoint, bool) {
	if len(key) <= prefixLen {
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
