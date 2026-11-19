package lookups

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

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

// filterUHRPRecords applies the two cross-cutting UHRP display rules to a
// candidate result set, in place of the engine's raw index contents:
//
//  1. Skip an expired BRC-26 advert. Canonical semantics per
//     ts-sdk storage/StorageDownloader.ts, which skips a decoded result
//     once `expiryTime < currentTime` — the same strict less-than.
//  2. Hide a legacy entry when a BRC-26 advert exists for the same
//     (content hash, URL) pair, so a superseded legacy advertisement
//     stops shadowing its canonical replacement.
//
// Divergence: canonical's reference ls_uhrp (UHRPLookupService.ts) does
// neither of these server-side — rule 1 is left to each resolving client
// (StorageDownloader.resolve), and rule 2 has no canonical equivalent at
// all (legacy OP_RETURN adverts are an Anvil-only compatibility format).
// Filtering server-side here is an Anvil choice: it keeps a request for
// "resolve this URL" from describing dead or shadowed hosts, in addition
// to whatever filtering a canonical client already does itself.
func filterUHRPRecords(recs []uhrpItemRecord, now int64) []uhrpItemRecord {
	dupKey := func(it uhrpItem) string { return it.ContentHash + "\x00" + it.URL }
	brc26Keys := make(map[string]struct{}, len(recs))
	for _, r := range recs {
		if r.BRC26 && !uhrpExpired(r.uhrpItem, now) {
			brc26Keys[dupKey(r.uhrpItem)] = struct{}{}
		}
	}
	out := make([]uhrpItemRecord, 0, len(recs))
	for _, r := range recs {
		if r.BRC26 {
			if uhrpExpired(r.uhrpItem, now) {
				continue
			}
			out = append(out, r)
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
// content hash, after applying filterUHRPRecords.
func (s *UHRPLookupService) scanByHash(hashHex string) ([]lookup.LookupFormula, error) {
	recs, err := s.itemsByHash(hashHex)
	if err != nil {
		return nil, err
	}
	return formulasFromRecords(filterUHRPRecords(recs, nowUnix())), nil
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
		return uhrpItem{}, false, fmt.Errorf("uhrp lookup: decode item: %w", err)
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
			continue // corrupt record — skip defensively
		}
		recs = append(recs, uhrpItemRecord{uhrpItem: item, outpoint: op})
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("uhrp lookup: iterate items: %w", err)
	}
	return recs, nil
}

// scanAllItems returns one formula per surviving item in the local index,
// after applying filterUHRPRecords.
func (s *UHRPLookupService) scanAllItems() ([]lookup.LookupFormula, error) {
	recs, err := s.allItemRecords()
	if err != nil {
		return nil, err
	}
	return formulasFromRecords(filterUHRPRecords(recs, nowUnix())), nil
}

// countByHash returns a hash→count map computed over the surviving items
// (after filterUHRPRecords), so an expired or superseded-legacy advert
// doesn't inflate a hash's reported host count.
func (s *UHRPLookupService) countByHash() (map[string]int, error) {
	recs, err := s.allItemRecords()
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int)
	for _, r := range filterUHRPRecords(recs, nowUnix()) {
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
