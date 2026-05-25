package lookups

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// nowUnixNano returns the current time in Unix nanoseconds. Package-
// level indirection (mirrors nowUnix in uhrp.go) so tests can pin time
// when ordering matters. Used by lookups that need sub-second
// resolution for "most-recent first" semantics — typically high-rate
// admission topics where two records can land in the same second.
var nowUnixNano = func() int64 { return time.Now().UnixNano() }

// itemKey assembles a per-output local-index key under a sub-prefix.
// Layout: <prefix><txid-hex>:<vout-decimal>. All lookups under this
// package share the same per-output key shape — only the prefix changes
// per service.
func itemKey(prefix string, txid *chainhash.Hash, vout uint32) []byte {
	return []byte(prefix + txid.String() + ":" + strconv.FormatUint(uint64(vout), 10))
}

// decodeItemKeyOutpoint parses a per-output key produced by itemKey,
// returning the encoded outpoint or false if the key shape is malformed.
func decodeItemKeyOutpoint(key []byte, prefix string) (*transaction.Outpoint, bool) {
	s := string(key)
	if !strings.HasPrefix(s, prefix) {
		return nil, false
	}
	rest := s[len(prefix):]
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

// loadFocusTx pulls the focus transaction out of an atomic-BEEF blob.
// All Anvil lookups use this entry-point to materialise the admitted
// output's script + tx-side context.
func loadFocusTx(atomicBEEF []byte) (*transaction.Transaction, *chainhash.Hash, error) {
	beef, focusTxid, err := transaction.NewBeefFromAtomicBytes(atomicBEEF)
	if err != nil {
		return nil, nil, fmt.Errorf("parse atomic beef: %w", err)
	}
	if focusTxid == nil {
		return nil, nil, errors.New("atomic beef yielded nil focus txid")
	}
	tx := beef.FindTransactionByHash(focusTxid)
	if tx == nil {
		return nil, nil, fmt.Errorf("focus tx %s not in beef", focusTxid.String())
	}
	return tx, focusTxid, nil
}

// deleteItem removes a single per-output index entry. Idempotent: a
// missing key is not an error. Returns true when something was actually
// deleted so callers that want to GC sidecar indexes can skip the work
// otherwise.
func deleteItem(db *leveldb.DB, key []byte) (bool, error) {
	if _, err := db.Get(key, nil); err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	if err := db.Delete(key, nil); err != nil {
		return false, err
	}
	return true, nil
}

// scanPrefix collects every key matching prefix and feeds them to fn.
// The slice returned from fn determines whether iteration continues:
// returning a non-nil error stops the scan and propagates the error.
func scanPrefix(db *leveldb.DB, prefix []byte, fn func(key, value []byte) error) error {
	iter := db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()
	for iter.Next() {
		if err := fn(iter.Key(), iter.Value()); err != nil {
			return err
		}
	}
	return iter.Error()
}

// formulaList builds a LookupAnswer with Type=AnswerTypeFormula from a
// slice of outpoints — the canonical pattern for "return references and
// let the engine hydrate BEEF via Storage."
func formulaList(outpoints []*transaction.Outpoint) *lookup.LookupAnswer {
	formulas := make([]lookup.LookupFormula, 0, len(outpoints))
	for _, op := range outpoints {
		if op == nil {
			continue
		}
		formulas = append(formulas, lookup.LookupFormula{Outpoint: op})
	}
	return &lookup.LookupAnswer{
		Type:     lookup.AnswerTypeFormula,
		Formulas: formulas,
	}
}

// jsonUnmarshalQuery is a tiny convenience used by every lookup's Lookup
// method: tolerate empty query bodies, but fail loudly on malformed JSON.
func jsonUnmarshalQuery(raw []byte, dst interface{}) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("invalid query: %w", err)
	}
	return nil
}

// applyPagination clamps limit + offset to safe bounds for an already-
// sorted slice and returns the window. Callers use this AFTER sorting so
// the page is taken from the desired order.
func applyPagination[T any](items []T, limit, offset, defaultLimit, maxLimit int) []T {
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= len(items) {
		return nil
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}
