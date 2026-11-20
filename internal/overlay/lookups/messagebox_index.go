package lookups

// The LevelDB index-key scheme behind MessageBoxLookupService (messagebox.go):
// encoding/decoding the <mbIDPrefix><identityKeyLower>:<invertedTime>:<txid>:
// <vout> key, and the scans built on it (currentRecords, CurrentHosts) plus
// the removal path (removeOutpoint) that keeps the index in step with the
// primary record.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// errMBScanLimitReached is returned by currentRecords' scanPrefix
// callback to stop the scan once limit hits are collected. It is
// not a real error — scanPrefix propagates whatever the callback
// returns, and currentRecords recognises this sentinel and swallows it.
var errMBScanLimitReached = errors.New("messagebox lookup: scan limit reached")

// invertedTimeKey renders admittedAt as a fixed-width string such that
// lexicographic (byte) order on the rendered string is descending
// chronological order on admittedAt.
func invertedTimeKey(admittedAt int64) string {
	return fmt.Sprintf("%0*d", mbInvertedTimeWidth, math.MaxInt64-admittedAt)
}

type mbHit struct {
	op   *transaction.Outpoint
	host string
}

// currentRecords returns live (unspent, unevicted) adverts for
// identityKeyLower, newest first, decoding at most limit of them (0 =
// unbounded). Newest-first order and the limit both come from the index
// KEY's own lexicographic order (mbIndexKey's inverted-time segment),
// not an in-memory sort: scanPrefix already visits keys in ascending
// byte order, which is descending AdmittedAt order by construction, and
// ties resolve by txid then vout ascending — the index key's own
// trailing bytes — "for free", with nothing left to sort afterwards
// (there is no comparator computing Txid.String() repeatedly,
// because there is no comparator).
func (s *MessageBoxLookupService) currentRecords(identityKeyLower string, limit int) ([]mbHit, error) {
	fullPrefix := []byte(mbIDPrefix + identityKeyLower + ":")
	var hits []mbHit
	err := scanPrefix(s.db, fullPrefix, func(k, _ []byte) error {
		op, ok := decodeMBIndexOutpoint(k, len(fullPrefix))
		if !ok {
			return nil
		}
		body, err := s.db.Get(itemKey(mbItemPrefix, &op.Txid, op.Index), nil)
		if err != nil {
			return nil // index drift — skip
		}
		var rec messageboxRecord
		if err := json.Unmarshal(body, &rec); err != nil {
			return nil
		}
		hits = append(hits, mbHit{op: op, host: rec.Host})
		if limit > 0 && len(hits) >= limit {
			return errMBScanLimitReached
		}
		return nil
	})
	if err != nil && !errors.Is(err, errMBScanLimitReached) {
		return nil, fmt.Errorf("messagebox lookup: scan %s: %w", mbIDPrefix, err)
	}
	return hits, nil
}

// CurrentHosts returns the raw (un-normalised) host string of the
// newest maxCurrentHostsScan live adverts for identityKeyHex,
// deduplicated after normalisation is NOT done here — qualifyAndNormalise
// (internal/messaging/home.go) normalises and HomeResolver.Resolve
// dedupes by comparing normalised forms, since two raw hosts can
// normalise to the same qualifying host (e.g. differing case or a
// trailing slash) and this package has no dependency on
// internal/messaging to do that itself. This is a native Go side-channel
// for messaging.HomeResolver: it reads the same `lk_messagebox:` index
// this service's own Lookup answers from (the LevelDB handle is the
// single source of truth), skipping the BEEF/output-list round trip the
// external ls_messagebox HTTP contract requires — the Home Rule check
// runs on every message send/forward and would otherwise re-fetch and
// re-decode a transaction per call, and without a bound would re-pay
// O(N) Gets and JSON decodes for an identity holding N live adverts on
// every single message. Returns (nil, nil) for an unknown or
// unadvertised identity.
func (s *MessageBoxLookupService) CurrentHosts(identityKeyHex string) ([]string, error) {
	hits, err := s.currentRecords(strings.ToLower(strings.TrimSpace(identityKeyHex)), maxCurrentHostsScan)
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(hits))
	for _, h := range hits {
		hosts = append(hosts, h.host)
	}
	return hosts, nil
}

// removeOutpoint deletes the record + its identityKey index entry.
func (s *MessageBoxLookupService) removeOutpoint(txid *chainhash.Hash, vout uint32) error {
	primary := itemKey(mbItemPrefix, txid, vout)
	body, err := s.db.Get(primary, nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("messagebox lookup: read for remove: %w", err)
	}
	var rec messageboxRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return s.db.Delete(primary, nil)
	}
	batch := new(leveldb.Batch)
	batch.Delete(primary)
	batch.Delete(mbIndexKey(rec.IdentityKey, rec.AdmittedAt, txid, vout))
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("messagebox lookup: delete batch: %w", err)
	}
	return nil
}

// mbIndexKey produces
// <mbIDPrefix><identityKeyLower>:<invertedTime>:<txid>:<vout>. The
// identity key is already hex (fixed alphabet, no ':'), so unlike
// kvstore's free-text keys it needs no extra hex-escaping layer, and the
// inverted-time segment is fixed-width so decodeMBIndexOutpoint can skip
// it unambiguously.
func mbIndexKey(identityKeyLower string, admittedAt int64, txid *chainhash.Hash, vout uint32) []byte {
	return []byte(mbIDPrefix + identityKeyLower + ":" + invertedTimeKey(admittedAt) + ":" + txid.String() + ":" + strconv.FormatUint(uint64(vout), 10))
}

// decodeMBIndexOutpoint extracts the trailing <txid>:<vout> from an index
// key, given the length of the <mbIDPrefix><identityKeyLower>: portion
// (fullPrefixLen does NOT include the inverted-time segment, which this
// function skips by its known fixed width before applying the original
// txid/vout parse).
func decodeMBIndexOutpoint(key []byte, fullPrefixLen int) (*transaction.Outpoint, bool) {
	if len(key) < fullPrefixLen+mbInvertedTimeWidth+1 {
		return nil, false
	}
	rest := string(key[fullPrefixLen+mbInvertedTimeWidth+1:]) // skip "<invertedTime>:"
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
