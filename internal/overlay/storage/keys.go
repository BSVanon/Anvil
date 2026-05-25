// Package storage is the LevelDB-backed implementation of the
// go-overlay-services engine.Storage interface for Anvil v3.
//
// W-4 phase A (2026-05-13): schema + primitives only. The engine is not yet
// wired to this package — that happens in W-5. Existing Anvil overlay storage
// (internal/overlay/engine.go's "ovl:" family) is left untouched; this package
// uses its own non-overlapping key prefixes so both can coexist during the
// transition.
package storage

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Key families. Each prefix is unique, ASCII, and terminated by ':' so prefix
// scans never accidentally cross families.
//
//	ovl3:<topic>:<txid-hex>:<vout>                              record JSON
//	txi3:<txid-hex>:<topic>:<vout>                              empty sentinel
//	topi3:<topic>:<score-hex16>:<txid-hex>:<vout>               empty sentinel (unspent only)
//	mst3:<topic>:<state>:<txid-hex>:<vout>                      empty sentinel
//	beef3:<txid-hex>                                            BEEF bytes
//	anci3:<txid-hex>                                            concatenated 32-byte ancillary hashes
//	txco3:<txid-hex>                                            concatenated 36-byte consumed outpoints
//	cons3:<topic>:<txid-hex>:<vout>:<ctxid-hex>:<cvout>         empty sentinel
//	appl3:<topic>:<txid-hex>                                    empty sentinel
//	peer3:<host>:<topic>                                        8-byte BE float64
//
// The "3" suffix distinguishes from the legacy v2 "ovl:" family used by
// internal/overlay/engine.go so both can share a single LevelDB during W-5
// dual-run. Phase B migration (later) will copy v2 → v3 then remove v2.
const (
	prefixOutput      = "ovl3:"
	prefixTxidIndex   = "txi3:"
	prefixTopicIndex  = "topi3:"
	prefixMerkleIndex = "mst3:"
	prefixBEEF        = "beef3:"
	prefixAncillary   = "anci3:"
	prefixTxConsumed  = "txco3:"
	prefixConsumer    = "cons3:"
	prefixApplied     = "appl3:"
	prefixPeer        = "peer3:"
)

// outputKey returns the primary record key for a given (topic, outpoint).
func outputKey(topic string, op *transaction.Outpoint) []byte {
	return []byte(prefixOutput + topic + ":" + op.Txid.String() + ":" + strconv.FormatUint(uint64(op.Index), 10))
}

// txidIndexKey returns the txid → (topic, vout) reverse-index sentinel key.
func txidIndexKey(txid *chainhash.Hash, topic string, vout uint32) []byte {
	return []byte(prefixTxidIndex + txid.String() + ":" + topic + ":" + strconv.FormatUint(uint64(vout), 10))
}

// txidIndexPrefix returns the prefix used to scan all outputs for a txid
// across all topics.
func txidIndexPrefix(txid *chainhash.Hash) []byte {
	return []byte(prefixTxidIndex + txid.String() + ":")
}

// parseTxidIndexKey decodes a txi3 sentinel key into (topic, vout). The
// caller already knows the txid because they used it to build the scan
// prefix.
func parseTxidIndexKey(key []byte, txidPrefix string) (topic string, vout uint32, ok bool) {
	s := string(key)
	if !strings.HasPrefix(s, txidPrefix) {
		return "", 0, false
	}
	rest := s[len(txidPrefix):]
	idx := strings.LastIndexByte(rest, ':')
	if idx <= 0 {
		return "", 0, false
	}
	topic = rest[:idx]
	n, err := strconv.ParseUint(rest[idx+1:], 10, 32)
	if err != nil {
		return "", 0, false
	}
	return topic, uint32(n), true
}

// topicIndexKey returns the (topic, since-score) ordered index key. The score
// is encoded as 16-char big-endian hex of its IEEE-754 bit pattern so that
// non-negative scores sort lexicographically the same way they sort
// numerically (good enough for Unix-epoch admission timestamps, which is all
// we store).
func topicIndexKey(topic string, score float64, op *transaction.Outpoint) []byte {
	return []byte(prefixTopicIndex + topic + ":" + encodeScore(score) + ":" + op.Txid.String() + ":" + strconv.FormatUint(uint64(op.Index), 10))
}

// topicIndexLowerBound returns the prefix at which a "since"-filtered scan
// should begin (inclusive).
func topicIndexLowerBound(topic string, sinceScore float64) []byte {
	return []byte(prefixTopicIndex + topic + ":" + encodeScore(sinceScore))
}

// topicIndexUpperBound returns the exclusive upper bound for a topic scan.
func topicIndexUpperBound(topic string) []byte {
	// ":" is 0x3A; using a single byte one above ':' (";", 0x3B) gives a
	// strict upper bound for any value in this topic.
	return []byte(prefixTopicIndex + topic + ";")
}

// parseTopicIndexKey decodes a topi3 sentinel key into (txid, vout). Used by
// FindUTXOsForTopic to recover the outpoint without parsing the score back.
func parseTopicIndexKey(key []byte) (txid string, vout uint32, ok bool) {
	s := string(key)
	if !strings.HasPrefix(s, prefixTopicIndex) {
		return "", 0, false
	}
	// trim the prefix and split from the right: txid is fixed 64 chars, vout
	// follows after a ':'.
	rest := s[len(prefixTopicIndex):]
	vIdx := strings.LastIndexByte(rest, ':')
	if vIdx <= 64 {
		return "", 0, false
	}
	txid = rest[vIdx-64 : vIdx]
	if len(txid) != 64 {
		return "", 0, false
	}
	n, err := strconv.ParseUint(rest[vIdx+1:], 10, 32)
	if err != nil {
		return "", 0, false
	}
	return txid, uint32(n), true
}

// merkleIndexKey returns the (topic, state, outpoint) sentinel key.
func merkleIndexKey(topic string, state uint8, op *transaction.Outpoint) []byte {
	return []byte(prefixMerkleIndex + topic + ":" + strconv.FormatUint(uint64(state), 10) + ":" + op.Txid.String() + ":" + strconv.FormatUint(uint64(op.Index), 10))
}

// merkleIndexPrefix returns the prefix scanned for FindOutpointsByMerkleState.
func merkleIndexPrefix(topic string, state uint8) []byte {
	return []byte(prefixMerkleIndex + topic + ":" + strconv.FormatUint(uint64(state), 10) + ":")
}

// parseMerkleIndexKey decodes (txid, vout) from a mst3 sentinel.
func parseMerkleIndexKey(key, prefix []byte) (txid string, vout uint32, ok bool) {
	s := string(key)
	p := string(prefix)
	if !strings.HasPrefix(s, p) {
		return "", 0, false
	}
	rest := s[len(p):]
	idx := strings.LastIndexByte(rest, ':')
	if idx != 64 {
		return "", 0, false
	}
	txid = rest[:64]
	n, err := strconv.ParseUint(rest[idx+1:], 10, 32)
	if err != nil {
		return "", 0, false
	}
	return txid, uint32(n), true
}

// beefKey returns the BEEF bytes key for a transaction.
func beefKey(txid *chainhash.Hash) []byte {
	return []byte(prefixBEEF + txid.String())
}

// ancillaryKey returns the ancillary-txids key for a transaction.
func ancillaryKey(txid *chainhash.Hash) []byte {
	return []byte(prefixAncillary + txid.String())
}

// txConsumedKey returns the per-tx consumed-outpoints key.
func txConsumedKey(txid *chainhash.Hash) []byte {
	return []byte(prefixTxConsumed + txid.String())
}

// consumerKey returns the per-output consumer sentinel key.
func consumerKey(topic string, op, consumer *transaction.Outpoint) []byte {
	return []byte(prefixConsumer + topic + ":" + op.Txid.String() + ":" + strconv.FormatUint(uint64(op.Index), 10) + ":" + consumer.Txid.String() + ":" + strconv.FormatUint(uint64(consumer.Index), 10))
}

// consumerPrefix returns the prefix used to scan the consumers of an output.
func consumerPrefix(topic string, op *transaction.Outpoint) []byte {
	return []byte(prefixConsumer + topic + ":" + op.Txid.String() + ":" + strconv.FormatUint(uint64(op.Index), 10) + ":")
}

// parseConsumerKey decodes (consumer-txid, consumer-vout) from a cons3
// sentinel. Caller knows the outer prefix.
func parseConsumerKey(key, prefix []byte) (*transaction.Outpoint, bool) {
	if len(key) <= len(prefix) {
		return nil, false
	}
	rest := string(key[len(prefix):])
	idx := strings.LastIndexByte(rest, ':')
	if idx != 64 {
		return nil, false
	}
	hash, err := chainhash.NewHashFromHex(rest[:64])
	if err != nil {
		return nil, false
	}
	n, err := strconv.ParseUint(rest[idx+1:], 10, 32)
	if err != nil {
		return nil, false
	}
	return &transaction.Outpoint{Txid: *hash, Index: uint32(n)}, true
}

// appliedKey returns the applied-transaction dedup sentinel key.
func appliedKey(topic string, txid *chainhash.Hash) []byte {
	return []byte(prefixApplied + topic + ":" + txid.String())
}

// peerKey returns the peer interaction key.
func peerKey(host, topic string) []byte {
	return []byte(prefixPeer + host + ":" + topic)
}

// encodeScore renders a float64 as 16-char hex of its IEEE-754 big-endian
// bit pattern. For non-negative scores (which is all we use — Unix epoch
// timestamps) the lexicographic ordering matches the numeric ordering.
func encodeScore(score float64) string {
	bits := math.Float64bits(score)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], bits)
	return hex.EncodeToString(buf[:])
}

// outpointFromHex builds an Outpoint from a 64-char hex txid + uint32 vout.
// Used in test helpers and key parsing.
func outpointFromHex(txidHex string, vout uint32) (*transaction.Outpoint, error) {
	if len(txidHex) != 64 {
		return nil, fmt.Errorf("storage: invalid txid hex length %d", len(txidHex))
	}
	h, err := chainhash.NewHashFromHex(txidHex)
	if err != nil {
		return nil, fmt.Errorf("storage: invalid txid hex: %w", err)
	}
	return &transaction.Outpoint{Txid: *h, Index: vout}, nil
}
