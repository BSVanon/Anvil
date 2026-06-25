package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// Storage implements engine.Storage backed by a single goleveldb instance.
// Multiple Storage values may share the same *leveldb.DB; the key prefixes
// (see keys.go) keep families disjoint from each other and from the legacy
// "ovl:" v2 family used by internal/overlay/engine.go.
//
// Concurrency contract: per-key atomicity only. LevelDB itself is
// goroutine-safe, and each multi-key write goes through a single
// leveldb.Batch so the primary record and its indexes update together.
// Reads that span multiple key families (FindOutput → record + cons3 +
// anci3 + beef3) are NOT cross-family snapshot-consistent — a concurrent
// writer can produce a mix of pre- and post-update values across the
// families. If a caller needs cross-family consistency it must hold an
// external lock around the access. W-5 wiring should keep this in mind.
type Storage struct {
	db *leveldb.DB

	// clock is overridable in tests; nil ⇒ time.Now.
	clock func() time.Time
}

// New constructs a Storage value wrapping the given LevelDB handle. The
// caller retains ownership of the handle and is responsible for closing it.
func New(db *leveldb.DB) *Storage {
	return &Storage{db: db}
}

// SetClock overrides the time source used to assign Score (admittedAt) on
// InsertOutputs. Test-only.
func (s *Storage) SetClock(fn func() time.Time) { s.clock = fn }

func (s *Storage) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// Compile-time assertion that Storage implements engine.Storage.
var _ engine.Storage = (*Storage)(nil)

// --- output CRUD ------------------------------------------------------------

// InsertOutputs writes the records for a single transaction's admitted
// outputs plus all dependent index entries (txid index, topic-since index,
// merkle-state index), the per-tx BEEF blob, the per-tx consumed-outpoints
// blob, and the per-tx ancillary-txids blob — all in a single atomic
// LevelDB batch.
func (s *Storage) InsertOutputs(
	ctx context.Context,
	topic string,
	txid *chainhash.Hash,
	outputs []uint32,
	outpointsConsumed []*transaction.Outpoint,
	beef *transaction.Beef,
	ancillaryTxids []*chainhash.Hash,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if txid == nil {
		return errors.New("storage: nil txid")
	}

	score := float64(s.now().Unix())
	batch := new(leveldb.Batch)

	// Per-tx BEEF (if provided).
	if beef != nil {
		bb, err := beef.Bytes()
		if err != nil {
			return fmt.Errorf("storage: serialise beef: %w", err)
		}
		batch.Put(beefKey(txid), bb)
	}

	// Per-tx consumed-outpoints blob (ordered concatenation of 36-byte
	// outpoint encodings; empty value when no inputs consumed).
	if len(outpointsConsumed) > 0 {
		buf := make([]byte, 0, 36*len(outpointsConsumed))
		for _, op := range outpointsConsumed {
			if op == nil {
				return errors.New("storage: nil outpoint in outpointsConsumed")
			}
			buf = append(buf, op.Bytes()...)
		}
		batch.Put(txConsumedKey(txid), buf)
	}

	// Per-tx ancillary-txid blob (concatenation of 32-byte hashes).
	if len(ancillaryTxids) > 0 {
		buf := make([]byte, 0, 32*len(ancillaryTxids))
		for _, h := range ancillaryTxids {
			if h == nil {
				return errors.New("storage: nil hash in ancillaryTxids")
			}
			buf = append(buf, h.CloneBytes()...)
		}
		batch.Put(ancillaryKey(txid), buf)
	}

	// One record per admitted output index, plus its indexes.
	for _, vout := range outputs {
		op := &transaction.Outpoint{Txid: *txid, Index: vout}
		rec := &record{
			TxidHex:     txid.String(),
			Index:       vout,
			Topic:       topic,
			Score:       score,
			MerkleState: uint8(engine.MerkleStateUnmined),
		}
		body, err := encodeRecord(rec)
		if err != nil {
			return fmt.Errorf("storage: encode record: %w", err)
		}
		batch.Put(outputKey(topic, op), body)
		batch.Put(txidIndexKey(txid, topic, vout), nil)
		batch.Put(topicIndexKey(topic, score, op), nil)
		batch.Put(merkleIndexKey(topic, uint8(engine.MerkleStateUnmined), op), nil)
	}

	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("storage: write batch: %w", err)
	}
	return nil
}

// FindOutput returns the record for a single outpoint, optionally hydrated
// with BEEF + OutputsConsumed + ConsumedBy. If topic is non-nil the lookup
// is constrained to that topic; otherwise we scan the txid index to find
// the topic that owns this outpoint (BRC-64 callers may not know the topic
// up front).
func (s *Storage) FindOutput(
	ctx context.Context,
	outpoint *transaction.Outpoint,
	topic *string,
	spent *bool,
	includeBEEF bool,
) (*engine.Output, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if outpoint == nil {
		return nil, errors.New("storage: nil outpoint")
	}
	rec, err := s.loadRecord(outpoint, topic)
	if err != nil {
		return nil, err
	}
	if spent != nil && rec.Spent != *spent {
		return nil, engine.ErrNotFound
	}
	out := rec.toEngineOutput()
	if err := s.hydrate(out, includeBEEF); err != nil {
		return nil, err
	}
	return out, nil
}

// FindOutputs is the batch form of FindOutput. The returned slice is
// POSITIONALLY PARALLEL to outpoints: out[i] corresponds to outpoints[i],
// with nil at positions where no record matched the (topic, spent) filter
// or where outpoints[i] itself was nil. This matches the upstream contract
// — engine.mergeExistingOutputs iterates `for vin, output := range outputs`
// and uses the slice index as the real input vin, skipping nil entries.
// Compacting misses out would silently renumber sparse spends.
func (s *Storage) FindOutputs(
	ctx context.Context,
	outpoints []*transaction.Outpoint,
	topic string,
	spent *bool,
	includeBEEF bool,
) ([]*engine.Output, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var t *string
	if topic != "" {
		t = &topic
	}
	out := make([]*engine.Output, len(outpoints))
	for i, op := range outpoints {
		if op == nil {
			continue
		}
		rec, err := s.loadRecord(op, t)
		if err != nil {
			if errors.Is(err, engine.ErrNotFound) {
				continue
			}
			return nil, err
		}
		if spent != nil && rec.Spent != *spent {
			continue
		}
		eo := rec.toEngineOutput()
		if err := s.hydrate(eo, includeBEEF); err != nil {
			return nil, err
		}
		out[i] = eo
	}
	return out, nil
}

// FindOutputsForTransaction returns every (topic, vout) record indexed under
// a given txid. Uses the txi3 index prefix scan.
func (s *Storage) FindOutputsForTransaction(
	ctx context.Context,
	txid *chainhash.Hash,
	includeBEEF bool,
) ([]*engine.Output, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if txid == nil {
		return nil, errors.New("storage: nil txid")
	}
	prefix := txidIndexPrefix(txid)
	iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()

	var out []*engine.Output
	prefixStr := string(prefix)
	for iter.Next() {
		topic, vout, ok := parseTxidIndexKey(iter.Key(), prefixStr)
		if !ok {
			continue
		}
		op := &transaction.Outpoint{Txid: *txid, Index: vout}
		rec, err := s.loadRecord(op, &topic)
		if err != nil {
			if errors.Is(err, engine.ErrNotFound) {
				continue
			}
			return nil, err
		}
		eo := rec.toEngineOutput()
		if err := s.hydrate(eo, includeBEEF); err != nil {
			return nil, err
		}
		out = append(out, eo)
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("storage: iterate txi: %w", err)
	}
	return out, nil
}

// FindUTXOsForTopic returns currently-unspent outputs admitted to a topic
// with admittedAt-score >= since, up to limit (0 = unbounded). Iterates the
// topi3 score-ordered index.
func (s *Storage) FindUTXOsForTopic(
	ctx context.Context,
	topic string,
	since float64,
	limit uint32,
	includeBEEF bool,
) ([]*engine.Output, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lo := topicIndexLowerBound(topic, since)
	hi := topicIndexUpperBound(topic)
	iter := s.db.NewIterator(&util.Range{Start: lo, Limit: hi}, nil)
	defer iter.Release()

	out := make([]*engine.Output, 0)
	var produced uint32
	for iter.Next() {
		if limit > 0 && produced >= limit {
			break
		}
		txidHex, vout, ok := parseTopicIndexKey(iter.Key())
		if !ok {
			continue
		}
		op, err := outpointFromHex(txidHex, vout)
		if err != nil {
			continue
		}
		rec, err := s.loadRecord(op, &topic)
		if err != nil {
			// topi3 should never reference a missing record; treat as
			// data-integrity issue and skip rather than failing the
			// whole scan.
			if errors.Is(err, engine.ErrNotFound) {
				continue
			}
			return nil, err
		}
		if rec.Spent {
			// Defensive: spent records should have had their topi3
			// entry removed by MarkUTXOsAsSpent.
			continue
		}
		eo := rec.toEngineOutput()
		if err := s.hydrate(eo, includeBEEF); err != nil {
			return nil, err
		}
		out = append(out, eo)
		produced++
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("storage: iterate topi: %w", err)
	}
	return out, nil
}

// DeleteOutput removes a single (topic, outpoint) record together with every
// index entry that refers to it. Idempotent: deleting an absent key is a
// no-op.
func (s *Storage) DeleteOutput(
	ctx context.Context,
	outpoint *transaction.Outpoint,
	topic string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if outpoint == nil {
		return errors.New("storage: nil outpoint")
	}

	rec, err := s.loadRecord(outpoint, &topic)
	if err != nil {
		if errors.Is(err, engine.ErrNotFound) {
			return nil
		}
		return err
	}
	batch := new(leveldb.Batch)
	batch.Delete(outputKey(topic, outpoint))
	batch.Delete(txidIndexKey(&outpoint.Txid, topic, outpoint.Index))
	if !rec.Spent {
		batch.Delete(topicIndexKey(topic, rec.Score, outpoint))
	}
	batch.Delete(merkleIndexKey(topic, rec.MerkleState, outpoint))
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("storage: delete batch: %w", err)
	}
	// Also clear this output's consumer index (cons3). Done outside the
	// primary batch because it requires a prefix scan.
	return s.clearConsumers(topic, outpoint)
}

// MarkUTXOsAsSpent flips Spent=true on every named outpoint and removes
// their topi3 entries so future FindUTXOsForTopic scans skip them.
func (s *Storage) MarkUTXOsAsSpent(
	ctx context.Context,
	outpoints []*transaction.Outpoint,
	topic string,
	spendTxid *chainhash.Hash,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, op := range outpoints {
		if op == nil {
			continue
		}
		rec, err := s.loadRecord(op, &topic)
		if err != nil {
			if errors.Is(err, engine.ErrNotFound) {
				continue
			}
			return err
		}
		if rec.Spent {
			continue
		}
		rec.Spent = true
		rec.SpendingTxid = spendTxid
		body, err := encodeRecord(rec)
		if err != nil {
			return fmt.Errorf("storage: encode record: %w", err)
		}
		batch := new(leveldb.Batch)
		batch.Put(outputKey(topic, op), body)
		batch.Delete(topicIndexKey(topic, rec.Score, op))
		if err := s.db.Write(batch, nil); err != nil {
			return fmt.Errorf("storage: mark spent: %w", err)
		}
	}
	return nil
}

// loadRecord fetches the record for an outpoint. If topic is non-nil it is
// used directly; otherwise we scan the txid index to discover the topic
// (engine often passes topic=nil when looking up "any output for this
// outpoint").
func (s *Storage) loadRecord(op *transaction.Outpoint, topic *string) (*record, error) {
	if topic != nil {
		body, err := s.db.Get(outputKey(*topic, op), nil)
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				return nil, engine.ErrNotFound
			}
			return nil, fmt.Errorf("storage: get record: %w", err)
		}
		return decodeRecord(body)
	}
	// Probe the txid index to find any topic that owns this outpoint.
	prefix := txidIndexPrefix(&op.Txid)
	iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()
	prefixStr := string(prefix)
	for iter.Next() {
		t, v, ok := parseTxidIndexKey(iter.Key(), prefixStr)
		if !ok || v != op.Index {
			continue
		}
		body, err := s.db.Get(outputKey(t, op), nil)
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				continue
			}
			return nil, fmt.Errorf("storage: get record (any topic): %w", err)
		}
		return decodeRecord(body)
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("storage: iterate txi: %w", err)
	}
	return nil, engine.ErrNotFound
}

// hydrate fills the Output's secondary slices (Beef, OutputsConsumed,
// ConsumedBy, AncillaryTxids) from their respective key families. BEEF is
// loaded only when requested because it can be expensive (UHRP bodies).
func (s *Storage) hydrate(out *engine.Output, includeBEEF bool) error {
	if out == nil {
		return nil
	}
	op := out.Outpoint
	// OutputsConsumed (per-tx blob).
	if blob, err := s.db.Get(txConsumedKey(&op.Txid), nil); err == nil {
		out.OutputsConsumed = decodeOutpointBlob(blob)
	} else if !errors.Is(err, leveldb.ErrNotFound) {
		return fmt.Errorf("storage: load tx-consumed: %w", err)
	}
	// AncillaryTxids (per-tx blob).
	if blob, err := s.db.Get(ancillaryKey(&op.Txid), nil); err == nil {
		out.AncillaryTxids = decodeHashBlob(blob)
	} else if !errors.Is(err, leveldb.ErrNotFound) {
		return fmt.Errorf("storage: load anci: %w", err)
	}
	// ConsumedBy (per-output prefix scan).
	consumers, err := s.collectConsumers(out.Topic, &op)
	if err != nil {
		return err
	}
	out.ConsumedBy = consumers
	if includeBEEF {
		if blob, err := s.db.Get(beefKey(&op.Txid), nil); err == nil {
			beef, perr := safeNewBeefFromBytes(blob)
			if perr != nil {
				// A corrupt/unparseable BEEF blob must NOT fail the whole lookup:
				// one bad offer would 502 every query that scans it (the go-sdk
				// parser panics on malformed input). Skip BEEF for this output —
				// the engine drops outputs whose Beef is nil from the results —
				// and log it so the bad entry can be pruned.
				slog.Warn("storage: output has unparseable BEEF, skipping from hydration",
					"txid", op.Txid.String(), "vout", op.Index, "error", perr)
			} else {
				out.Beef = beef
			}
		} else if !errors.Is(err, leveldb.ErrNotFound) {
			return fmt.Errorf("storage: load beef: %w", err)
		}
	}
	return nil
}

// safeNewBeefFromBytes wraps go-sdk's NewBeefFromBytes, which can PANIC (not
// merely return an error) on a malformed or truncated BEEF blob — it trusts an
// embedded transaction count and indexes out of range (observed in the field:
// "index out of range [210] with length 1"). A single corrupt stored blob must
// not crash an entire lookup, so we recover and surface it as an ordinary error
// the caller can skip.
func safeNewBeefFromBytes(blob []byte) (beef *transaction.Beef, err error) {
	defer func() {
		if r := recover(); r != nil {
			beef = nil
			err = fmt.Errorf("BEEF parse panicked: %v", r)
		}
	}()
	return transaction.NewBeefFromBytes(blob)
}

// decodeOutpointBlob splits a concatenated 36-byte-per-outpoint blob.
func decodeOutpointBlob(blob []byte) []*transaction.Outpoint {
	if len(blob) == 0 || len(blob)%36 != 0 {
		return nil
	}
	out := make([]*transaction.Outpoint, 0, len(blob)/36)
	for i := 0; i < len(blob); i += 36 {
		op := transaction.NewOutpointFromBytes(blob[i : i+36])
		if op != nil {
			out = append(out, op)
		}
	}
	return out
}

// decodeHashBlob splits a concatenated 32-byte-per-hash blob.
func decodeHashBlob(blob []byte) []*chainhash.Hash {
	if len(blob) == 0 || len(blob)%32 != 0 {
		return nil
	}
	out := make([]*chainhash.Hash, 0, len(blob)/32)
	for i := 0; i < len(blob); i += 32 {
		var h chainhash.Hash
		copy(h[:], blob[i:i+32])
		// Defensive copy so callers can't mutate our blob window.
		hc := h
		out = append(out, &hc)
	}
	return out
}

// collectConsumers reads the cons3 prefix scan for one output and returns
// the consumer outpoints.
func (s *Storage) collectConsumers(topic string, op *transaction.Outpoint) ([]*transaction.Outpoint, error) {
	prefix := consumerPrefix(topic, op)
	iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()
	var out []*transaction.Outpoint
	for iter.Next() {
		if op, ok := parseConsumerKey(iter.Key(), prefix); ok {
			out = append(out, op)
		}
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("storage: iterate cons: %w", err)
	}
	return out, nil
}

// clearConsumers removes every cons3 entry rooted at the given (topic,
// outpoint). Used by DeleteOutput.
func (s *Storage) clearConsumers(topic string, op *transaction.Outpoint) error {
	prefix := consumerPrefix(topic, op)
	iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()
	batch := new(leveldb.Batch)
	for iter.Next() {
		k := append([]byte(nil), iter.Key()...) // own the bytes
		batch.Delete(k)
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("storage: scan cons for delete: %w", err)
	}
	if batch.Len() == 0 {
		return nil
	}
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("storage: delete cons: %w", err)
	}
	return nil
}

// hashEqual compares two chainhash pointers for value-equality, treating
// nil-vs-nil as equal and nil-vs-non-nil as unequal.
func hashEqual(a, b *chainhash.Hash) bool {
	if a == nil || b == nil {
		return a == b
	}
	return bytes.Equal(a[:], b[:])
}
