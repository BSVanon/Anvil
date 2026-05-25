package storage

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// UpdateConsumedBy replaces the cons3 entries for a single output with the
// provided list. The replacement is atomic: we collect existing entries,
// emit deletes + new puts in one batch.
func (s *Storage) UpdateConsumedBy(
	ctx context.Context,
	outpoint *transaction.Outpoint,
	topic string,
	consumedBy []*transaction.Outpoint,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if outpoint == nil {
		return errors.New("storage: nil outpoint")
	}
	// Ensure the underlying record exists; UpdateConsumedBy on an absent
	// output is a no-op (mirrors engine.ErrNotFound suppression at the
	// engine layer).
	if _, err := s.loadRecord(outpoint, &topic); err != nil {
		if errors.Is(err, engine.ErrNotFound) {
			return nil
		}
		return err
	}

	prefix := consumerPrefix(topic, outpoint)
	iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
	batch := new(leveldb.Batch)
	for iter.Next() {
		k := append([]byte(nil), iter.Key()...)
		batch.Delete(k)
	}
	if err := iter.Error(); err != nil {
		iter.Release()
		return fmt.Errorf("storage: scan cons: %w", err)
	}
	iter.Release()

	for _, c := range consumedBy {
		if c == nil {
			continue
		}
		batch.Put(consumerKey(topic, outpoint, c), nil)
	}
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("storage: update cons: %w", err)
	}
	return nil
}

// UpdateTransactionBEEF overwrites the BEEF blob stored for a txid.
func (s *Storage) UpdateTransactionBEEF(
	ctx context.Context,
	txid *chainhash.Hash,
	beef *transaction.Beef,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if txid == nil {
		return errors.New("storage: nil txid")
	}
	if beef == nil {
		return s.db.Delete(beefKey(txid), nil)
	}
	body, err := beef.Bytes()
	if err != nil {
		return fmt.Errorf("storage: serialise beef: %w", err)
	}
	if err := s.db.Put(beefKey(txid), body, nil); err != nil {
		return fmt.Errorf("storage: put beef: %w", err)
	}
	return nil
}

// UpdateOutputBlockHeight stamps the block height/index onto an output's
// record. Does not change MerkleState — that transitions via
// ReconcileMerkleRoot which knows whether the merkle root matched.
func (s *Storage) UpdateOutputBlockHeight(
	ctx context.Context,
	outpoint *transaction.Outpoint,
	topic string,
	blockHeight uint32,
	blockIndex uint64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if outpoint == nil {
		return errors.New("storage: nil outpoint")
	}
	rec, err := s.loadRecord(outpoint, &topic)
	if err != nil {
		return err
	}
	if rec.BlockHeight == blockHeight && rec.BlockIdx == blockIndex {
		return nil
	}
	rec.BlockHeight = blockHeight
	rec.BlockIdx = blockIndex
	body, err := encodeRecord(rec)
	if err != nil {
		return fmt.Errorf("storage: encode record: %w", err)
	}
	if err := s.db.Put(outputKey(topic, outpoint), body, nil); err != nil {
		return fmt.Errorf("storage: put record: %w", err)
	}
	return nil
}

// InsertAppliedTransaction records that a (topic, txid) pair has been
// processed. Idempotent.
func (s *Storage) InsertAppliedTransaction(
	ctx context.Context,
	tx *overlay.AppliedTransaction,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tx == nil || tx.Txid == nil {
		return errors.New("storage: nil applied transaction")
	}
	if err := s.db.Put(appliedKey(tx.Topic, tx.Txid), nil, nil); err != nil {
		return fmt.Errorf("storage: put applied: %w", err)
	}
	return nil
}

// DoesAppliedTransactionExist returns true if the (topic, txid) pair has
// been recorded as applied.
func (s *Storage) DoesAppliedTransactionExist(
	ctx context.Context,
	tx *overlay.AppliedTransaction,
) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if tx == nil || tx.Txid == nil {
		return false, errors.New("storage: nil applied transaction")
	}
	_, err := s.db.Get(appliedKey(tx.Topic, tx.Txid), nil)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, leveldb.ErrNotFound) {
		return false, nil
	}
	return false, fmt.Errorf("storage: get applied: %w", err)
}

// UpdateLastInteraction stores the peer-interaction score (Unix epoch
// fractional seconds typically) for a (host, topic) pair.
func (s *Storage) UpdateLastInteraction(
	ctx context.Context,
	host, topic string,
	since float64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], math.Float64bits(since))
	if err := s.db.Put(peerKey(host, topic), buf[:], nil); err != nil {
		return fmt.Errorf("storage: put peer: %w", err)
	}
	return nil
}

// GetLastInteraction returns the recorded peer-interaction score, or 0 if
// no entry exists for that (host, topic).
func (s *Storage) GetLastInteraction(
	ctx context.Context,
	host, topic string,
) (float64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	body, err := s.db.Get(peerKey(host, topic), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return 0, nil
		}
		return 0, fmt.Errorf("storage: get peer: %w", err)
	}
	if len(body) != 8 {
		return 0, fmt.Errorf("storage: peer value wrong length %d", len(body))
	}
	bits := binary.BigEndian.Uint64(body)
	return math.Float64frombits(bits), nil
}

// FindOutpointsByMerkleState returns up to `limit` outpoints in the given
// topic + merkle-state bucket. limit=0 means unbounded.
func (s *Storage) FindOutpointsByMerkleState(
	ctx context.Context,
	topic string,
	state engine.MerkleState,
	limit uint32,
) ([]*transaction.Outpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prefix := merkleIndexPrefix(topic, uint8(state))
	iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()

	out := make([]*transaction.Outpoint, 0)
	var produced uint32
	for iter.Next() {
		if limit > 0 && produced >= limit {
			break
		}
		txidHex, vout, ok := parseMerkleIndexKey(iter.Key(), prefix)
		if !ok {
			continue
		}
		op, err := outpointFromHex(txidHex, vout)
		if err != nil {
			continue
		}
		out = append(out, op)
		produced++
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("storage: iterate mst: %w", err)
	}
	return out, nil
}

// ReconcileMerkleRoot transitions every output at the given block height in
// `topic` based on whether its stored merkle root matches the authoritative
// `merkleRoot` argument. Matching → Validated, mismatching → Invalidated,
// nil-root → left as Unmined.
//
// W-4 phase A keeps this conservative: it does NOT auto-promote to
// Immutable (that requires header-chain depth info the storage layer
// shouldn't own). Callers may invoke a separate promotion path in W-5 when
// chain depth is known.
func (s *Storage) ReconcileMerkleRoot(
	ctx context.Context,
	topic string,
	blockHeight uint32,
	merkleRoot *chainhash.Hash,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Iterate the Unmined and Validated buckets. Anything already
	// Invalidated or Immutable is terminal and not re-evaluated.
	for _, st := range []engine.MerkleState{engine.MerkleStateUnmined, engine.MerkleStateValidated} {
		ops, err := s.FindOutpointsByMerkleState(ctx, topic, st, 0)
		if err != nil {
			return err
		}
		for _, op := range ops {
			rec, err := s.loadRecord(op, &topic)
			if err != nil {
				if errors.Is(err, engine.ErrNotFound) {
					continue
				}
				return err
			}
			if rec.BlockHeight != blockHeight {
				continue
			}
			oldState := engine.MerkleState(rec.MerkleState)
			var newState engine.MerkleState
			switch {
			case rec.MerkleRoot == nil:
				newState = engine.MerkleStateUnmined
			case hashEqual(rec.MerkleRoot, merkleRoot):
				newState = engine.MerkleStateValidated
			default:
				newState = engine.MerkleStateInvalidated
			}
			if newState == oldState {
				continue
			}
			rec.MerkleState = uint8(newState)
			body, err := encodeRecord(rec)
			if err != nil {
				return fmt.Errorf("storage: encode record: %w", err)
			}
			batch := new(leveldb.Batch)
			batch.Put(outputKey(topic, op), body)
			batch.Delete(merkleIndexKey(topic, uint8(oldState), op))
			batch.Put(merkleIndexKey(topic, uint8(newState), op), nil)
			if err := s.db.Write(batch, nil); err != nil {
				return fmt.Errorf("storage: reconcile write: %w", err)
			}
		}
	}
	return nil
}

// LoadAncillaryBeef merges the BEEF data for every transaction in
// out.AncillaryTxids into out.Beef so callers can hand the result to a
// validator that needs the full evaluation graph.
func (s *Storage) LoadAncillaryBeef(ctx context.Context, out *engine.Output) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if out == nil {
		return errors.New("storage: nil output")
	}
	if out.Beef == nil {
		blob, err := s.db.Get(beefKey(&out.Outpoint.Txid), nil)
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				return engine.ErrNotFound
			}
			return fmt.Errorf("storage: load beef: %w", err)
		}
		beef, err := transaction.NewBeefFromBytes(blob)
		if err != nil {
			return fmt.Errorf("storage: parse beef: %w", err)
		}
		out.Beef = beef
	}
	for _, h := range out.AncillaryTxids {
		if h == nil {
			continue
		}
		blob, err := s.db.Get(beefKey(h), nil)
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				continue
			}
			return fmt.Errorf("storage: load ancillary beef %s: %w", h.String(), err)
		}
		if err := out.Beef.MergeBeefBytes(blob); err != nil {
			return fmt.Errorf("storage: merge ancillary beef %s: %w", h.String(), err)
		}
	}
	return nil
}
