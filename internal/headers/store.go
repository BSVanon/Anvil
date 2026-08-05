package headers

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/store"
	sdkchainhash "github.com/bsv-blockchain/go-sdk/chainhash"
	p2pwire "github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
	"github.com/syndtr/goleveldb/leveldb"
)

// ErrRangeExceedsTip is returned by RangeHeaders when the requested range
// extends past the chain tip observed under the read lock. The tip value
// returned alongside this error is authoritative for the snapshot.
var ErrRangeExceedsTip = errors.New("headers: range exceeds tip")

// ErrPrevHashMismatch is returned by AddHeaders when a header does not link to
// the current tip — the signal that our tip may be on a minority fork. The
// syncer catches this (errors.Is) and attempts ReorgTo instead of giving up.
// The wrapped message deliberately keeps the literal "prev hash mismatch"
// substring that `anvil doctor` and /status health checks match on.
var ErrPrevHashMismatch = errors.New("prev hash mismatch")

// maxReorgDepth bounds how far below the tip ReorgTo will roll back to adopt a
// competing chain. Real BSV reorgs are a handful of blocks; a day of headers is
// a generous ceiling that still stops a broken/hostile peer from forcing an
// unbounded rollback. A fork deeper than this is surfaced as an error for
// operator/doctor handling rather than auto-adopted.
const maxReorgDepth = 144

// Key prefixes for LevelDB.
var (
	prefixHeader = []byte("h:")   // h:<height_be> → serialized 80-byte header
	prefixHash   = []byte("hi:")  // hi:<hash> → height (4 bytes big-endian)
	prefixMerkle = []byte("m:")   // m:<height_be> → merkle root (32 bytes)
	keyTip       = []byte("tip")  // tip → height (4 bytes big-endian)
	keyWork      = []byte("work") // work → cumulative chain work (big.Int bytes)
)

// Store is a LevelDB-backed block header store that implements the go-sdk
// ChainTracker interface for sovereign SPV verification.
type Store struct {
	db      *leveldb.DB
	mu      sync.RWMutex
	tip     uint32
	work    *big.Int // cumulative work of the active chain
	skipPoW bool     // for testing only
}

// NewStore opens or creates a header store at the given path.
// If the store is empty, it writes the genesis header at height 0.
func NewStore(path string) (*Store, error) {
	db, err := store.OpenWithRecover(path, nil)
	if err != nil {
		return nil, fmt.Errorf("open header store: %w", err)
	}

	s := &Store{db: db, work: big.NewInt(0)}

	// Load current tip
	tipBytes, err := db.Get(keyTip, nil)
	if err == leveldb.ErrNotFound {
		// Empty store — write genesis
		if err := s.writeGenesis(); err != nil {
			_ = db.Close()
			return nil, err
		}
	} else if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read tip: %w", err)
	} else {
		s.tip = binary.BigEndian.Uint32(tipBytes)
	}

	// Load cumulative work
	workBytes, err := db.Get(keyWork, nil)
	if err == nil {
		s.work.SetBytes(workBytes)
	} else if err != leveldb.ErrNotFound {
		_ = db.Close()
		return nil, fmt.Errorf("read work: %w", err)
	}

	return s, nil
}

// NewTestStore creates a store with PoW validation disabled, for unit tests
// that use synthetic headers which don't have valid proof of work.
func NewTestStore(path string) (*Store, error) {
	s, err := NewStore(path)
	if err != nil {
		return nil, err
	}
	s.skipPoW = true
	return s, nil
}

// Close closes the underlying LevelDB.
func (s *Store) Close() error {
	return s.db.Close()
}

// Tip returns the current chain tip height.
func (s *Store) Tip() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tip
}

// AddHeaders stores a batch of sequential headers starting at the given height.
// Validates:
//   - Prev-hash linkage against the existing chain tip
//   - Proof of work (block hash meets difficulty target)
//   - Tracks cumulative chain work
func (s *Store) AddHeaders(startHeight uint32, headers []*wire.BlockHeader) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if startHeight != s.tip+1 {
		return fmt.Errorf("expected start height %d, got %d", s.tip+1, startHeight)
	}

	if len(headers) == 0 {
		return nil
	}

	tipHash, err := s.hashAtHeight(s.tip)
	if err != nil {
		return fmt.Errorf("get tip hash: %w", err)
	}

	batch := new(leveldb.Batch)
	height := startHeight
	batchWork := new(big.Int)

	for i, hdr := range headers {
		// Check prev-hash linkage
		if hdr.PrevBlock != *tipHash {
			if i == 0 {
				return fmt.Errorf("header %d at height %d: %w", i, height, ErrPrevHashMismatch)
			}
			return fmt.Errorf("header %d at height %d: batch linkage mismatch", i, height)
		}

		// Validate proof of work
		if !s.skipPoW {
			if err := ValidatePoW(hdr); err != nil {
				return fmt.Errorf("header %d at height %d: %w", i, height, err)
			}
		}

		// Serialize header
		var buf bytes.Buffer
		if err := hdr.Serialize(&buf); err != nil {
			return fmt.Errorf("serialize header %d: %w", i, err)
		}

		blockHash := hdr.BlockHash()
		heightKey := heightToKey(prefixHeader, height)
		hashKey := append(append([]byte{}, prefixHash...), blockHash[:]...)
		merkleKey := heightToKey(prefixMerkle, height)
		heightBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(heightBytes, height)

		batch.Put(heightKey, buf.Bytes())
		batch.Put(hashKey, heightBytes)
		batch.Put(merkleKey, hdr.MerkleRoot[:])

		batchWork.Add(batchWork, WorkForHeader(hdr))

		tipHash = &blockHash
		height++
	}

	// Update tip and cumulative work
	newTip := height - 1
	tipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tipBytes, newTip)
	batch.Put(keyTip, tipBytes)

	newWork := new(big.Int).Add(s.work, batchWork)
	batch.Put(keyWork, newWork.Bytes())

	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("write batch: %w", err)
	}

	s.tip = newTip
	s.work = newWork
	return nil
}

// Work returns the cumulative chain work.
func (s *Store) Work() *big.Int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return new(big.Int).Set(s.work)
}

// Rollback removes headers from the tip back to the given height (inclusive).
// Used during reorg when a competing chain has more cumulative work.
func (s *Store) Rollback(toHeight uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if toHeight >= s.tip {
		return fmt.Errorf("rollback target %d >= current tip %d", toHeight, s.tip)
	}

	batch := new(leveldb.Batch)
	rollbackWork := new(big.Int)

	for h := s.tip; h > toHeight; h-- {
		raw, err := s.db.Get(heightToKey(prefixHeader, h), nil)
		if err != nil {
			return fmt.Errorf("read header at %d for rollback: %w", h, err)
		}
		var hdr wire.BlockHeader
		if err := hdr.Deserialize(bytes.NewReader(raw)); err != nil {
			return fmt.Errorf("deserialize header at %d: %w", h, err)
		}

		blockHash := hdr.BlockHash()
		rollbackWork.Add(rollbackWork, WorkForHeader(&hdr))

		batch.Delete(heightToKey(prefixHeader, h))
		batch.Delete(append(append([]byte{}, prefixHash...), blockHash[:]...))
		batch.Delete(heightToKey(prefixMerkle, h))
	}

	tipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tipBytes, toHeight)
	batch.Put(keyTip, tipBytes)

	newWork := new(big.Int).Sub(s.work, rollbackWork)
	batch.Put(keyWork, newWork.Bytes())

	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("rollback write: %w", err)
	}

	s.tip = toHeight
	s.work = newWork
	return nil
}

// ReorgTo attempts to adopt a competing chain delivered as a batch of headers
// that fork below the current tip — the case the strict AddHeaders path reports
// as ErrPrevHashMismatch. It locates the fork point from headers[0].PrevBlock,
// validates the batch (linkage + PoW), and adopts it (atomically rolling back
// the orphaned tip range and writing the new chain in one LevelDB batch) ONLY
// if the resulting chain has strictly more cumulative work — Bitcoin's
// most-work rule. A fork deeper than maxReorgDepth, or a fork point we don't
// have, is refused so a broken/hostile peer cannot force an unbounded rollback
// or trick us onto a lighter chain.
//
// Returns adopted=true when the new chain was committed; adopted=false when the
// competing chain was valid but not heavier (current chain kept). A non-nil
// error means the batch was unusable (unknown/too-deep fork, or invalid PoW) —
// the caller surfaces it for operator/doctor handling.
func (s *Store) ReorgTo(headers []*wire.BlockHeader) (adopted bool, forkHeight uint32, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(headers) == 0 {
		return false, 0, errors.New("reorg: empty header batch")
	}

	// Locate the fork point: the height at which headers[0] attaches.
	forkHash := headers[0].PrevBlock
	fhBytes, err := s.db.Get(append(append([]byte{}, prefixHash...), forkHash[:]...), nil)
	if errors.Is(err, leveldb.ErrNotFound) {
		return false, 0, fmt.Errorf("reorg: fork point %s not in store", forkHash.String())
	}
	if err != nil {
		return false, 0, fmt.Errorf("reorg: lookup fork point: %w", err)
	}
	forkHeight = binary.BigEndian.Uint32(fhBytes)

	if forkHeight >= s.tip {
		// Fork point is at/above the tip — not a below-tip reorg; nothing to do.
		return false, forkHeight, nil
	}
	if s.tip-forkHeight > maxReorgDepth {
		return false, forkHeight, fmt.Errorf("reorg: depth %d exceeds max %d", s.tip-forkHeight, maxReorgDepth)
	}

	// Validate the incoming chain from the fork point and sum its work.
	prevHash := forkHash
	newBatchWork := new(big.Int)
	for i, hdr := range headers {
		if hdr.PrevBlock != prevHash {
			return false, forkHeight, fmt.Errorf("reorg: header %d does not link at height %d", i, forkHeight+uint32(i)+1)
		}
		if !s.skipPoW {
			if err := ValidatePoW(hdr); err != nil {
				return false, forkHeight, fmt.Errorf("reorg: header %d invalid pow: %w", i, err)
			}
		}
		newBatchWork.Add(newBatchWork, WorkForHeader(hdr))
		bh := hdr.BlockHash()
		prevHash = bh
	}

	// Work we would discard by rolling back to the fork point.
	discardedWork := new(big.Int)
	for h := forkHeight + 1; h <= s.tip; h++ {
		raw, err := s.db.Get(heightToKey(prefixHeader, h), nil)
		if err != nil {
			return false, forkHeight, fmt.Errorf("reorg: read header at %d: %w", h, err)
		}
		var hdr wire.BlockHeader
		if err := hdr.Deserialize(bytes.NewReader(raw)); err != nil {
			return false, forkHeight, fmt.Errorf("reorg: deserialize header at %d: %w", h, err)
		}
		discardedWork.Add(discardedWork, WorkForHeader(&hdr))
	}

	// Most-work rule: adopt only if the competing chain is strictly heavier.
	if newBatchWork.Cmp(discardedWork) <= 0 {
		return false, forkHeight, nil
	}

	// Adopt atomically: delete the orphaned tip range, write the new chain,
	// update tip + cumulative work — all in one batch. Deletes are queued
	// before Puts, so any height present in both resolves to the new header.
	batch := new(leveldb.Batch)
	for h := s.tip; h > forkHeight; h-- {
		raw, err := s.db.Get(heightToKey(prefixHeader, h), nil)
		if err != nil {
			return false, forkHeight, fmt.Errorf("reorg: read old header at %d: %w", h, err)
		}
		var hdr wire.BlockHeader
		if err := hdr.Deserialize(bytes.NewReader(raw)); err != nil {
			return false, forkHeight, fmt.Errorf("reorg: deserialize old header at %d: %w", h, err)
		}
		oldHash := hdr.BlockHash()
		batch.Delete(heightToKey(prefixHeader, h))
		batch.Delete(append(append([]byte{}, prefixHash...), oldHash[:]...))
		batch.Delete(heightToKey(prefixMerkle, h))
	}

	height := forkHeight + 1
	for _, hdr := range headers {
		var buf bytes.Buffer
		if err := hdr.Serialize(&buf); err != nil {
			return false, forkHeight, fmt.Errorf("reorg: serialize header at %d: %w", height, err)
		}
		bh := hdr.BlockHash()
		heightBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(heightBytes, height)
		batch.Put(heightToKey(prefixHeader, height), buf.Bytes())
		batch.Put(append(append([]byte{}, prefixHash...), bh[:]...), heightBytes)
		batch.Put(heightToKey(prefixMerkle, height), hdr.MerkleRoot[:])
		height++
	}
	newTip := height - 1

	// New cumulative work = (work at fork) + new batch
	//                     = (current work - discarded) + new batch.
	newWork := new(big.Int).Sub(s.work, discardedWork)
	newWork.Add(newWork, newBatchWork)

	tipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tipBytes, newTip)
	batch.Put(keyTip, tipBytes)
	batch.Put(keyWork, newWork.Bytes())

	if err := s.db.Write(batch, nil); err != nil {
		return false, forkHeight, fmt.Errorf("reorg: write batch: %w", err)
	}
	s.tip = newTip
	s.work = newWork
	return true, forkHeight, nil
}

// HeaderAtHeight returns the raw 80-byte header at the given height.
func (s *Store) HeaderAtHeight(height uint32) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db.Get(heightToKey(prefixHeader, height), nil)
}

// RangeHeaders returns N consecutive raw 80-byte headers starting at `from`,
// along with the chain tip observed at the start of the read. The full range
// is read under a single RLock so a concurrent Rollback cannot interleave
// headers from different chain states into the response.
func (s *Store) RangeHeaders(from, count uint32) ([][]byte, uint32, error) {
	if count == 0 {
		return nil, 0, fmt.Errorf("count must be >= 1")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	tip := s.tip
	last := uint64(from) + uint64(count) - 1
	if last > uint64(tip) {
		return nil, tip, ErrRangeExceedsTip
	}

	out := make([][]byte, 0, count)
	// Iterate by offset so the loop counter cannot overflow uint32 even when
	// from+count would wrap. The uint64 bound check above already guarantees
	// from+i fits in uint32 for every i in [0, count).
	for i := uint32(0); i < count; i++ {
		h := from + i
		raw, err := s.db.Get(heightToKey(prefixHeader, h), nil)
		if err != nil {
			return nil, tip, fmt.Errorf("header at %d: %w", h, err)
		}
		if len(raw) != 80 {
			return nil, tip, fmt.Errorf("header at %d: expected 80 bytes, got %d", h, len(raw))
		}
		out = append(out, raw)
	}
	return out, tip, nil
}

// HashAtHeight returns the block hash at the given height.
func (s *Store) HashAtHeight(height uint32) (*p2pwire.Hash, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hashAtHeight(height)
}

func (s *Store) hashAtHeight(height uint32) (*p2pwire.Hash, error) {
	raw, err := s.db.Get(heightToKey(prefixHeader, height), nil)
	if err != nil {
		return nil, err
	}
	var hdr wire.BlockHeader
	if err := hdr.Deserialize(bytes.NewReader(raw)); err != nil {
		return nil, err
	}
	h := hdr.BlockHash()
	return &h, nil
}

// HeightForHash returns the height for a given block hash, or an error if not found.
func (s *Store) HeightForHash(hash *p2pwire.Hash) (uint32, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := append(append([]byte{}, prefixHash...), hash[:]...)
	val, err := s.db.Get(key, nil)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(val), nil
}

// --- ChainTracker interface (go-sdk) ---

// IsValidRootForHeight checks if the given merkle root matches the header at
// the given height. This is the core SPV verification primitive.
func (s *Store) IsValidRootForHeight(_ context.Context, root *sdkchainhash.Hash, height uint32) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	merkle, err := s.db.Get(heightToKey(prefixMerkle, height), nil)
	if err == leveldb.ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return bytes.Equal(merkle, root[:]), nil
}

// CurrentHeight returns the chain tip height.
func (s *Store) CurrentHeight(_ context.Context) (uint32, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tip, nil
}

// --- helpers ---

func heightToKey(prefix []byte, height uint32) []byte {
	key := make([]byte, len(prefix)+4)
	copy(key, prefix)
	binary.BigEndian.PutUint32(key[len(prefix):], height)
	return key
}

// BSV mainnet genesis block header (height 0).
var genesisHeaderBytes = func() []byte {
	// Hardcoded genesis block header for BSV mainnet.
	// This is the same as BTC genesis since BSV shares the same genesis.
	h := wire.NewBlockHeader(
		1,               // version
		&p2pwire.Hash{}, // prev block (all zeros)
		mustHash("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"), // merkle root
		0x1d00ffff, // bits
		2083236893, // nonce
	)
	h.Timestamp = time.Unix(1231006505, 0)
	var buf bytes.Buffer
	_ = h.Serialize(&buf) // genesis header serialization can't fail
	return buf.Bytes()
}()

func (s *Store) writeGenesis() error {
	var hdr wire.BlockHeader
	if err := hdr.Deserialize(bytes.NewReader(genesisHeaderBytes)); err != nil {
		return fmt.Errorf("deserialize genesis: %w", err)
	}

	blockHash := hdr.BlockHash()
	heightBytes := make([]byte, 4)

	batch := new(leveldb.Batch)
	batch.Put(heightToKey(prefixHeader, 0), genesisHeaderBytes)
	batch.Put(append(append([]byte{}, prefixHash...), blockHash[:]...), heightBytes)
	batch.Put(heightToKey(prefixMerkle, 0), hdr.MerkleRoot[:])
	batch.Put(keyTip, heightBytes) // height 0

	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("write genesis: %w", err)
	}
	s.tip = 0
	return nil
}

func mustHash(s string) *p2pwire.Hash {
	h, err := p2pwire.NewHashFromStr(s)
	if err != nil {
		panic(err)
	}
	return h
}
