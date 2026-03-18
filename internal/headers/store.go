package headers

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	sdkchainhash "github.com/bsv-blockchain/go-sdk/chainhash"
	p2pwire "github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
	"github.com/syndtr/goleveldb/leveldb"
)

// Key prefixes for LevelDB.
var (
	prefixHeader    = []byte("h:")  // h:<height_be> → serialized 80-byte header
	prefixHash      = []byte("hi:") // hi:<hash> → height (4 bytes big-endian)
	prefixMerkle    = []byte("m:")  // m:<height_be> → merkle root (32 bytes)
	keyTip          = []byte("tip") // tip → height (4 bytes big-endian)
)

// Store is a LevelDB-backed block header store that implements the go-sdk
// ChainTracker interface for sovereign SPV verification.
type Store struct {
	db  *leveldb.DB
	mu  sync.RWMutex
	tip uint32
}

// NewStore opens or creates a header store at the given path.
// If the store is empty, it writes the genesis header at height 0.
func NewStore(path string) (*Store, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, fmt.Errorf("open header store: %w", err)
	}

	s := &Store{db: db}

	// Load current tip
	tipBytes, err := db.Get(keyTip, nil)
	if err == leveldb.ErrNotFound {
		// Empty store — write genesis
		if err := s.writeGenesis(); err != nil {
			db.Close()
			return nil, err
		}
	} else if err != nil {
		db.Close()
		return nil, fmt.Errorf("read tip: %w", err)
	} else {
		s.tip = binary.BigEndian.Uint32(tipBytes)
	}

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
// It validates prev-hash linkage against the existing chain tip.
func (s *Store) AddHeaders(startHeight uint32, headers []*wire.BlockHeader) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if startHeight != s.tip+1 {
		return fmt.Errorf("expected start height %d, got %d", s.tip+1, startHeight)
	}

	// Validate prev-hash linkage: first header must link to current tip
	if len(headers) == 0 {
		return nil
	}

	tipHash, err := s.hashAtHeight(s.tip)
	if err != nil {
		return fmt.Errorf("get tip hash: %w", err)
	}

	batch := new(leveldb.Batch)
	height := startHeight

	for i, hdr := range headers {
		// Check prev-hash linkage
		if hdr.PrevBlock != *tipHash {
			return fmt.Errorf("header %d: prev hash mismatch at height %d", i, height)
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

		tipHash = &blockHash
		height++
	}

	// Update tip
	tipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tipBytes, height-1)
	batch.Put(keyTip, tipBytes)

	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("write batch: %w", err)
	}

	s.tip = height - 1
	return nil
}

// HeaderAtHeight returns the raw 80-byte header at the given height.
func (s *Store) HeaderAtHeight(height uint32) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db.Get(heightToKey(prefixHeader, height), nil)
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
		1,                                     // version
		&p2pwire.Hash{},                       // prev block (all zeros)
		mustHash("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"), // merkle root
		0x1d00ffff,                            // bits
		2083236893,                            // nonce
	)
	h.Timestamp = time.Unix(1231006505, 0)
	var buf bytes.Buffer
	h.Serialize(&buf)
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

