package spv

import (
	"fmt"

	"github.com/BSVanon/Anvil/internal/store"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

var (
	prefixBeef = []byte("beef:") // beef:<txid_hex> → full BEEF binary (tx + ancestry + BUMPs)
)

// ProofStore is a LevelDB-backed store for BEEF envelopes.
// Stores the complete BEEF binary so it can be served back as-is,
// preserving the full ancestry chain and all merkle proofs.
type ProofStore struct {
	db *leveldb.DB
}

// NewProofStore opens or creates a proof store at the given path.
func NewProofStore(path string) (*ProofStore, error) {
	db, err := store.OpenWithRecover(path, nil)
	if err != nil {
		return nil, fmt.Errorf("open proof store: %w", err)
	}
	return &ProofStore{db: db}, nil
}

// Close closes the underlying LevelDB.
func (s *ProofStore) Close() error {
	return s.db.Close()
}

// StoreBEEF saves the complete BEEF binary for a transaction.
// The txid is extracted from the BEEF to use as the key.
func (s *ProofStore) StoreBEEF(beef []byte) (string, error) {
	tx, err := transaction.NewTransactionFromBEEF(beef)
	if err != nil {
		return "", fmt.Errorf("parse BEEF: %w", err)
	}
	txid := tx.TxID().String()

	key := append(append([]byte{}, prefixBeef...), []byte(txid)...)
	if err := s.db.Put(key, beef, nil); err != nil {
		return txid, fmt.Errorf("store BEEF: %w", err)
	}
	return txid, nil
}

// GetBEEF retrieves the complete BEEF binary for a transaction.
func (s *ProofStore) GetBEEF(txid string) ([]byte, error) {
	key := append(append([]byte{}, prefixBeef...), []byte(txid)...)
	return s.db.Get(key, nil)
}

// HasBEEF returns whether a BEEF envelope exists for the given txid.
func (s *ProofStore) HasBEEF(txid string) bool {
	key := append(append([]byte{}, prefixBeef...), []byte(txid)...)
	ok, _ := s.db.Has(key, nil)
	return ok
}

// Count returns the number of persisted BEEF proofs.
func (s *ProofStore) Count() int {
	count := 0
	iter := s.db.NewIterator(util.BytesPrefix(prefixBeef), nil)
	defer iter.Release()
	for iter.Next() {
		count++
	}
	return count
}
