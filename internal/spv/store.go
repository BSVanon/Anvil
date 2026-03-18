package spv

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

var (
	prefixBump = []byte("bump:") // bump:<txid_hex> → BRC-74 BUMP binary
	prefixRaw  = []byte("raw:")  // raw:<txid_hex> → raw transaction bytes
)

// ProofStore is a LevelDB-backed store for merkle proofs (BUMPs) and raw
// transactions, enabling BEEF serving for confirmed transactions.
type ProofStore struct {
	db *leveldb.DB
}

// NewProofStore opens or creates a proof store at the given path.
func NewProofStore(path string) (*ProofStore, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, fmt.Errorf("open proof store: %w", err)
	}
	return &ProofStore{db: db}, nil
}

// Close closes the underlying LevelDB.
func (s *ProofStore) Close() error {
	return s.db.Close()
}

// StoreBUMP saves a BRC-74 merkle proof for a transaction.
func (s *ProofStore) StoreBUMP(txid string, bump []byte) error {
	key := append(append([]byte{}, prefixBump...), []byte(txid)...)
	return s.db.Put(key, bump, nil)
}

// GetBUMP retrieves the BRC-74 merkle proof for a transaction.
func (s *ProofStore) GetBUMP(txid string) ([]byte, error) {
	key := append(append([]byte{}, prefixBump...), []byte(txid)...)
	return s.db.Get(key, nil)
}

// StoreRawTx saves a raw transaction.
func (s *ProofStore) StoreRawTx(txid string, raw []byte) error {
	key := append(append([]byte{}, prefixRaw...), []byte(txid)...)
	return s.db.Put(key, raw, nil)
}

// GetRawTx retrieves a raw transaction.
func (s *ProofStore) GetRawTx(txid string) ([]byte, error) {
	key := append(append([]byte{}, prefixRaw...), []byte(txid)...)
	return s.db.Get(key, nil)
}

// StoreFromBEEF extracts and stores the merkle proof and raw tx from a
// validated BEEF transaction.
func (s *ProofStore) StoreFromBEEF(beef []byte) (string, error) {
	tx, err := transaction.NewTransactionFromBEEF(beef)
	if err != nil {
		return "", fmt.Errorf("parse BEEF: %w", err)
	}

	txid := tx.TxID().String()

	// Store raw transaction
	rawBytes := tx.Bytes()
	if err := s.StoreRawTx(txid, rawBytes); err != nil {
		return txid, fmt.Errorf("store raw tx: %w", err)
	}

	// Store BUMP if present
	if tx.MerklePath != nil {
		bumpBytes := tx.MerklePath.Bytes()
		if err := s.StoreBUMP(txid, bumpBytes); err != nil {
			return txid, fmt.Errorf("store BUMP: %w", err)
		}
	}

	return txid, nil
}

// HasProof returns whether a merkle proof exists for the given txid.
func (s *ProofStore) HasProof(txid string) bool {
	key := append(append([]byte{}, prefixBump...), []byte(txid)...)
	ok, _ := s.db.Has(key, nil)
	return ok
}
