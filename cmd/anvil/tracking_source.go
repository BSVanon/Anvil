package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/BSVanon/Anvil/internal/ordtrack"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// trackSource is the version tracker's view of the node's transaction
// paths: the proof store; the tx-status path and the proof fetch, ARC
// first, then WhatsOnChain (spv.ProofFetcher, as GET /tx/{txid}/status and
// GET /tx/{txid}/beef use them); and the content fetch path for a
// transaction not yet mined (the block cache, a P2P fetch, then
// WhatsOnChain). A transaction counts as mined only with a merkle path the
// node's own headers confirm; what an upstream says about it is never
// enough.
type trackSource struct {
	proofs  proofReader
	fetcher proofFetcher // nil: no tx-status path
	rawTx   func(ctx context.Context, txid string) ([]byte, error)
	headers chaintracker.ChainTracker
}

// proofReader is the part of spv.ProofStore the tracker uses.
type proofReader interface {
	GetBEEF(txid string) ([]byte, error)
}

// proofFetcher is the part of spv.ProofFetcher the tracker uses.
type proofFetcher interface {
	TxStatus(txid string) (*spv.TxStatusResult, error)
	FetchBEEF(txid string) ([]byte, string, error)
}

// Tx returns txid's transaction, with its merkle path when it is proven
// mined. One that cannot be proven mined, even for want of an answer from
// the tx-status path, comes without, and is checked as an unmined one.
func (s *trackSource) Tx(ctx context.Context, txid string) (*transaction.Transaction, error) {
	if tx, _, err := s.lookup(ctx, txid); err == nil && tx != nil {
		return tx, nil
	}
	raw, err := s.rawTx(ctx, txid)
	if err != nil {
		return nil, err
	}
	return transaction.NewTransactionFromBytes(raw)
}

// Status returns txid's chain status. Mined means proven mined.
func (s *trackSource) Status(ctx context.Context, txid string) (ordtrack.Status, error) {
	_, st, err := s.lookup(ctx, txid)
	return st, err
}

// lookup returns txid proven mined, from the proof store or from a proof
// fetched once the tx-status path reports it mined; or, when it cannot be
// proven mined, a nil transaction and what the tx-status path knows. Only
// a tx-status path that cannot answer is an error.
func (s *trackSource) lookup(ctx context.Context, txid string) (*transaction.Transaction, ordtrack.Status, error) {
	if beef, err := s.proofs.GetBEEF(txid); err == nil {
		if tx := s.proven(ctx, beef, txid); tx != nil {
			return tx, minedStatus(tx), nil
		}
	}
	if s.fetcher == nil {
		return nil, ordtrack.Status{}, nil
	}
	st, err := s.fetcher.TxStatus(txid)
	if err != nil {
		return nil, ordtrack.Status{}, fmt.Errorf("tx status: %w", err)
	}
	if st == nil || !st.Found {
		return nil, ordtrack.Status{}, nil
	}
	if !st.Mined {
		return nil, ordtrack.Status{Known: true}, nil
	}
	beef, _, err := s.fetcher.FetchBEEF(txid)
	if err != nil {
		return nil, ordtrack.Status{Known: true}, nil
	}
	tx := s.proven(ctx, beef, txid)
	if tx == nil {
		return nil, ordtrack.Status{Known: true}, nil
	}
	return tx, minedStatus(tx), nil
}

// proven returns beef's subject when it is txid with a merkle path that
// the node's headers confirm, else nil.
func (s *trackSource) proven(ctx context.Context, beef []byte, txid string) *transaction.Transaction {
	tx, err := beefSubject(beef)
	if err != nil || tx.MerklePath == nil || tx.TxID().String() != txid {
		return nil
	}
	ok, err := tx.MerklePath.Verify(ctx, tx.TxID(), s.headers)
	if err != nil || !ok {
		return nil
	}
	return tx
}

func minedStatus(tx *transaction.Transaction) ordtrack.Status {
	return ordtrack.Status{Known: true, Mined: true, Height: tx.MerklePath.BlockHeight}
}

// beefSubject is transaction.NewTransactionFromBEEF behind a panic recover.
func beefSubject(beef []byte) (tx *transaction.Transaction, err error) {
	defer func() {
		if p := recover(); p != nil {
			tx, err = nil, fmt.Errorf("BEEF parse panicked: %v", p)
		}
	}()
	tx, err = transaction.NewTransactionFromBEEF(beef)
	if err == nil && tx == nil {
		err = errors.New("BEEF has no subject")
	}
	return tx, err
}
