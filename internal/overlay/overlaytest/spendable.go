// Package overlaytest builds real, spendable transactions for tests that
// submit through the overlay engine.
//
// Since go-sdk v1.7, spv.Verify checks every unmined transaction the way a
// node checks it before mining it. The transaction must have inputs, spend
// outputs that exist, satisfy their locking scripts and pay out no more than
// it spends. Engine fixtures therefore can no longer be input-less. This
// package mints one deterministic funding transaction, mined in block 1 of a
// headers test store, and builds transactions that spend its OP_TRUE output.
//
// It is test support: import it only from _test.go files, never from
// production code.
package overlaytest

import (
	"testing"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	p2pchainhash "github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

// FundingHeight is the block height at which FundingTx is mined: the first
// block after genesis in a fresh headers test store.
const FundingHeight uint32 = 1

// FundingSatoshis is the value of FundingTx's single OP_TRUE output. Each
// spending transaction pays its outputs from it and leaves the rest as fee.
const FundingSatoshis uint64 = 100_000

// fundingPrevOutpoint is the fixed, non-null outpoint FundingTx spends. Its
// value only has to be stable and non-null. FundingTx is proven mined by its
// BUMP, so spv.Verify never walks past it to that outpoint's transaction.
var fundingPrevOutpoint = chainhash.DoubleHashH([]byte("anvil overlaytest funding outpoint"))

// FundingTx returns a fresh copy of the deterministic funding transaction.
// It has one input spending a fixed non-null outpoint, one OP_TRUE output
// worth FundingSatoshis, and a single-leaf BUMP at FundingHeight. A
// single-leaf BUMP describes a block holding only this transaction, so its
// merkle root is the txid itself. SeedFundingBlock stores a header with that
// root, which makes a headers store, acting as the chain tracker, accept the
// BUMP.
func FundingTx() *transaction.Transaction {
	prev := fundingPrevOutpoint
	unlock := script.Script{}
	lock := script.Script{script.OpTRUE}
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &prev,
		SourceTxOutIndex: 0,
		UnlockingScript:  &unlock,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	})
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: FundingSatoshis})
	isTxid := true
	tx.MerklePath = transaction.NewMerklePath(FundingHeight, [][]*transaction.PathElement{
		{{Offset: 0, Hash: tx.TxID(), Txid: &isTxid}},
	})
	return tx
}

// SeedFundingBlock appends a header at FundingHeight whose merkle root is
// FundingTx's txid, so that store accepts FundingTx's BUMP. store must be a
// fresh headers test store (headers.NewTestStore, PoW checks off) still at
// the genesis tip.
func SeedFundingBlock(t testing.TB, store *headers.Store) {
	t.Helper()
	if tip := store.Tip(); tip != FundingHeight-1 {
		t.Fatalf("overlaytest: headers store tip is %d, want %d (a fresh test store)", tip, FundingHeight-1)
	}
	genesis, err := store.HashAtHeight(0)
	if err != nil {
		t.Fatalf("overlaytest: genesis hash: %v", err)
	}
	root := p2pchainhash.Hash(*FundingTx().TxID())
	hdr := wire.NewBlockHeader(1, genesis, &root, 0x1d00ffff, 0)
	if err := store.AddHeaders(FundingHeight, []*wire.BlockHeader{hdr}); err != nil {
		t.Fatalf("overlaytest: seed funding block: %v", err)
	}
}

// SpendingTx returns an unmined transaction that spends FundingTx's OP_TRUE
// output with an empty unlocking script and pays the given outputs. The input
// carries its source transaction, so a BEEF built from the result includes
// FundingTx and its BUMP. The outputs must total at most FundingSatoshis; the
// remainder is the fee.
//
// The result is deterministic: the same outputs always produce the same
// txid. Every result spends the same funding outpoint. The overlay engine
// only tracks outputs it admits to a topic, so repeated spends of the
// unadmitted funding output do not conflict.
func SpendingTx(t testing.TB, outputs ...*transaction.TransactionOutput) *transaction.Transaction {
	t.Helper()
	if len(outputs) == 0 {
		t.Fatal("overlaytest: SpendingTx needs at least one output")
	}
	unlock := script.Script{}
	tx := transaction.NewTransaction()
	tx.AddInputFromTx(FundingTx(), 0, nil)
	tx.Inputs[0].UnlockingScript = &unlock
	var total uint64
	for _, out := range outputs {
		total += out.Satoshis
		tx.AddOutput(out)
	}
	if total > FundingSatoshis {
		t.Fatalf("overlaytest: outputs total %d sats, more than the %d-sat funding output", total, FundingSatoshis)
	}
	return tx
}
