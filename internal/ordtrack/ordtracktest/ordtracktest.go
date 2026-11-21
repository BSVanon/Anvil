// Package ordtracktest builds what tests of ordinal version tracking need:
// signed P2PKH spends, inscription outputs, transactions mined into a
// header view that knows only the blocks a test mines, and an in-memory
// transaction source over them.
//
// It is test support: import it only from _test.go files, never from
// production code.
package ordtracktest

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// Wallet signs spends of the P2PKH outputs it locks.
type Wallet struct {
	key  *ec.PrivateKey
	lock *script.Script
	seed atomic.Uint64
}

// NewWallet returns a wallet with a fresh key.
func NewWallet(tb testing.TB) *Wallet {
	tb.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		tb.Fatal(err)
	}
	addr, err := script.NewAddressFromPublicKey(key.PubKey(), true)
	if err != nil {
		tb.Fatal(err)
	}
	lock, err := p2pkh.Lock(addr)
	if err != nil {
		tb.Fatal(err)
	}
	return &Wallet{key: key, lock: lock}
}

// Lock is the wallet's P2PKH locking script.
func (w *Wallet) Lock() *script.Script { return w.lock }

// Inscription is a BRC-160 envelope of contentType and body, followed by
// the wallet's lock.
func (w *Wallet) Inscription(contentType string, body []byte) *script.Script {
	s := &script.Script{}
	_ = s.AppendOpcodes(script.Op0, script.OpIF)
	_ = s.AppendPushData([]byte("ord"))
	_ = s.AppendOpcodes(script.Op1)
	_ = s.AppendPushData([]byte(contentType))
	_ = s.AppendOpcodes(script.Op0)
	_ = s.AppendPushData(body)
	_ = s.AppendOpcodes(script.OpENDIF)
	out := append(script.Script{}, *s...)
	out = append(out, *w.lock...)
	return &out
}

// Out is one output: Sats paid to Script, or to the wallet's lock when
// Script is nil.
type Out struct {
	Sats   uint64
	Script *script.Script
}

// In names output Vout of Tx.
type In struct {
	Tx   *transaction.Transaction
	Vout uint32
}

// Fund returns a transaction paying outs from a made-up outpoint no test
// carries: spendable only once mined.
func (w *Wallet) Fund(outs ...Out) *transaction.Transaction {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], w.seed.Add(1))
	prev := chainhash.DoubleHashH(append(append([]byte("ordtracktest fund"), w.lock.Bytes()...), b[:]...))
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID: &prev, UnlockingScript: &script.Script{}, SequenceNumber: transaction.DefaultSequenceNumber,
	})
	w.addOutputs(tx, outs)
	return tx
}

// Spend returns a transaction spending ins, in order, signed by the
// wallet, and paying outs.
func (w *Wallet) Spend(tb testing.TB, ins []In, outs ...Out) *transaction.Transaction {
	tb.Helper()
	tx := transaction.NewTransaction()
	for _, in := range ins {
		unlock, err := p2pkh.Unlock(w.key, nil)
		if err != nil {
			tb.Fatal(err)
		}
		tx.AddInputFromTx(in.Tx, in.Vout, unlock)
	}
	w.addOutputs(tx, outs)
	if err := tx.Sign(); err != nil {
		tb.Fatal(err)
	}
	return tx
}

func (w *Wallet) addOutputs(tx *transaction.Transaction, outs []Out) {
	for _, o := range outs {
		lock := o.Script
		if lock == nil {
			lock = w.lock
		}
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: o.Sats, LockingScript: lock})
	}
}

// Chain is a header view holding only the blocks Mine adds, each holding
// one transaction, which is therefore its block's merkle root.
type Chain struct {
	mu     sync.Mutex
	roots  map[uint32]chainhash.Hash
	height uint32
}

// NewChain returns a view whose next block is at height 900,000.
func NewChain() *Chain { return &Chain{roots: map[uint32]chainhash.Hash{}, height: 899_999} }

// Mine puts each tx in a new block of its own and sets its merkle path.
func (c *Chain) Mine(txs ...*transaction.Transaction) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, tx := range txs {
		c.height++
		yes := true
		id := tx.TxID()
		tx.MerklePath = transaction.NewMerklePath(c.height, [][]*transaction.PathElement{{{Offset: 0, Hash: id, Txid: &yes}}})
		c.roots[c.height] = *id
	}
}

// IsValidRootForHeight implements chaintracker.ChainTracker.
func (c *Chain) IsValidRootForHeight(_ context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.roots[height]
	return ok && root != nil && r.Equal(*root), nil
}

// CurrentHeight implements chaintracker.ChainTracker.
func (c *Chain) CurrentHeight(context.Context) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.height + 1, nil
}

// Store holds transactions the way a node's fetch path finds them.
type Store struct {
	mu    sync.Mutex
	txs   map[string]*transaction.Transaction
	Calls atomic.Int64 // Tx calls
}

// NewStore returns an empty store.
func NewStore() *Store { return &Store{txs: map[string]*transaction.Transaction{}} }

// Add makes txs fetchable.
func (s *Store) Add(txs ...*transaction.Transaction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tx := range txs {
		s.txs[tx.TxID().String()] = tx
	}
}

// Tx returns a fresh parse of txid's bytes, carrying its merkle path when
// it has one, as a fetch would.
func (s *Store) Tx(_ context.Context, txid string) (*transaction.Transaction, error) {
	s.Calls.Add(1)
	s.mu.Lock()
	tx := s.txs[txid]
	s.mu.Unlock()
	if tx == nil {
		return nil, fmt.Errorf("%s not found", txid)
	}
	out, err := transaction.NewTransactionFromBytes(tx.Bytes())
	if err != nil {
		return nil, err
	}
	out.MerklePath = tx.MerklePath
	return out, nil
}

// Mined reports whether txid is held and mined, and its height.
func (s *Store) Mined(txid string) (known, mined bool, height uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx := s.txs[txid]
	if tx == nil {
		return false, false, 0
	}
	if tx.MerklePath == nil {
		return true, false, 0
	}
	return true, true, tx.MerklePath.BlockHeight
}

// AtomicBEEF is tx's Atomic BEEF, its unmined ancestry carried whole.
func AtomicBEEF(tb testing.TB, tx *transaction.Transaction) []byte {
	tb.Helper()
	b, err := tx.AtomicBEEF(false)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}
