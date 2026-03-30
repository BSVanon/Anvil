package mempool

import (
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
	"github.com/syndtr/goleveldb/leveldb"
)

// buildTestTx creates a minimal serialized tx with one P2PKH output
// paying to the given hash160 (20 bytes).
func buildTestTx(hash160 [20]byte, satoshis int64) (chainhash.Hash, []byte) {
	tx := wire.NewMsgTx(1)
	// Add a dummy input
	prevHash := chainhash.Hash{}
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevHash, 0), nil))
	// P2PKH output: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
	script := make([]byte, 25)
	script[0] = 0x76 // OP_DUP
	script[1] = 0xa9 // OP_HASH160
	script[2] = 0x14 // push 20
	copy(script[3:23], hash160[:])
	script[23] = 0x88 // OP_EQUALVERIFY
	script[24] = 0xac // OP_CHECKSIG
	tx.AddTxOut(wire.NewTxOut(satoshis, script))

	var buf []byte
	w := &byteWriter{buf: &buf}
	tx.Serialize(w)

	return tx.TxHash(), buf
}

// buildSpendTx creates a tx that spends the given outpoint.
func buildSpendTx(prevTxid chainhash.Hash, prevVout uint32) (chainhash.Hash, []byte) {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevTxid, prevVout), nil))
	// OP_RETURN output (unspendable)
	tx.AddTxOut(wire.NewTxOut(0, []byte{0x6a}))

	var buf []byte
	w := &byteWriter{buf: &buf}
	tx.Serialize(w)

	return tx.TxHash(), buf
}

type byteWriter struct{ buf *[]byte }

func (w *byteWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

func TestExtractP2PKHHash160(t *testing.T) {
	// Valid P2PKH script
	h160, _ := hex.DecodeString("89abcdefabbaabbaabbaabbaabbaabbaabbaabba")
	script := make([]byte, 25)
	script[0] = 0x76
	script[1] = 0xa9
	script[2] = 0x14
	copy(script[3:23], h160)
	script[23] = 0x88
	script[24] = 0xac

	got := extractP2PKHHash160(script)
	if got == nil {
		t.Fatal("expected hash160, got nil")
	}
	if hex.EncodeToString(got) != hex.EncodeToString(h160) {
		t.Fatalf("hash160 mismatch: got %x, want %x", got, h160)
	}

	// Non-P2PKH
	if extractP2PKHHash160([]byte{0x6a, 0x04, 0xde, 0xad}) != nil {
		t.Fatal("expected nil for OP_RETURN script")
	}
}

func TestWatcherAddRemoveList(t *testing.T) {
	w := NewWatcher(nil, slog.Default())

	// Use a well-known BSV address (Satoshi's genesis address)
	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	if err := w.Add(addr); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if w.Count() != 1 {
		t.Fatalf("expected 1, got %d", w.Count())
	}

	list := w.List()
	if len(list) != 1 || list[0] != addr {
		t.Fatalf("List mismatch: %v", list)
	}

	w.Remove(addr)
	if w.Count() != 0 {
		t.Fatalf("expected 0 after remove, got %d", w.Count())
	}
}

func TestWatcherInvalidAddress(t *testing.T) {
	w := NewWatcher(nil, slog.Default())
	if err := w.Add("not-a-valid-address"); err == nil {
		t.Fatal("expected error for invalid address")
	}
}

func TestWatcherCheckTxMatch(t *testing.T) {
	w := NewWatcher(nil, slog.Default())

	// Watch a known address — derive hash160 from it
	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	if err := w.Add(addr); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Get the hash160 for this address from our watch map
	var h160 [20]byte
	w.mu.RLock()
	for k := range w.watches {
		h160 = k
		break
	}
	w.mu.RUnlock()

	// Subscribe
	ch := make(chan WatchHit, 4)
	unsub := w.Subscribe(addr, ch)
	defer unsub()

	// Build and check a matching tx
	txHash, raw := buildTestTx(h160, 50000)
	w.CheckTx(txHash, raw)

	select {
	case hit := <-ch:
		if hit.Address != addr {
			t.Fatalf("address mismatch: got %s, want %s", hit.Address, addr)
		}
		if hit.Satoshis != 50000 {
			t.Fatalf("satoshis mismatch: got %d, want 50000", hit.Satoshis)
		}
		if hit.Vout != 0 {
			t.Fatalf("vout mismatch: got %d, want 0", hit.Vout)
		}
		if hit.Spent {
			t.Fatal("should not be marked spent")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for watch hit")
	}

	if w.Hits() != 1 {
		t.Fatalf("expected 1 hit, got %d", w.Hits())
	}
}

func TestWatcherCheckTxNoMatch(t *testing.T) {
	w := NewWatcher(nil, slog.Default())

	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	if err := w.Add(addr); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Build tx to a different hash160
	var otherH160 [20]byte
	otherH160[0] = 0xFF
	txHash, raw := buildTestTx(otherH160, 10000)

	ch := make(chan WatchHit, 4)
	unsub := w.Subscribe(addr, ch)
	defer unsub()

	w.CheckTx(txHash, raw)

	select {
	case <-ch:
		t.Fatal("should not have received a hit for non-matching address")
	case <-time.After(100 * time.Millisecond):
		// expected
	}

	if w.Hits() != 0 {
		t.Fatalf("expected 0 hits, got %d", w.Hits())
	}
}

func TestWatcherSpendDetection(t *testing.T) {
	w := NewWatcher(nil, slog.Default())

	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	if err := w.Add(addr); err != nil {
		t.Fatalf("Add: %v", err)
	}

	var h160 [20]byte
	w.mu.RLock()
	for k := range w.watches {
		h160 = k
		break
	}
	w.mu.RUnlock()

	// Step 1: receive a UTXO
	recvHash, recvRaw := buildTestTx(h160, 25000)
	w.CheckTx(recvHash, recvRaw)

	if w.Hits() != 1 {
		t.Fatalf("expected 1 hit after receive, got %d", w.Hits())
	}

	// Subscribe for spend notifications
	ch := make(chan WatchHit, 4)
	unsub := w.Subscribe(addr, ch)
	defer unsub()

	// Drain the receive hit if buffered
	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
	}

	// Step 2: spend that UTXO
	spendHash, spendRaw := buildSpendTx(recvHash, 0)
	w.CheckTx(spendHash, spendRaw)

	if w.Spends() != 1 {
		t.Fatalf("expected 1 spend, got %d", w.Spends())
	}

	select {
	case hit := <-ch:
		if !hit.Spent {
			t.Fatal("expected Spent=true")
		}
		if hit.SpentBy != spendHash.String() {
			t.Fatalf("SpentBy mismatch: got %s, want %s", hit.SpentBy, spendHash.String())
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for spend notification")
	}
}

func TestWatcherPersistence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "watchdb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	w := NewWatcher(db, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	if err := w.Add(addr); err != nil {
		t.Fatalf("Add: %v", err)
	}

	var h160 [20]byte
	w.mu.RLock()
	for k := range w.watches {
		h160 = k
		break
	}
	w.mu.RUnlock()

	// Receive a UTXO
	txHash, raw := buildTestTx(h160, 99000)
	w.CheckTx(txHash, raw)

	// Check history
	hits := w.History(addr, 10)
	if len(hits) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(hits))
	}
	if hits[0].Satoshis != 99000 {
		t.Fatalf("satoshis mismatch in history: got %d", hits[0].Satoshis)
	}

	// Close and reopen — UTXOs should reload
	db.Close()
	db2, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer db2.Close()

	w2 := NewWatcher(db2, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	w2.utxoMu.RLock()
	n := len(w2.utxos)
	w2.utxoMu.RUnlock()
	if n != 1 {
		t.Fatalf("expected 1 UTXO loaded from disk, got %d", n)
	}

	// History should survive too
	hits2 := w2.History(addr, 10)
	if len(hits2) != 1 {
		t.Fatalf("expected 1 history entry after reopen, got %d", len(hits2))
	}
}

func TestWatcherHistoryOrderByTimestamp(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "watchdb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	w := NewWatcher(db, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	if err := w.Add(addr); err != nil {
		t.Fatalf("Add: %v", err)
	}

	var h160 [20]byte
	w.mu.RLock()
	for k := range w.watches {
		h160 = k
		break
	}
	w.mu.RUnlock()

	// Insert 3 hits with short sleeps to get different timestamps
	for i := 0; i < 3; i++ {
		h160Copy := h160
		h160Copy[19] = byte(i) // vary the hash slightly to get different txids
		// Use the real h160 for matching, but we need different txids.
		// Simplest: create txs with different satoshi amounts.
		txHash, raw := buildTestTx(h160, int64((i+1)*1000))
		time.Sleep(10 * time.Millisecond) // ensure distinct timestamps at second granularity? No, unix seconds.
		// Force distinct timestamps by manually persisting with different timestamps
		hit := WatchHit{
			TxID:      txHash.String(),
			Vout:      0,
			Address:   addr,
			Satoshis:  int64((i + 1) * 1000),
			Timestamp: int64(1000 + i), // ascending: 1000, 1001, 1002
		}
		_ = raw // we bypass CheckTx to control timestamps
		w.persist(hit)
	}

	hits := w.History(addr, 10)
	if len(hits) != 3 {
		t.Fatalf("expected 3 history entries, got %d", len(hits))
	}
	// Should be newest first: 1002, 1001, 1000
	if hits[0].Timestamp != 1002 || hits[1].Timestamp != 1001 || hits[2].Timestamp != 1000 {
		t.Fatalf("expected newest-first order [1002,1001,1000], got [%d,%d,%d]",
			hits[0].Timestamp, hits[1].Timestamp, hits[2].Timestamp)
	}
}

func TestWatcherSubscribeAll(t *testing.T) {
	w := NewWatcher(nil, slog.Default())

	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	if err := w.Add(addr); err != nil {
		t.Fatalf("Add: %v", err)
	}

	var h160 [20]byte
	w.mu.RLock()
	for k := range w.watches {
		h160 = k
		break
	}
	w.mu.RUnlock()

	// Subscribe to ALL addresses (empty string)
	ch := make(chan WatchHit, 4)
	unsub := w.Subscribe("", ch)
	defer unsub()

	txHash, raw := buildTestTx(h160, 1000)
	w.CheckTx(txHash, raw)

	select {
	case hit := <-ch:
		if hit.Address != addr {
			t.Fatalf("expected %s, got %s", addr, hit.Address)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for all-address subscription hit")
	}
}
