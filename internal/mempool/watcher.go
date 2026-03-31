// Package mempool — address watcher.
//
// The Watcher monitors incoming mempool transactions for outputs matching a
// set of watched addresses. When a match is found, a WatchHit is emitted to
// all registered subscribers via a fan-out hub (SSE-ready).
//
// Features:
//   - P2PKH output matching (hash160 set lookup, O(1))
//   - Input spend detection (tracks when watched UTXOs get spent)
//   - Persistent hit storage (LevelDB) — survives restarts
//   - Fan-out hub for SSE subscribers (per-address or all)
package mempool

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// LevelDB key prefixes for watch data.
var (
	prefixUTXO = []byte("wu:") // wu:<address>:<txid>:<vout> → WatchHit JSON
)

// WatchHit represents a matching transaction output for a watched address.
type WatchHit struct {
	TxID      string `json:"txid"`
	Vout      int    `json:"vout"`
	Address   string `json:"address"`
	Satoshis  int64  `json:"satoshis"`
	ScriptHex string `json:"script_hex"`
	Timestamp int64  `json:"timestamp"`
	Spent     bool   `json:"spent,omitempty"`
	SpentBy   string `json:"spent_by,omitempty"`
}

// Watcher holds a set of watched addresses and matches incoming transactions.
type Watcher struct {
	mu      sync.RWMutex
	watches map[[20]byte]string // hash160 → original address string

	// In-memory UTXO set for spend detection: "txid:vout" → address
	utxoMu sync.RWMutex
	utxos  map[string]string

	// Fan-out hub for watch hits
	subMu sync.RWMutex
	subs  map[string]map[chan WatchHit]struct{} // address → subscriber channels
	allCh map[chan WatchHit]struct{}             // subscribers for all addresses

	db     *leveldb.DB // nil = no persistence
	hits   atomic.Int64
	spends atomic.Int64
	logger *slog.Logger
}

// NewWatcher creates an empty address watcher. Pass a LevelDB instance for
// persistent storage, or nil for in-memory only.
func NewWatcher(db *leveldb.DB, logger *slog.Logger) *Watcher {
	w := &Watcher{
		watches: make(map[[20]byte]string),
		utxos:   make(map[string]string),
		subs:    make(map[string]map[chan WatchHit]struct{}),
		allCh:   make(map[chan WatchHit]struct{}),
		db:      db,
		logger:  logger,
	}
	if db != nil {
		w.loadUTXOs()
	}
	return w
}

// Add registers an address for watching.
func (w *Watcher) Add(address string) error {
	addr, err := script.NewAddressFromString(address)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", address, err)
	}
	pkh := addr.PublicKeyHash
	if len(pkh) != 20 {
		return fmt.Errorf("invalid hash160 length for %q: got %d", address, len(pkh))
	}
	var key [20]byte
	copy(key[:], pkh)

	w.mu.Lock()
	w.watches[key] = address
	w.mu.Unlock()
	return nil
}

// Remove unregisters an address from watching.
func (w *Watcher) Remove(address string) {
	addr, err := script.NewAddressFromString(address)
	if err != nil {
		return
	}
	pkh := addr.PublicKeyHash
	if len(pkh) != 20 {
		return
	}
	var key [20]byte
	copy(key[:], pkh)

	w.mu.Lock()
	delete(w.watches, key)
	w.mu.Unlock()
}

// List returns all currently watched addresses.
func (w *Watcher) List() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]string, 0, len(w.watches))
	for _, addr := range w.watches {
		out = append(out, addr)
	}
	return out
}

// Count returns the number of watched addresses.
func (w *Watcher) Count() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.watches)
}

// Hits returns the total number of watch hits since startup.
func (w *Watcher) Hits() int64 { return w.hits.Load() }

// Spends returns the total number of spend detections since startup.
func (w *Watcher) Spends() int64 { return w.spends.Load() }

// Subscribe registers a channel for watch hits on a specific address.
// Pass "" to receive hits for all addresses. Returns an unsubscribe function.
func (w *Watcher) Subscribe(address string, ch chan WatchHit) func() {
	w.subMu.Lock()
	defer w.subMu.Unlock()

	if address == "" {
		w.allCh[ch] = struct{}{}
		return func() {
			w.subMu.Lock()
			delete(w.allCh, ch)
			w.subMu.Unlock()
		}
	}

	if w.subs[address] == nil {
		w.subs[address] = make(map[chan WatchHit]struct{})
	}
	w.subs[address][ch] = struct{}{}
	return func() {
		w.subMu.Lock()
		delete(w.subs[address], ch)
		if len(w.subs[address]) == 0 {
			delete(w.subs, address)
		}
		w.subMu.Unlock()
	}
}

// History returns persisted watch hits for an address (newest first, up to limit).
// Sorted by timestamp descending — LevelDB iteration is lexicographic by txid,
// so we sort explicitly after retrieval.
func (w *Watcher) History(address string, limit int) []WatchHit {
	if w.db == nil {
		return nil
	}
	prefix := append(prefixUTXO, []byte(address+":")...)
	iter := w.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()

	var hits []WatchHit
	for iter.Next() {
		var hit WatchHit
		if json.Unmarshal(iter.Value(), &hit) == nil {
			hits = append(hits, hit)
		}
	}
	// Sort by timestamp descending (newest first)
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].Timestamp > hits[j].Timestamp
	})
	if limit > 0 && len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}

// notify fans out a hit to relevant subscribers. Non-blocking.
func (w *Watcher) notify(hit WatchHit) {
	w.subMu.RLock()
	defer w.subMu.RUnlock()

	for ch := range w.subs[hit.Address] {
		select {
		case ch <- hit:
		default:
		}
	}
	for ch := range w.allCh {
		select {
		case ch <- hit:
		default:
		}
	}
}

// CheckTx parses a raw transaction and checks outputs against watched addresses,
// then checks inputs for spends of previously seen UTXOs.
func (w *Watcher) CheckTx(txHash chainhash.Hash, raw []byte) {
	w.mu.RLock()
	n := len(w.watches)
	w.mu.RUnlock()

	w.utxoMu.RLock()
	nUtxos := len(w.utxos)
	w.utxoMu.RUnlock()

	if n == 0 && nUtxos == 0 {
		return
	}

	tx := wire.NewMsgTx(1)
	if err := tx.Bsvdecode(bytes.NewReader(raw), wire.ProtocolVersion, wire.BaseEncoding); err != nil {
		return
	}

	txid := txHash.String()
	now := time.Now().Unix()

	// Check outputs — any paying to watched addresses?
	for vout, out := range tx.TxOut {
		h160 := extractP2PKHHash160(out.PkScript)
		if h160 == nil {
			continue
		}
		var key [20]byte
		copy(key[:], h160)

		w.mu.RLock()
		addr, ok := w.watches[key]
		w.mu.RUnlock()
		if !ok {
			continue
		}

		hit := WatchHit{
			TxID:      txid,
			Vout:      vout,
			Address:   addr,
			Satoshis:  out.Value,
			ScriptHex: hex.EncodeToString(out.PkScript),
			Timestamp: now,
		}
		w.hits.Add(1)
		w.logger.Info("watch hit", "address", addr, "txid", txid, "vout", vout, "sats", out.Value)

		// Track UTXO for spend detection
		utxoKey := fmt.Sprintf("%s:%d", txid, vout)
		w.utxoMu.Lock()
		w.utxos[utxoKey] = addr
		w.utxoMu.Unlock()

		w.persist(hit)
		w.notify(hit)
	}

	// Check inputs — any spending tracked UTXOs?
	for _, in := range tx.TxIn {
		prevTxid := in.PreviousOutPoint.Hash.String()
		prevVout := in.PreviousOutPoint.Index
		utxoKey := fmt.Sprintf("%s:%d", prevTxid, prevVout)

		w.utxoMu.RLock()
		addr, tracked := w.utxos[utxoKey]
		w.utxoMu.RUnlock()
		if !tracked {
			continue
		}

		w.spends.Add(1)
		w.logger.Info("watch spend", "address", addr, "spent_utxo", utxoKey, "spent_by", txid)

		// Remove from tracking
		w.utxoMu.Lock()
		delete(w.utxos, utxoKey)
		w.utxoMu.Unlock()

		// Emit spend as a hit with Spent=true
		spendHit := WatchHit{
			TxID:      prevTxid,
			Vout:      int(prevVout),
			Address:   addr,
			Timestamp: now,
			Spent:     true,
			SpentBy:   txid,
		}
		w.persistSpend(spendHit)
		w.notify(spendHit)
	}
}

// persist stores a watch hit in LevelDB.
func (w *Watcher) persist(hit WatchHit) {
	if w.db == nil {
		return
	}
	key := fmt.Sprintf("%s%s:%s:%d", prefixUTXO, hit.Address, hit.TxID, hit.Vout)
	data, err := json.Marshal(hit)
	if err != nil {
		return
	}
	_ = w.db.Put([]byte(key), data, nil) // best-effort persist
}

// persistSpend marks a UTXO as spent in LevelDB.
func (w *Watcher) persistSpend(hit WatchHit) {
	if w.db == nil {
		return
	}
	// Update the original UTXO record
	utxoKey := fmt.Sprintf("%s%s:%s:%d", prefixUTXO, hit.Address, hit.TxID, hit.Vout)
	if existing, err := w.db.Get([]byte(utxoKey), nil); err == nil {
		var orig WatchHit
		if json.Unmarshal(existing, &orig) == nil {
			orig.Spent = true
			orig.SpentBy = hit.SpentBy
			if data, err := json.Marshal(orig); err == nil {
				_ = w.db.Put([]byte(utxoKey), data, nil) // best-effort persist
			}
		}
	}
}

// loadUTXOs rebuilds the in-memory UTXO set from LevelDB on startup.
func (w *Watcher) loadUTXOs() {
	iter := w.db.NewIterator(util.BytesPrefix(prefixUTXO), nil)
	defer iter.Release()

	loaded := 0
	for iter.Next() {
		var hit WatchHit
		if json.Unmarshal(iter.Value(), &hit) != nil || hit.Spent {
			continue
		}
		utxoKey := fmt.Sprintf("%s:%d", hit.TxID, hit.Vout)
		w.utxos[utxoKey] = hit.Address
		loaded++
	}
	if loaded > 0 {
		w.logger.Info("watcher loaded UTXOs from disk", "count", loaded)
	}
}

// extractP2PKHHash160 returns the 20-byte hash160 from a standard P2PKH
// locking script, or nil if the script is not P2PKH.
func extractP2PKHHash160(pkScript []byte) []byte {
	if len(pkScript) == 25 &&
		pkScript[0] == 0x76 && // OP_DUP
		pkScript[1] == 0xa9 && // OP_HASH160
		pkScript[2] == 0x14 && // push 20 bytes
		pkScript[23] == 0x88 && // OP_EQUALVERIFY
		pkScript[24] == 0xac { // OP_CHECKSIG
		return pkScript[3:23]
	}
	return nil
}
