package gossip

// TX relay handlers for mesh transaction propagation.
// Follows the announce/request/response pattern:
//   1. Node receives tx (API, mempool monitor, or peer) → announces txid to mesh
//   2. Peers that don't have it request the full tx
//   3. Sender responds with raw tx hex
//   4. Receiver stores in local mempool, re-announces to its peers

import (
	"context"
	"encoding/hex"
	"encoding/json"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// onTxAnnounce handles an incoming transaction announcement.
// If we don't have this txid, request the full tx from the sender.
func (m *Manager) onTxAnnounce(senderPKHex string, senderPK *ec.PublicKey, raw json.RawMessage) error {
	var ann TxAnnouncePayload
	if err := json.Unmarshal(raw, &ann); err != nil {
		return nil
	}
	if len(ann.TxID) != 64 {
		return nil
	}

	// Dedup: have we already seen this txid?
	seenKey := "tx:" + ann.TxID
	m.seenMu.Lock()
	if _, seen := m.seen[seenKey]; seen {
		m.seenMu.Unlock()
		return nil
	}
	m.seen[seenKey] = struct{}{}
	m.seenMu.Unlock()

	// Check if we already have the tx in our mempool
	if m.txMempool != nil && m.txMempool.Has(ann.TxID) {
		return nil
	}

	// Request the full tx from the sender
	payload, err := Encode(MsgTxRequest, TxRequestPayload{TxID: ann.TxID})
	if err != nil {
		return nil
	}

	m.mu.RLock()
	peer, ok := m.peers[senderPKHex]
	m.mu.RUnlock()
	if ok && peer.Peer != nil {
		_ = peer.Peer.ToPeer(context.Background(), payload, senderPK, 5000)
	}

	return nil
}

// onTxRequest handles a request for a full transaction.
// Responds with the raw tx hex if we have it in our mempool.
func (m *Manager) onTxRequest(senderPKHex string, senderPK *ec.PublicKey, raw json.RawMessage) error {
	var req TxRequestPayload
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil
	}
	if len(req.TxID) != 64 {
		return nil
	}

	// Look up in our mempool
	if m.txMempool == nil {
		return nil
	}
	rawTx := m.txMempool.Get(req.TxID)
	if rawTx == nil {
		return nil // don't have it
	}

	// Respond with the full tx
	payload, err := Encode(MsgTxResponse, TxResponsePayload{
		TxID:   req.TxID,
		RawHex: hex.EncodeToString(rawTx),
	})
	if err != nil {
		return nil
	}

	m.mu.RLock()
	peer, ok := m.peers[senderPKHex]
	m.mu.RUnlock()
	if ok && peer.Peer != nil {
		_ = peer.Peer.ToPeer(context.Background(), payload, senderPK, 5000)
	}

	return nil
}

// onTxResponse handles a received full transaction.
// Adds to local mempool and re-announces to other peers.
func (m *Manager) onTxResponse(senderPKHex string, raw json.RawMessage) error {
	var resp TxResponsePayload
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil
	}
	if len(resp.TxID) != 64 || resp.RawHex == "" {
		return nil
	}

	rawTx, err := hex.DecodeString(resp.RawHex)
	if err != nil {
		return nil
	}

	// Store in local mempool
	if m.txMempool != nil {
		if !m.txMempool.Add(resp.TxID, rawTx) {
			return nil // already had it
		}
	}

	m.logger.Info("mesh tx received", "txid", resp.TxID[:16]+"...", "size", len(rawTx), "from", truncate(senderPKHex))

	// Call the onTx callback if registered (feeds into address watcher, etc.)
	if m.onTxCallback != nil {
		m.onTxCallback(resp.TxID, rawTx)
	}

	// Re-announce to other peers (flood-fill)
	m.AnnounceTx(resp.TxID, len(rawTx), senderPKHex)

	return nil
}

// AnnounceTx announces a txid to all mesh peers, excluding the source.
// Called when a tx is received via API, mempool monitor, or another peer.
func (m *Manager) AnnounceTx(txid string, size int, excludePK string) {
	// Mark as seen so we don't re-process our own announcement
	seenKey := "tx:" + txid
	m.seenMu.Lock()
	m.seen[seenKey] = struct{}{}
	m.seenMu.Unlock()

	payload, err := Encode(MsgTxAnnounce, TxAnnouncePayload{
		TxID: txid,
		Size: size,
	})
	if err != nil {
		return
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	for pkHex, peer := range m.peers {
		if pkHex == excludePK {
			continue
		}
		if peer.Peer != nil {
			_ = peer.Peer.ToPeer(context.Background(), payload, peer.IdentityPK, 5000)
		}
	}
}

// TxRelayStats returns transaction relay counters.
func (m *Manager) TxRelayStats() map[string]interface{} {
	stats := map[string]interface{}{
		"tx_relay_enabled": m.txMempool != nil,
	}
	if m.txMempool != nil {
		stats["tx_mempool_size"] = m.txMempool.Count()
	}
	return stats
}

// Mempool is the interface the TX relay needs from the local mempool.
type Mempool interface {
	Has(txid string) bool
	Get(txid string) []byte
	Add(txid string, raw []byte) bool
	Count() int
}

// OnTxCallback is called when a new transaction is received via the mesh.
type OnTxCallback func(txid string, rawTx []byte)

// TxRelayMempool wraps txrelay.Mempool to satisfy the gossip.Mempool interface.
type TxRelayMempool struct {
	inner interface {
		Has(string) bool
		Get(string) ([]byte, bool)
		Add(string, []byte) error
		Count() int
	}
}

// NewTxRelayMempool creates a gossip.Mempool adapter for txrelay.Mempool.
func NewTxRelayMempool(m interface {
	Has(string) bool
	Get(string) ([]byte, bool)
	Add(string, []byte) error
	Count() int
}) *TxRelayMempool {
	return &TxRelayMempool{inner: m}
}

func (a *TxRelayMempool) Has(txid string) bool { return a.inner.Has(txid) }
func (a *TxRelayMempool) Get(txid string) []byte {
	raw, _ := a.inner.Get(txid)
	return raw
}
func (a *TxRelayMempool) Add(txid string, raw []byte) bool {
	return a.inner.Add(txid, raw) == nil // true = new, false = duplicate
}
func (a *TxRelayMempool) Count() int { return a.inner.Count() }
