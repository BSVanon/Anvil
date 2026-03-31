package p2p

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

// TxFetcher fetches raw transactions directly from BSV P2P peers,
// eliminating dependency on external APIs like WhatsOnChain.
// Falls back gracefully — callers should wrap with WoC fallback.
type TxFetcher struct {
	addresses []string
	network   wire.BitcoinNet
	logger    *slog.Logger
	timeout   time.Duration
	mu        sync.Mutex
	peer      *Peer // reusable connection
}

// NewTxFetcher creates a fetcher that connects to BSV P2P nodes.
func NewTxFetcher(addresses []string, logger *slog.Logger) *TxFetcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &TxFetcher{
		addresses: addresses,
		network:   wire.MainNet,
		logger:    logger,
		timeout:   30 * time.Second,
	}
}

// FetchRawTx fetches a transaction by txid and returns the raw hex.
// Tries P2P first with each configured peer. Returns error if all fail.
func (f *TxFetcher) FetchRawTx(txid string) (string, error) {
	hash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return "", fmt.Errorf("invalid txid: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Try existing connection first
	if f.peer != nil {
		rawHex, err := f.fetchFromPeer(f.peer, hash)
		if err == nil {
			return rawHex, nil
		}
		f.logger.Debug("p2p tx fetch failed on existing peer, reconnecting", "error", err)
		_ = f.peer.Close()
		f.peer = nil
	}

	// Try each address
	for _, addr := range f.addresses {
		peer, err := Connect(addr, f.network, f.logger)
		if err != nil {
			f.logger.Debug("p2p connect failed", "addr", addr, "error", err)
			continue
		}

		rawHex, err := f.fetchFromPeer(peer, hash)
		if err != nil {
			f.logger.Debug("p2p tx fetch failed", "addr", addr, "error", err)
			_ = peer.Close()
			continue
		}

		// Keep connection for reuse
		f.peer = peer
		return rawHex, nil
	}

	return "", fmt.Errorf("all P2P peers failed for txid %s", txid)
}

// Close closes any open peer connection.
func (f *TxFetcher) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.peer != nil {
		_ = f.peer.Close()
		f.peer = nil
	}
}

func (f *TxFetcher) fetchFromPeer(peer *Peer, hash *chainhash.Hash) (string, error) {
	if err := peer.RequestTransaction(hash); err != nil {
		return "", fmt.Errorf("request: %w", err)
	}

	tx, err := peer.ReadTransaction(hash)
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}

	// Serialize to raw hex
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", fmt.Errorf("serialize: %w", err)
	}

	return hex.EncodeToString(buf.Bytes()), nil
}
