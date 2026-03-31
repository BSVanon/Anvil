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

// BlockTxFetcher fetches transactions by downloading the containing block via P2P.
// Used when individual tx fetch fails (large ordinal inscriptions not served by APIs).
type BlockTxFetcher struct {
	addresses []string
	network   wire.BitcoinNet
	logger    *slog.Logger
	mu        sync.Mutex

	// blockCache: blockHash -> map[txid]rawHex
	// Once we download a block, we cache ALL its transactions
	blockCache map[string]map[string]string
}

// NewBlockTxFetcher creates a block-based transaction fetcher.
func NewBlockTxFetcher(addresses []string, logger *slog.Logger) *BlockTxFetcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &BlockTxFetcher{
		addresses:  addresses,
		network:    wire.MainNet,
		logger:     logger,
		blockCache: make(map[string]map[string]string),
	}
}

// FetchTxFromBlock fetches a transaction by downloading its containing block.
// blockHash is the hash of the block containing the transaction.
func (f *BlockTxFetcher) FetchTxFromBlock(txid string, blockHashHex string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check cache first — if we already downloaded this block, the tx is there
	if txMap, ok := f.blockCache[blockHashHex]; ok {
		if rawHex, ok := txMap[txid]; ok {
			return rawHex, nil
		}
		return "", fmt.Errorf("tx %s not found in cached block %s", txid, blockHashHex[:16])
	}

	blockHash, err := chainhash.NewHashFromStr(blockHashHex)
	if err != nil {
		return "", fmt.Errorf("invalid block hash: %w", err)
	}

	// Try each peer
	for _, addr := range f.addresses {
		f.logger.Info("fetching block for tx", "txid", txid[:16], "block", blockHashHex[:16], "peer", addr)

		peer, err := Connect(addr, f.network, f.logger)
		if err != nil {
			f.logger.Debug("block fetch connect failed", "addr", addr, "error", err)
			continue
		}

		txMap, err := f.fetchBlock(peer, blockHash)
		_ = peer.Close()

		if err != nil {
			f.logger.Debug("block fetch failed", "addr", addr, "error", err)
			continue
		}

		// Cache the entire block's transactions
		f.blockCache[blockHashHex] = txMap
		// Log a few sample txids for debugging hash format
		sampleCount := 0
		for k := range txMap {
			if sampleCount < 3 {
				f.logger.Info("cached tx sample", "txid", k)
				sampleCount++
			}
		}
		f.logger.Info("block fetched and cached", "block", blockHashHex[:16], "txs", len(txMap))

		// Evict old blocks if cache grows
		if len(f.blockCache) > 50 {
			for k := range f.blockCache {
				if k != blockHashHex {
					delete(f.blockCache, k)
					break
				}
			}
		}

		if rawHex, ok := txMap[txid]; ok {
			return rawHex, nil
		}
		return "", fmt.Errorf("tx %s not found in block %s (%d txs)", txid, blockHashHex[:16], len(txMap))
	}

	return "", fmt.Errorf("all peers failed to serve block %s", blockHashHex[:16])
}

// LookupCachedTx searches all cached blocks for a txid. Returns raw hex if found.
func (f *BlockTxFetcher) LookupCachedTx(txid string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for blockHash, txMap := range f.blockCache {
		if rawHex, ok := txMap[txid]; ok {
			return rawHex, true
		}
		// Try reversed txid — libsv may store in natural byte order
		reversed := reverseHex(txid)
		if rawHex, ok := txMap[reversed]; ok {
			f.logger.Info("found tx with reversed hash", "txid", txid[:16], "block", blockHash[:16])
			return rawHex, true
		}
	}
	return "", false
}

// reverseHex reverses a hex string byte-by-byte (e.g. "aabb" -> "bbaa").
func reverseHex(h string) string {
	return reverseHashHex(h)
}

// reverseHashHex reverses a hex-encoded hash byte-by-byte.
// Converts between natural byte order and display (reversed) order.
func reverseHashHex(h string) string {
	if len(h)%2 != 0 {
		return h
	}
	b := make([]byte, len(h))
	for i := 0; i < len(h); i += 2 {
		b[len(h)-2-i] = h[i]
		b[len(h)-1-i] = h[i+1]
	}
	return string(b)
}

func (f *BlockTxFetcher) fetchBlock(peer *Peer, blockHash *chainhash.Hash) (map[string]string, error) {
	// Request the block
	msg := wire.NewMsgGetData()
	inv := wire.NewInvVect(wire.InvTypeBlock, blockHash)
	if err := msg.AddInvVect(inv); err != nil {
		return nil, err
	}
	if err := peer.writeMsg(msg); err != nil {
		return nil, fmt.Errorf("send getdata: %w", err)
	}

	// Read the block response — use very long timeout for large blocks
	_ = peer.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	for {
		wireMsg, _, err := wire.ReadMessage(peer.conn, protocolVersion, peer.network)
		if err != nil {
			return nil, fmt.Errorf("read block: %w", err)
		}

		switch m := wireMsg.(type) {
		case *wire.MsgBlock:
			// Parse all transactions — store under BOTH natural and reversed txid
			// because libsv uses natural byte order while humans/APIs use reversed
			txMap := make(map[string]string, len(m.Transactions)*2)
			for _, tx := range m.Transactions {
				txHash := tx.TxHash()
				var buf bytes.Buffer
				if err := tx.Serialize(&buf); err != nil {
					continue
				}
				rawHex := hex.EncodeToString(buf.Bytes())
				// Natural order (libsv format)
				natural := txHash.String()
				txMap[natural] = rawHex
				// Reversed order (display/API format)
				reversed := reverseHashHex(natural)
				txMap[reversed] = rawHex
			}
			return txMap, nil

		case *wire.MsgPing:
			pong := wire.NewMsgPong(m.Nonce)
			_ = peer.writeMsg(pong)

		case *wire.MsgNotFound:
			return nil, fmt.Errorf("block not found by peer")

		default:
			f.logger.Debug("block fetch: ignoring", "cmd", wireMsg.Command())
		}
	}
}
