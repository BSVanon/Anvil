package main

import (
	"context"
	"log"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	mempoolpkg "github.com/BSVanon/Anvil/internal/mempool"
	"github.com/BSVanon/Anvil/internal/p2p"
	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
	"github.com/syndtr/goleveldb/leveldb"
)

// mempoolComponents holds the mempool monitoring subsystem.
type mempoolComponents struct {
	index   *mempoolpkg.Index
	watcher *mempoolpkg.Watcher
	monitor *p2p.MempoolMonitor
	watchDB *leveldb.DB
	cancel  context.CancelFunc
}

// setupMempool initialises the P2P mempool monitor, sharded index, and address
// watcher. Returns nil if mempool monitoring is disabled or no BSV nodes are
// configured.
func setupMempool(cfg *config.Config, logger *slog.Logger) *mempoolComponents {
	if !cfg.Mempool.Enabled || len(cfg.BSV.Nodes) == 0 {
		return nil
	}

	idx := mempoolpkg.NewIndex()

	// Open LevelDB for persistent watch hits
	watchDir := filepath.Join(cfg.Node.DataDir, "watch")
	watchDB, err := leveldb.OpenFile(watchDir, nil)
	if err != nil {
		log.Printf("watch store failed (non-fatal, in-memory only): %v", err)
	}
	watcher := mempoolpkg.NewWatcher(watchDB, logger)

	// Build coverage map from config prefixes (or default to first 5 bytes)
	coverage := make(map[byte]struct{})
	if len(cfg.Mempool.Prefixes) > 0 {
		for _, p := range cfg.Mempool.Prefixes {
			if p >= 0 && p <= 255 {
				coverage[byte(p)] = struct{}{}
			}
		}
	} else {
		for i := byte(0); i < 5; i++ {
			coverage[i] = struct{}{}
		}
	}

	monitor := p2p.NewMempoolMonitor(
		cfg.BSV.Nodes[0], wire.MainNet, coverage, cfg.Mempool.MaxTxSize,
		func(txHash chainhash.Hash, raw []byte) {
			var id [32]byte
			copy(id[:], txHash[:])
			idx.Add(id, mempoolpkg.TxMeta{
				FirstSeen: time.Now(),
				Size:      uint32(len(raw)),
			})
			watcher.CheckTx(txHash, raw)
		},
		logger,
	)

	ctx, cancel := context.WithCancel(context.Background())
	if err := monitor.Start(ctx); err != nil {
		cancel()
		log.Printf("mempool monitor failed (non-fatal): %v", err)
		return &mempoolComponents{index: idx, watcher: watcher, watchDB: watchDB}
	}

	log.Printf("mempool monitor: connected to %s, coverage=%d prefixes", cfg.BSV.Nodes[0], len(coverage))

	// Periodic eviction
	ttl := time.Duration(cfg.Mempool.TTLSeconds) * time.Second
	if ttl == 0 {
		ttl = time.Hour
	}
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-ttl)
			if n := idx.ExpireBefore(cutoff); n > 0 {
				logger.Info("mempool evicted expired entries", "count", n)
			}
		}
	}()

	return &mempoolComponents{
		index:   idx,
		watcher: watcher,
		monitor: monitor,
		watchDB: watchDB,
		cancel:  cancel,
	}
}

// Close shuts down the mempool monitor and closes the watch database.
func (mc *mempoolComponents) Close() {
	if mc == nil {
		return
	}
	if mc.cancel != nil {
		mc.cancel()
	}
	if mc.monitor != nil {
		mc.monitor.Stop()
	}
	if mc.watchDB != nil {
		mc.watchDB.Close()
	}
}
