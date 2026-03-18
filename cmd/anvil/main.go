package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/libsv/go-p2p/wire"
)

func main() {
	configPath := flag.String("config", "anvil.toml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	logger := slog.Default()

	log.Printf("anvil node %q starting", cfg.Node.Name)
	log.Printf("  data_dir:   %s", cfg.Node.DataDir)
	log.Printf("  mesh:       %s", cfg.Node.Listen)
	log.Printf("  api:        %s", cfg.Node.APIListen)
	log.Printf("  bsv nodes:  %v", cfg.BSV.Nodes)
	log.Printf("  arc:        enabled=%v", cfg.ARC.Enabled)
	log.Printf("  junglebus:  enabled=%v", cfg.JungleBus.Enabled)
	log.Printf("  overlay:    enabled=%v topics=%v", cfg.Overlay.Enabled, cfg.Overlay.Topics)

	// Phase 2: Header store + sync
	headerDir := filepath.Join(cfg.Node.DataDir, "headers")
	headerStore, err := headers.NewStore(headerDir)
	if err != nil {
		log.Fatalf("header store: %v", err)
	}
	defer headerStore.Close()
	log.Printf("header store opened at height %d", headerStore.Tip())

	syncer := headers.NewSyncer(headerStore, wire.MainNet, logger)
	for _, node := range cfg.BSV.Nodes {
		tip, err := syncer.SyncFrom(node)
		if err != nil {
			log.Printf("header sync from %s failed: %v", node, err)
			continue
		}
		log.Printf("header sync from %s complete, tip=%d", node, tip)
		break
	}

	// Phase 7: SPV proof store
	proofDir := filepath.Join(cfg.Node.DataDir, "proofs")
	proofStore, err := spv.NewProofStore(proofDir)
	if err != nil {
		log.Fatalf("proof store: %v", err)
	}
	defer proofStore.Close()

	// Phase 3: TX relay + broadcast
	mempool := txrelay.NewMempool()
	var arcClient *txrelay.ARCClient
	if cfg.ARC.Enabled {
		arcClient = txrelay.NewARCClient(cfg.ARC.URL, cfg.ARC.APIKey)
		log.Printf("ARC enabled: %s", cfg.ARC.URL)
	}
	broadcaster := txrelay.NewBroadcaster(mempool, arcClient, logger)

	// REST API
	validator := spv.NewValidator(headerStore)
	srv := api.NewServer(headerStore, proofStore, validator, broadcaster, cfg.API.AuthToken, logger)

	go func() {
		log.Printf("REST API listening on %s", cfg.Node.APIListen)
		if err := http.ListenAndServe(cfg.Node.APIListen, srv.Handler()); err != nil {
			log.Fatalf("api server: %v", err)
		}
	}()

	// TODO: Phase 1 — init BRC identity from cfg.Identity.WIF
	// TODO: Phase 4 — start gossip mesh
	// TODO: Phase 5 — init envelope store
	// TODO: Phase 5.5 — init wallet
	// TODO: Phase 6 — start overlay discovery

	// Block until signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Println()
	log.Printf("received %v, shutting down", s)
}
