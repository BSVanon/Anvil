package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/envelope"
	anvilgossip "github.com/BSVanon/Anvil/internal/gossip"
	"github.com/BSVanon/Anvil/internal/headers"
	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	anvilwallet "github.com/BSVanon/Anvil/internal/wallet"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
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

	// Phase 5: Data envelope store
	envDir := filepath.Join(cfg.Node.DataDir, "envelopes")
	envStore, err := envelope.NewStore(envDir, cfg.Envelopes.MaxEphemeralTTL, cfg.Envelopes.MaxDurableSize)
	if err != nil {
		log.Fatalf("envelope store: %v", err)
	}
	defer envStore.Close()
	log.Printf("envelope store opened (max TTL=%ds, max durable=%d bytes)", cfg.Envelopes.MaxEphemeralTTL, cfg.Envelopes.MaxDurableSize)

	// Periodic ephemeral envelope sweeper
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if n := envStore.ExpireEphemeral(); n > 0 {
				logger.Info("expired ephemeral envelopes", "count", n)
			}
		}
	}()

	// Phase 6: Overlay directory
	var overlayDir *anviloverlay.Directory
	if cfg.Overlay.Enabled {
		ovDir := filepath.Join(cfg.Node.DataDir, "overlay")
		var err error
		overlayDir, err = anviloverlay.NewDirectory(ovDir)
		if err != nil {
			log.Fatalf("overlay directory: %v", err)
		}
		defer overlayDir.Close()
		log.Printf("overlay directory opened (topics=%v)", cfg.Overlay.Topics)

		// Local bootstrap: register our own SHIP tokens (dev/operator convenience)
		if cfg.Identity.WIF != "" {
			identityKey, err := ec.PrivateKeyFromWif(cfg.Identity.WIF)
			if err != nil {
				log.Printf("overlay bootstrap: invalid WIF: %v", err)
			} else {
				domain := cfg.Node.Listen
				anviloverlay.Bootstrap(overlayDir, identityKey, domain, cfg.Overlay.Topics, logger)
			}
		}

		// Live discovery: JungleBus subscription for real-time SHIP/SLAP detection
		if cfg.JungleBus.Enabled {
			discoverer := anviloverlay.NewDiscoverer(overlayDir, logger)
			for _, sub := range cfg.JungleBus.Subscriptions {
				jbSub, err := anviloverlay.NewJungleBusSubscriber(
					cfg.JungleBus.URL,
					sub.ID,
					uint64(sub.FromBlock),
					discoverer,
					logger,
				)
				if err != nil {
					log.Printf("junglebus subscription %q failed: %v", sub.Name, err)
					continue
				}
				go func(name string) {
					if err := jbSub.Start(context.Background()); err != nil {
						logger.Error("junglebus subscription stopped", "name", name, "error", err)
					}
				}(sub.Name)
				log.Printf("junglebus: subscribed %q from block %d", sub.Name, sub.FromBlock)
			}
		}
	}

	// REST API
	validator := spv.NewValidator(headerStore)
	srv := api.NewServer(headerStore, proofStore, envStore, overlayDir, validator, broadcaster, cfg.API.AuthToken, logger)

	// Phase 5.5: Node wallet (optional — requires identity WIF)
	if cfg.Identity.WIF != "" {
		walletDir := filepath.Join(cfg.Node.DataDir, "wallet")
		nw, err := anvilwallet.New(cfg.Identity.WIF, walletDir, headerStore, proofStore, broadcaster, logger)
		if err != nil {
			log.Printf("wallet init failed (non-fatal): %v", err)
		} else {
			defer nw.Close()
			nw.RegisterRoutes(srv.Mux(), srv.RequireAuth)
			log.Printf("wallet initialized")
		}
	}

	go func() {
		log.Printf("REST API listening on %s", cfg.Node.APIListen)
		if err := http.ListenAndServe(cfg.Node.APIListen, srv.Handler()); err != nil {
			log.Fatalf("api server: %v", err)
		}
	}()

	// Phase 4: Gossip mesh — uses go-sdk auth.Peer for authenticated WebSocket peering
	var gossipMgr *anvilgossip.Manager
	if len(cfg.Forge.Seeds) > 0 || cfg.Node.Listen != "" {
		gossipMgr = anvilgossip.NewManager(anvilgossip.ManagerConfig{
			Store:          envStore,
			Logger:         logger,
			LocalInterests: cfg.Overlay.Topics,
			MaxSeen:        10000,
			OnEnvelope: func(env *envelope.Envelope) {
				logger.Info("mesh envelope received", "topic", env.Topic, "from", env.Pubkey[:16])
			},
		})
		defer gossipMgr.Stop()

		// Connect to seed peers
		for _, seed := range cfg.Forge.Seeds {
			go func(endpoint string) {
				if err := gossipMgr.ConnectPeer(context.Background(), endpoint); err != nil {
					logger.Warn("forge peer failed", "endpoint", endpoint, "error", err)
				}
			}(seed)
		}
		log.Printf("forge mesh: connecting to %d seed peers", len(cfg.Forge.Seeds))

		// Wire broadcaster to forward txs to mesh peers
		broadcaster.SetGossipForwarder(func(txid, rawHex string) {
			if gossipMgr.PeerCount() > 0 {
				logger.Debug("forwarding tx to mesh", "txid", txid[:16], "peers", gossipMgr.PeerCount())
			}
		})
	}

	// Block until signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Println()
	log.Printf("received %v, shutting down", s)
}

