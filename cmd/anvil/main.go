package main

import (
	"context"
	"crypto/tls"
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
	"github.com/BSVanon/Anvil/internal/bond"
	"github.com/BSVanon/Anvil/internal/p2p"
	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/envelope"
	anvilgossip "github.com/BSVanon/Anvil/internal/gossip"
	"github.com/BSVanon/Anvil/internal/headers"
	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	anvilwallet "github.com/BSVanon/Anvil/internal/wallet"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/libsv/go-p2p/wire"
)

func main() {
	// Subcommand routing — deploy, doctor, or run (default)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "deploy":
			cmdDeploy(os.Args[2:])
			return
		case "doctor":
			cmdDoctor(os.Args[2:])
			return
		}
	}

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

	// Phase 5.5: Node wallet (optional — requires identity WIF)
	var identityPubHex string
	if cfg.Identity.WIF != "" {
		if ik, err := ec.PrivateKeyFromWif(cfg.Identity.WIF); err == nil {
			identityPubHex = fmt.Sprintf("%x", ik.PubKey().Compressed())
		}
	}

	var bondCheck *bond.Checker // may be set in mesh block below

	var nodeWallet *anvilwallet.NodeWallet
	if cfg.Identity.WIF != "" {
		walletDir := filepath.Join(cfg.Node.DataDir, "wallet")
		nw, err := anvilwallet.New(cfg.Identity.WIF, walletDir, headerStore, proofStore, broadcaster, arcClient, logger)
		if err != nil {
			log.Printf("wallet init failed (non-fatal): %v", err)
		} else {
			nodeWallet = nw
			defer nodeWallet.Close()
			log.Printf("wallet initialized")
		}
	}

	// Anvil mesh — uses go-sdk auth.Peer for authenticated WebSocket peering.
	// Requires a wallet for authenticated identity: mesh is disabled without identity.wif.
	var gossipMgr *anvilgossip.Manager
	meshWanted := len(cfg.Mesh.Seeds) > 0 || cfg.Node.Listen != ""
	if meshWanted && nodeWallet == nil {
		log.Printf("mesh disabled: identity.wif required for authenticated peering (seeds=%d listen=%q)",
			len(cfg.Mesh.Seeds), cfg.Node.Listen)
	}
	if meshWanted && nodeWallet != nil {
		// Bond checker — if configured, peers must prove a bond UTXO to join the mesh
		if cfg.Mesh.MinBondSats > 0 {
			bondCheck = bond.NewChecker(cfg.Mesh.MinBondSats, cfg.Mesh.BondCheckURL)
			log.Printf("bond required: %d sats minimum for mesh peering", cfg.Mesh.MinBondSats)
		}

		gossipMgr = anvilgossip.NewManager(anvilgossip.ManagerConfig{
			Wallet:         nodeWallet.Wallet(),
			Store:          envStore,
			Logger:         logger,
			LocalInterests: []string{""}, // match all topics — relay everything we store
			MaxSeen:        10000,
			OverlayDir:     overlayDir,
			BondChecker:    bondCheck,
			OnEnvelope: func(env *envelope.Envelope) {
				logger.Info("mesh envelope received", "topic", env.Topic, "from", env.Pubkey[:16])
			},
		})
		defer gossipMgr.Stop()

		// Connect to seed peers with automatic reconnection.
		// Each seed gets a goroutine that reconnects on disconnect (30s retry).
		for _, seed := range cfg.Mesh.Seeds {
			go gossipMgr.ConnectSeedWithReconnect(context.Background(), seed, 30*time.Second)
		}
		if len(cfg.Mesh.Seeds) > 0 {
			log.Printf("anvil mesh: connecting to %d seed peers (auto-reconnect enabled)", len(cfg.Mesh.Seeds))
		}

		// NOTE: TX mesh forwarding is NOT implemented. Envelope gossip works
		// (proven by mesh_e2e_test.go), but raw transaction forwarding across
		// the mesh requires a dedicated wire message type and is deferred.
		// Transactions are local mempool + optional ARC submission only.

		// Inbound mesh listener: accept authenticated WebSocket peers.
		// Uses TLS (wss://) when cert/key are configured — required for production.
		if cfg.Node.Listen != "" {
			go func() {
				handler := gossipMgr.MeshHandler()
				if cfg.API.TLSCert != "" && cfg.API.TLSKey != "" {
					log.Printf("mesh listener on %s (wss, TLS)", cfg.Node.Listen)
					if err := http.ListenAndServeTLS(cfg.Node.Listen, cfg.API.TLSCert, cfg.API.TLSKey, handler); err != nil {
						log.Fatalf("mesh listener: %v", err)
					}
				} else {
					log.Printf("mesh listener on %s (ws, no TLS — dev only)", cfg.Node.Listen)
					if err := http.ListenAndServe(cfg.Node.Listen, handler); err != nil {
						log.Fatalf("mesh listener: %v", err)
					}
				}
			}()
		}
	}

	// x402 payment gating requires both identity.wif (for payee script) and
	// a wallet (for nonce UTXO minting). If either is missing, payment gating
	// is forced off — payment_satoshis is zeroed so no dev-mode gate can leak through.
	paymentSatoshis := cfg.API.PaymentSatoshis
	var payeeScriptHex string
	var nonceProvider api.NonceProvider
	// Create nonce provider whenever wallet exists — needed for app passthrough/split
	// payments even when the node itself charges 0 (payment_satoshis = 0).
	if cfg.Identity.WIF != "" && nodeWallet != nil {
		payeeKey, err := ec.PrivateKeyFromWif(cfg.Identity.WIF)
		if err != nil {
			log.Fatalf("x402: invalid identity WIF: %v", err)
		}
		addr, err := bsvscript.NewAddressFromPublicKey(payeeKey.PubKey(), true)
		if err != nil {
			log.Fatalf("x402: derive address: %v", err)
		}
		lockScript, err := p2pkh.Lock(addr)
		if err != nil {
			log.Fatalf("x402: build locking script: %v", err)
		}
		payeeScriptHex = fmt.Sprintf("%x", []byte(*lockScript))
		walletNonce := api.NewWalletNonceProvider(nodeWallet.Wallet())
		nonceProvider = api.NewUTXONoncePool(walletNonce, 100, logger)
		if paymentSatoshis > 0 {
			log.Printf("x402: payment gating enabled (%d sats/request, payee=%s, nonce pool=100)",
				paymentSatoshis, addr.AddressString)
		} else {
			log.Printf("x402: node is free, nonce pool ready for app passthrough/split payments")
		}
	} else if paymentSatoshis > 0 {
		log.Printf("x402: payment_satoshis=%d but identity.wif or wallet missing — payment gating DISABLED", paymentSatoshis)
		paymentSatoshis = 0
	}

	// P2P fetchers for content CDN — uses BSV nodes directly, WoC as fallback
	var p2pTxFetcher *p2p.TxFetcher
	var p2pBlockFetcher *p2p.BlockTxFetcher
	if len(cfg.BSV.Nodes) > 0 {
		p2pTxFetcher = p2p.NewTxFetcher(cfg.BSV.Nodes, logger)
		p2pBlockFetcher = p2p.NewBlockTxFetcher(cfg.BSV.Nodes, logger)
		defer p2pTxFetcher.Close()
	}

	// REST API — gossip manager wired in so POST /data can broadcast to mesh
	validator := spv.NewValidator(headerStore)
	srv := api.NewServer(api.ServerConfig{
		HeaderStore:      headerStore,
		ProofStore:       proofStore,
		EnvelopeStore:    envStore,
		OverlayDir:       overlayDir,
		Validator:        validator,
		Broadcaster:      broadcaster,
		GossipMgr:        gossipMgr,
		AuthToken:        cfg.API.AuthToken,
		RateLimit:        cfg.API.RateLimit,
		TrustProxy:       cfg.API.TrustProxy,
		PaymentSatoshis:  paymentSatoshis,
		PayeeScriptHex:   payeeScriptHex,
		NonceProvider:    nonceProvider,
		AllowPassthrough: cfg.API.AppPayments.AllowPassthrough,
		AllowSplit:       cfg.API.AppPayments.AllowSplit,
		AllowTokenGating: cfg.API.AppPayments.AllowTokenGating,
		MaxAppPriceSats:  cfg.API.AppPayments.MaxAppPriceSats,
		EndpointPrices:   cfg.API.EndpointPrices,
		ARCClient:        arcClient,
		RequireMempool:   cfg.API.RequireMempool,
		Logger:           logger,
		NodeName:         cfg.Node.Name,
		IdentityPub:      identityPubHex,
		BondChecker:      bondCheck,
		P2PTxSource:      p2pTxFetcher,
		P2PBlockSource:   p2pBlockFetcher,
		HeaderLookup: func(height int) string {
			hash, err := headerStore.HashAtHeight(uint32(height))
			if err != nil || hash == nil {
				return ""
			}
			return hash.String()
		},
	})

	if nodeWallet != nil {
		nodeWallet.RegisterRoutes(srv.Mux(), srv.RequireAuth)
	}

	go func() {
		handler := srv.Handler()
		if cfg.API.TLSCert != "" && cfg.API.TLSKey != "" {
			log.Printf("REST API listening on %s (TLS)", cfg.Node.APIListen)
			tlsSrv := &http.Server{
				Addr:    cfg.Node.APIListen,
				Handler: handler,
				TLSConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			}
			if err := tlsSrv.ListenAndServeTLS(cfg.API.TLSCert, cfg.API.TLSKey); err != nil {
				log.Fatalf("api server: %v", err)
			}
		} else {
			log.Printf("REST API listening on %s (no TLS — use reverse proxy for production)", cfg.Node.APIListen)
			if err := http.ListenAndServe(cfg.Node.APIListen, handler); err != nil {
				log.Fatalf("api server: %v", err)
			}
		}
	}()

	// Block until signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Println()
	log.Printf("received %v, shutting down", s)
}

