package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/txrelay"
	anvilwallet "github.com/BSVanon/Anvil/internal/wallet"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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

		// Bootstrap: register our own SHIP tokens if identity is configured
		if cfg.Identity.WIF != "" {
			// Parse WIF to get identity key for SHIP registration
			wifBytes, err := wifToPrivKey(cfg.Identity.WIF)
			if err != nil {
				log.Printf("overlay bootstrap: invalid WIF: %v", err)
			} else {
				// Use the node's listen address as the domain
				domain := cfg.Node.Listen
				anviloverlay.Bootstrap(overlayDir, wifBytes, domain, cfg.Overlay.Topics, logger)
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

	// TODO: Phase 4 — start gossip mesh

	// Block until signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Println()
	log.Printf("received %v, shutting down", s)
}

// wifToPrivKey decodes a WIF string to a secp256k1 private key.
// WIF format: base58check(version + privkey + [compressed_flag] + checksum)
func wifToPrivKey(wif string) (*secp256k1.PrivateKey, error) {
	raw := base58Decode(wif)
	if len(raw) < 33 {
		return nil, fmt.Errorf("invalid WIF: too short")
	}
	// Skip version byte (1), take 32 bytes of private key
	privBytes := raw[1:33]
	return secp256k1.PrivKeyFromBytes(privBytes), nil
}

// base58Decode decodes a base58 string to bytes.
func base58Decode(s string) []byte {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	result := big.NewInt(0)
	for _, c := range s {
		idx := int64(0)
		for i, a := range alphabet {
			if c == a {
				idx = int64(i)
				break
			}
		}
		result.Mul(result, big.NewInt(58))
		result.Add(result, big.NewInt(idx))
	}
	b := result.Bytes()
	// Preserve leading zeros
	for _, c := range s {
		if c != '1' {
			break
		}
		b = append([]byte{0x00}, b...)
	}
	return b
}
