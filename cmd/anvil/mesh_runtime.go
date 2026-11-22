package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/gossip"
)

// startMeshNetworking owns the long-running socket loops and returns the
// heartbeat source for the currently verified/configured advertised URL.
func startMeshNetworking(ctx context.Context, cfg *config.Config, manager *gossip.Manager) func() string {
	if manager == nil {
		return func() string { return "" }
	}
	for _, seed := range cfg.Mesh.Seeds {
		go manager.ConnectSeedWithReconnect(ctx, seed, 30*time.Second)
	}
	if len(cfg.Mesh.Seeds) > 0 {
		log.Printf("anvil mesh: connecting to %d seed peers (auto-reconnect enabled)", len(cfg.Mesh.Seeds))
	}

	startMeshListener(cfg, manager)
	go manager.RunPeerExchange(ctx)
	manager.StartPeerExchangeAdvertiser(ctx, gossip.PeerAdvertiseConfig{
		ExplicitURL: cfg.Mesh.AdvertiseURL,
		PublicURL:   cfg.Node.PublicURL,
		Listen:      cfg.Node.Listen,
		TLS:         cfg.API.TLSCert != "" && cfg.API.TLSKey != "",
	})
	return manager.PeerExchangeAdvertisedURL
}

func startMeshListener(cfg *config.Config, manager *gossip.Manager) {
	if cfg.Node.Listen == "" {
		return
	}
	go func() {
		handler := manager.MeshHandler()
		server := &http.Server{
			Addr:              cfg.Node.Listen,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		if cfg.API.TLSCert != "" && cfg.API.TLSKey != "" {
			log.Printf("mesh listener on %s (wss, TLS)", cfg.Node.Listen)
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			if err := server.ListenAndServeTLS(cfg.API.TLSCert, cfg.API.TLSKey); err != nil {
				log.Fatalf("mesh listener: %v", err)
			}
			return
		}
		log.Printf("mesh listener on %s (ws, no TLS — dev only)", cfg.Node.Listen)
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("mesh listener: %v", err)
		}
	}()
}
