package main

// Starts the gateway's TLS (443) and plain (80) listeners when
// [gateway] is enabled, wired from wireGateway (gateway_wire.go). With
// gateway mode off, wireGateway returns before this is ever called, so
// nothing listens on 80 or 443 at all — the hard constraint this whole
// mechanism exists under.

import (
	"log"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/gateway"
	anvilgossip "github.com/BSVanon/Anvil/internal/gossip"
)

// startGatewayTLS builds the autocert.Manager and replicated challenge
// cache over router's own policy, then starts the 443 (TLS) and 80
// (ACME http-01 + redirect) listeners in their own goroutines — the same
// fire-and-forget pattern as the existing :9333 API listener goroutine in
// cmdServe (main.go), logging and exiting the process if either port
// fails to bind, since a gateway that can't bind what it was configured
// for can't serve anything.
//
// gossipMgr may be nil (mesh disabled, or no identity configured) — in
// that case the cache is built with no outbound sender and no inbound
// hook, which NewCache already treats the same as an empty
// [mesh] allowed_peers: replication is simply off.
func startGatewayTLS(cfg *config.Config, policy *gateway.Policy, router *gateway.Router, counters *gateway.Counters, gossipMgr *anvilgossip.Manager, logger *slog.Logger) {
	var send gateway.ACMEPeerSender
	if gossipMgr != nil {
		send = gossipMgr.BroadcastACMEChallenge
	}
	acmeDir := filepath.Join(cfg.Node.DataDir, "acme")
	cache := gateway.NewCache(acmeDir, send, policy, cfg.Mesh.AllowedPeers, counters)

	if gossipMgr != nil {
		gossipMgr.SetACMEChallengeHook(func(senderPKHex, key string, value []byte, expires time.Time) {
			if err := cache.ApplyReceived(senderPKHex, key, value, expires); err != nil {
				logger.Debug("gateway: refused a replicated ACME challenge entry", "error", err)
			}
		})
	}

	manager := gateway.NewACMEManager(gateway.ACMEManagerConfig{
		Cache:     cache,
		Policy:    policy,
		APIHost:   cfg.Gateway.APIHost,
		Email:     cfg.Gateway.ACMEEmail,
		Directory: cfg.Gateway.ACMEDirectory,
		AcceptTOS: cfg.Gateway.AcceptTOS,
		Counters:  counters,
	})

	httpsSrv := gateway.NewHTTPSServer(cfg.Gateway.HTTPSListen, router, manager, counters)
	go func() {
		log.Printf("gateway TLS listening on %s", cfg.Gateway.HTTPSListen)
		if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("gateway TLS server: %v", err)
		}
	}()

	httpSrv := gateway.NewHTTPServer(cfg.Gateway.HTTPListen, manager, policy, cfg.Gateway.APIHost)
	go func() {
		log.Printf("gateway ACME/redirect listening on %s", cfg.Gateway.HTTPListen)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("gateway HTTP server: %v", err)
		}
	}()
}
