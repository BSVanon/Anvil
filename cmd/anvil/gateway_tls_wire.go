package main

// Starts the gateway's TLS (443) and plain (80) listeners when
// [gateway] is enabled, wired from wireGateway (gateway_wire.go). With
// gateway mode off, wireGateway returns before this is ever called, so
// nothing listens on 80 or 443 at all — the hard constraint this whole
// mechanism exists under.

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
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
// cmdServe (main.go). A listener that fails to bind logs the failure and
// returns from its own goroutine; it never stops the node — the mesh and
// the existing :9333 API listener are a separate goroutine each and keep
// running regardless. Doctor's own "80 and 443 are bound" check is what
// surfaces an unbound port to the operator.
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
	warnIfAcmeDirUnwritable(acmeDir, logger)

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
			logger.Error("gateway TLS listener stopped", "addr", cfg.Gateway.HTTPSListen, "error", err)
		}
	}()

	httpSrv := gateway.NewHTTPServer(cfg.Gateway.HTTPListen, manager, policy, cfg.Gateway.APIHost)
	go func() {
		log.Printf("gateway ACME/redirect listening on %s", cfg.Gateway.HTTPListen)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("gateway HTTP listener stopped", "addr", cfg.Gateway.HTTPListen, "error", err)
		}
	}()
}

// warnIfAcmeDirUnwritable logs one clear, non-fatal error naming the fix
// when dir already exists but this process can't write into it — the
// state doctorAcmeDirOwnershipAndMode (doctor_gateway.go) reports lazily,
// on demand, but which the daemon itself only discovers the hard way,
// the first time it tries to write a certificate or an error note,
// unless checked here at start. Checked with a real, throwaway write
// rather than an owner/mode comparison, so it also catches a cause
// doctor's own check doesn't: a directory that's 0700 and anvil-owned on
// disk but unwritable for another reason (a read-only bind mount, a
// filesystem gone read-only after a fault, an ACL).
//
// A directory that doesn't exist yet is NewCache's own job, moments ago,
// and is never reported here — this only ever fires for a directory a
// previous run, or an operator, already created.
func warnIfAcmeDirUnwritable(dir string, logger *slog.Logger) {
	if _, err := os.Stat(dir); err != nil {
		return
	}
	if err := probeWritable(dir); err != nil {
		logger.Error("gateway: acme directory exists but this process cannot write to it — certificates can never be issued or renewed until this is fixed",
			"dir", dir, "fix", fmt.Sprintf("chown anvil %s && chmod 0700 %s", dir, dir), "error", err)
	}
}

// probeWritable reports whether dir can be written to by this process,
// by creating and immediately removing one throwaway file inside it.
// This process never chowns or chmods the directory itself — see
// warnIfAcmeDirUnwritable's doc comment; the one-line fix it logs is for
// an operator to run by hand, the same division of labour as doctor's
// own report-only ownership and mode check.
func probeWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".write-probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}
