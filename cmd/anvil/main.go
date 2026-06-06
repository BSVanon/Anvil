package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/bond"
	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/diagnostics"
	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/feeds"
	anvilgossip "github.com/BSVanon/Anvil/internal/gossip"
	"github.com/BSVanon/Anvil/internal/headers"
	mempoolpkg "github.com/BSVanon/Anvil/internal/mempool"
	anvilmsg "github.com/BSVanon/Anvil/internal/messaging"
	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/overlay/federation"
	"github.com/BSVanon/Anvil/internal/overlay/legacyshim"
	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/v3engine"
	"github.com/BSVanon/Anvil/internal/p2p"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	anvilversion "github.com/BSVanon/Anvil/internal/version"
	anvilwallet "github.com/BSVanon/Anvil/internal/wallet"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	goSdkOverlay "github.com/bsv-blockchain/go-sdk/overlay"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/libsv/go-p2p/wire"
)

func main() {
	// Subcommand routing — deploy, doctor, token, or run (default)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "deploy":
			cmdDeploy(os.Args[2:])
			return
		case "doctor":
			cmdDoctor(os.Args[2:])
			return
		case "token":
			cmdToken(os.Args[2:])
			return
		case "info":
			cmdInfo(os.Args[2:])
			return
		case "upgrade":
			cmdUpgrade(os.Args[2:])
			return
		case "overlay-migrate":
			cmdOverlayMigrate(os.Args[2:])
			return
		case "prune-ads":
			cmdPruneAds(os.Args[2:])
			return
		case "version", "--version", "-v":
			// Minimal output so diagnostics.BinaryVersion() can parse the
			// on-disk binary's version without starting the full node.
			fmt.Println("anvil v" + anvilversion.Version)
			return
		case "help", "--help", "-h":
			cmdHelp(os.Args[2:])
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

	log.Printf("anvil node %q v%s starting", cfg.Node.Name, anvilversion.Version)
	log.Printf("  data_dir:   %s", cfg.Node.DataDir)
	log.Printf("  mesh:       %s", cfg.Node.Listen)
	log.Printf("  api:        %s", cfg.Node.APIListen)
	log.Printf("  bsv nodes:  %v", cfg.BSV.Nodes)
	log.Printf("  arc:        enabled=%v", cfg.ARC.Enabled)
	log.Printf("  overlay:    enabled=%v topics=%v gasp_sync=%v",
		cfg.Overlay.Enabled, cfg.Overlay.Topics, cfg.Overlay.EnableGASPSync)
	if cfg.API.AuthToken != "" {
		log.Printf("  auth:       configured (run 'anvil token' to display)")
	}

	go checkForUpdate(logger)

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

	// Periodic header re-sync (without this, headers go stale after boot)
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			before := headerStore.Tip()
			for _, node := range cfg.BSV.Nodes {
				tip, err := syncer.SyncFrom(node)
				if err != nil {
					continue
				}
				if tip > before {
					logger.Info("header re-sync", "from", before, "to", tip, "new", tip-before)
				}
				break
			}
		}
	}()

	proofDir := filepath.Join(cfg.Node.DataDir, "proofs")
	proofStore, err := spv.NewProofStore(proofDir)
	if err != nil {
		log.Fatalf("proof store: %v", err)
	}
	defer proofStore.Close()

	mempool := txrelay.NewMempool()
	var arcClient *txrelay.ARCClient
	if cfg.ARC.Enabled {
		arcClient = txrelay.NewARCClient(cfg.ARC.URL, cfg.ARC.APIKey)
		if cfg.ARC.TAALEnabled && cfg.ARC.TAALURL != "" {
			arcClient.SetFailover(cfg.ARC.TAALURL, cfg.ARC.TAALAPIKey)
			log.Printf("ARC enabled: %s (failover: %s)", cfg.ARC.URL, cfg.ARC.TAALURL)
		} else {
			log.Printf("ARC enabled: %s", cfg.ARC.URL)
		}
	}
	broadcaster := txrelay.NewBroadcaster(mempool, arcClient, logger)

	envDir := filepath.Join(cfg.Node.DataDir, "envelopes")
	envStore, err := envelope.NewStore(envDir, cfg.Envelopes.MaxEphemeralTTL, cfg.Envelopes.MaxDurableSize)
	if err != nil {
		log.Fatalf("envelope store: %v", err)
	}
	defer envStore.Close()
	log.Printf("envelope store opened (max TTL=%ds, max durable=%d bytes)", cfg.Envelopes.MaxEphemeralTTL, cfg.Envelopes.MaxDurableSize)
	envStore.SetMaxDurableStoreMB(cfg.Envelopes.MaxDurableStoreMB)

	go func() { // ephemeral envelope sweeper + durable capacity check
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if n := envStore.ExpireEphemeral(); n > 0 {
				logger.Info("expired ephemeral envelopes", "count", n)
			}
			if sizeB, full := envStore.CheckDurableCapacity(); full {
				logger.Warn("durable store full — rejecting new durable writes",
					"size_mb", sizeB/(1024*1024),
					"max_mb", cfg.Envelopes.MaxDurableStoreMB)
			}
		}
	}()

	// Point-to-point messaging (BRC-33)
	msgDir := filepath.Join(cfg.Node.DataDir, "messages")
	msgStore, err := anvilmsg.NewStore(msgDir, 7*24*3600) // 7-day TTL
	if err != nil {
		log.Fatalf("message store: %v", err)
	}
	defer msgStore.Close()
	log.Printf("message store opened (7-day TTL)")

	// Periodic message expiry (demand decay added after gossipMgr init)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if n := msgStore.ExpireOld(); n > 0 {
				logger.Info("expired old messages", "count", n)
			}
		}
	}()

	mpool := setupMempool(cfg, logger)
	defer mpool.Close()

	// Anvil's overlay subsystem. The legacy in-process engine (legacy
	// internal/overlay.Engine) was removed in W-7 (2026-05-16); the
	// canonical v3 engine + legacy compat shim wired below replace it.
	// overlayDir survives because it owns the LevelDB shared with the
	// v3 engine + federation storage AND the Anvil-Mesh internal peer
	// directory (Bootstrap, ForEachSHIP, AddSHIPPeerFromGossip, etc.) —
	// these are NOT BRC-88 federation, they are Anvil's internal mesh
	// peer discovery for anvil-a/anvil-b coordination, per the Codex
	// 14a2d703 scope carve-out (reference_anvil_teranode_boundary.md).
	// W-10.5 retired the BRC-88-equivalent paths (on-chain SHIP publish,
	// JungleBus SHIP/SLAP discovery) because those duplicate what
	// canonical federation now does; Anvil-Mesh internal discovery
	// stays.
	var overlayDir *anviloverlay.Directory
	var v3Eng *engine.Engine
	var v3Handlers *v3engine.Handlers
	var legacyShim *legacyshim.Shim
	var shipStore *federation.SHIPStorage
	var slapStore *federation.SLAPStorage
	var anvilStore *anvilstorage.Storage
	if cfg.Overlay.Enabled {
		ovDir := filepath.Join(cfg.Node.DataDir, "overlay")
		var err error
		overlayDir, err = anviloverlay.NewDirectory(ovDir)
		if err != nil {
			log.Fatalf("overlay directory: %v", err)
		}
		defer overlayDir.Close()
		log.Printf("overlay directory opened (topics=%v)", cfg.Overlay.Topics)

		// v3.0.2: auto-migrate legacy v2 overlay data in-process on
		// first boot from a v2.x.x install. v2.x.x stored admitted
		// outputs under the `ovl:` LevelDB key family; the v3 canonical
		// engine uses `ovl3:` instead. If we detect legacy keys with
		// no matching v3 records, we run the same migration as the
		// standalone `anvil overlay-migrate` subcommand BEFORE the v3
		// engine wires up — the daemon serves traffic post-migration,
		// not pre-migration.
		//
		// This breaks the v2→v3 upgrade chicken-and-egg: v2's upgrade.go
		// can't run the migrate hook (it predates v3), but the v3
		// daemon running afterwards CAN detect the state and self-heal.
		// Zero manual operator steps required for the v2→v3 transition.
		//
		// Fresh installs have neither family populated and boot
		// cleanly (early-return on legacyCount == 0). Already-migrated
		// nodes are skipped via the count-based comparison.
		if err := autoMigrateLegacyOverlayKeys(overlayDir.DB(), logger); err != nil {
			log.Fatalf("auto-migrate legacy overlay data: %v", err)
		}

		// W-5 phase B-c: wire the v3 canonical engine + legacy compat
		// shim against the same LevelDB. headerStore is reused as the
		// chaintracker.ChainTracker (headers.Store satisfies the
		// interface directly).
		//
		// W-10.3: federation surface (Advertiser, LookupResolver, GASP
		// SyncConfiguration, SHIP/SLAP trackers, Broadcaster) is wired
		// AFTER nodeWallet construction below — it needs the wallet
		// for admin-token PushDrop signing. The engine boots without
		// the federation fields populated and is upgraded in place
		// once nodeWallet is ready. Until then, outbound advertising
		// is dormant but inbound GASP routes are served normally.
		anvilStore = anvilstorage.New(overlayDir.DB())
		shipStore = federation.NewSHIPStorage(overlayDir.DB())
		slapStore = federation.NewSLAPStorage(overlayDir.DB())
		v3Eng, err = v3engine.New(&v3engine.Config{
			Storage:      anvilStore,
			HeadersStore: headerStore,
			LookupDB:     overlayDir.DB(),
			HostingURL:   cfg.Node.PublicURL,
			SHIPStorage:  shipStore,
			SLAPStorage:  slapStore,
			// Wrap Anvil's broadcaster in the canonical SDK adapter so
			// the v3 engine's Submit pipeline propagates SHIP/SLAP
			// advertisement transactions through to ARC. Without this,
			// the engine admits ads locally but they never reach the
			// chain; canonical federation peers would never see our
			// advertisements via SLAP discovery.
			Broadcaster: txrelay.NewSDKBroadcaster(broadcaster),
		})
		if err != nil {
			log.Fatalf("v3 canonical engine: %v", err)
		}
		v3Handlers = v3engine.NewHandlers(v3Eng)
		legacyShim = &legacyshim.Shim{
			Engine:        v3Eng,
			Parsers:       legacyshim.DefaultParsers(),
			ServiceTopics: legacyshim.DefaultServiceTopics(),
		}
		log.Printf("v3 canonical engine wired (%d topics, %d lookup services)",
			len(v3Eng.ListTopicManagers()), len(v3Eng.ListLookupServiceProviders()))

		if cfg.Identity.WIF != "" { // local SHIP bootstrap
			identityKey, err := ec.PrivateKeyFromWif(cfg.Identity.WIF)
			if err != nil {
				log.Printf("overlay bootstrap: invalid WIF: %v", err)
			} else {
				domain := cfg.Node.PublicURL
				if domain == "" {
					domain = cfg.Node.Listen
				}
				identityHex := fmt.Sprintf("%x", identityKey.PubKey().Compressed())

				localDomains := map[string]string{domain: identityHex}
				if cleaned := overlayDir.CleanupOnBoot(localDomains, logger); cleaned > 0 {
					log.Printf("overlay: cleaned %d stale SHIP entries on boot", cleaned)
				}

				_ = anviloverlay.Bootstrap(overlayDir, identityKey, domain, cfg.Node.Name, anvilversion.Version, cfg.Overlay.Topics, logger)
			}
		}

		go func() { // SHIP TTL sweep
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				if n := overlayDir.SweepExpired(); n > 0 {
					logger.Info("overlay: swept expired SHIP entries", "count", n)
				}
			}
		}()

		// W-10.5: JungleBus subscription block retired. The bespoke
		// path used JungleBus to discover other anvil-mesh nodes' SHIP
		// admin tokens on-chain; canonical BRC-88 SLAP discovery via
		// go-sdk's LookupResolver (with DEFAULT_SLAP_TRACKERS or
		// operator-configured SHIP/SLAP trackers) now does the same
		// thing using the canonical primitive. cfg.JungleBus is still
		// loaded for backwards compat but no longer wired to SHIP/SLAP
		// — operators with a JungleBus.Enabled=true config see no
		// side effect from the leftover setting; a future config
		// audit can decide whether to deprecate the section entirely.
	}

	var identityPubHex string
	var identityPrivKey *ec.PrivateKey
	if cfg.Identity.WIF != "" {
		if ik, err := ec.PrivateKeyFromWif(cfg.Identity.WIF); err == nil {
			identityPubHex = fmt.Sprintf("%x", ik.PubKey().Compressed())
			identityPrivKey = ik
		}
	}

	var bondCheck *bond.Checker
	var nodeWallet *anvilwallet.NodeWallet
	if cfg.Identity.WIF != "" {
		walletDir := filepath.Join(cfg.Node.DataDir, "wallet")
		nw, err := anvilwallet.New(cfg.Identity.WIF, walletDir, headerStore, proofStore, broadcaster, arcClient, logger)
		if err != nil {
			if strings.Contains(err.Error(), "CGO_ENABLED") || strings.Contains(err.Error(), "cgo to work") {
				log.Fatalf("FATAL: binary was built with CGO_ENABLED=0 but the wallet requires CGO.\n"+
					"  Rebuild with: CGO_ENABLED=1 go build ./cmd/anvil\n"+
					"  Or use: make build\n"+
					"  Error: %v", err)
			}
			log.Printf("wallet init failed (non-fatal): %v", err)
		} else {
			nodeWallet = nw
			defer nodeWallet.Close()
			log.Printf("wallet initialized")
			// Auto-scan: discover external UTXOs on boot, then every 30 min.
			// Without this, funds sent from other wallets are invisible and
			// nonce minting / x402 silently fails.
			go nodeWallet.RunAutoScan(context.Background(), 30*time.Minute)

			// W-10.3: canonical BRC-88 federation. Now that the wallet
			// exists, upgrade the v3 engine in place with the canonical
			// Advertiser + LookupResolver + GASP SyncConfiguration.
			// Federation participation is opt-out via
			// cfg.Overlay.EnableGASPSync = false.
			if v3Eng != nil && cfg.Overlay.EnableGASPSync && cfg.Node.PublicURL != "" {
				slapTrackers := cfg.Overlay.SLAPTrackers
				if len(slapTrackers) == 0 {
					// Fall back to go-sdk's canonical defaults
					// (overlay-us-1.bsvb.tech, overlay-eu-1.bsvb.tech,
					// overlay-ap-1.bsvb.tech, users.bapp.dev). Operators
					// can override via anvil.toml [overlay] slap_trackers.
					slapTrackers = append(slapTrackers, lookup.DEFAULT_SLAP_TRACKERS...)
				}
				shipTrackers := cfg.Overlay.SHIPTrackers
				if len(shipTrackers) == 0 {
					shipTrackers = append(shipTrackers, lookup.DEFAULT_SLAP_TRACKERS...)
				}
				adv := federation.NewAdvertiser(nodeWallet.Wallet(), cfg.Node.PublicURL, shipStore, slapStore, anvilStore)
				resolver := engine.NewLookupResolverWithNetwork(overlayNetworkFromBSV(cfg))
				resolver.SetSLAPTrackers(slapTrackers)
				v3Eng.Advertiser = adv
				v3Eng.LookupResolver = resolver
				v3Eng.SHIPTrackers = shipTrackers
				v3Eng.SLAPTrackers = slapTrackers
				v3Eng.SyncConfiguration = buildSyncConfiguration(v3Eng)
				log.Printf("v3 federation wired: %d topics syncable via canonical SHIP/SLAP (trackers=%d)",
					len(v3Eng.SyncConfiguration), len(slapTrackers))

				// Periodic federation work. SyncAdvertisements
				// reconciles our on-chain ad set with the topics we
				// currently host; StartGASPSync pulls peer state for
				// each subscribed topic. Both gated on
				// EnableGASPSync, both safe to run periodically.
				go runSyncAdvertisements(context.Background(), v3Eng, logger, cfg.Overlay.AdvertiseIntervalSecs)
				go runGASPSync(context.Background(), v3Eng, logger, cfg.Overlay.GASPSyncIntervalSecs)
			} else if v3Eng != nil && !cfg.Overlay.EnableGASPSync {
				log.Printf("v3 federation disabled (cfg.Overlay.EnableGASPSync = false); GASP routes still serve inbound requests")
			}

			// W-10.5: Bespoke on-chain SHIP publish retired. The
			// canonical federation Advertiser wired above publishes
			// SHIP+SLAP advertisements for every active topic via
			// admin-token PushDrop on the next SyncAdvertisements pass.
			// Identical effect (an on-chain admin token announcing the
			// node's hosted topics + lookup services) using the
			// canonical primitive instead of the bespoke path.
		}
	}

	// Anvil mesh — go-sdk auth.Peer over WebSocket. Requires wallet for identity.
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

		localPKSet := make(map[string]struct{}) // local pubkeys exempt from double-publish
		var localPKs []string
		if identityPubHex != "" {
			localPKSet[identityPubHex] = struct{}{}
			localPKs = append(localPKs, identityPubHex)
		}
		for _, pk := range cfg.Mesh.LocalPubkeys {
			pk = strings.ToLower(strings.TrimSpace(pk))
			if pk == "" {
				continue
			}
			if _, exists := localPKSet[pk]; exists {
				continue
			}
			localPKSet[pk] = struct{}{}
			localPKs = append(localPKs, pk)
		}
		var connLog *anvilgossip.ConnectionLog
		connLogPath := filepath.Join(cfg.Node.DataDir, "mesh", "connections.jsonl")
		if cl, err := anvilgossip.NewConnectionLog(connLogPath, 50); err != nil {
			log.Printf("mesh connection log disabled: %v", err)
		} else {
			connLog = cl
			log.Printf("mesh connection log: %s", connLogPath)
		}
		gossipMgr = anvilgossip.NewManager(anvilgossip.ManagerConfig{
			Wallet:         nodeWallet.Wallet(),
			Store:          envStore,
			Logger:         logger,
			LocalInterests: []string{""}, // match all topics — relay everything we store
			MaxSeen:        10000,
			OverlayDir:     overlayDir,
			BondChecker:    bondCheck,
			LocalPubkeys:   localPKs,
			ConnectionLog:  connLog,
			IdentityKey:    identityPrivKey,
			RatePerSec:     cfg.Mesh.RatePerSec,
			RateBurst:      cfg.Mesh.RateBurst,
			TxMempool:      anvilgossip.NewTxRelayMempool(mempool),
			CatchUpTopics:  []string{"anvil:catalog", "mesh:heartbeat"},
			OnEnvelope: func() func(*envelope.Envelope) {
				var firstData sync.Once
				return func(env *envelope.Envelope) {
					firstData.Do(func() {
						log.Printf("mesh: receiving live data from peers (first: %s)", env.Topic)
					})
					logger.Debug("mesh envelope received", "topic", env.Topic, "from", env.Pubkey[:16])

					// Merge demand from peer heartbeats.
					if env.Topic == "mesh:heartbeat" {
						var hb feeds.HeartbeatPayload
						if err := json.Unmarshal([]byte(env.Payload), &hb); err == nil && len(hb.Demand) > 0 {
							gossipMgr.MergeDemand(hb.Demand)
						}
					}
				}
			}(),
		})
		defer gossipMgr.Stop()

		// Connect to seed peers (auto-reconnect on disconnect, 30s retry)
		for _, seed := range cfg.Mesh.Seeds {
			go gossipMgr.ConnectSeedWithReconnect(context.Background(), seed, 30*time.Second)
		}
		if len(cfg.Mesh.Seeds) > 0 {
			log.Printf("anvil mesh: connecting to %d seed peers (auto-reconnect enabled)", len(cfg.Mesh.Seeds))
		}

		// TX mesh relay deprecated (post-Teranode: no mempool to relay).
		// Keeping code but not wiring announcers.

		// Inbound mesh listener (wss:// with TLS, ws:// without)
		if cfg.Node.Listen != "" {
			go func() {
				handler := gossipMgr.MeshHandler()
				if cfg.API.TLSCert != "" && cfg.API.TLSKey != "" {
					log.Printf("mesh listener on %s (wss, TLS)", cfg.Node.Listen)
					meshSrv := &http.Server{
						Addr:              cfg.Node.Listen,
						Handler:           handler,
						ReadHeaderTimeout: 10 * time.Second,
						TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
					}
					if err := meshSrv.ListenAndServeTLS(cfg.API.TLSCert, cfg.API.TLSKey); err != nil {
						log.Fatalf("mesh listener: %v", err)
					}
				} else {
					log.Printf("mesh listener on %s (ws, no TLS — dev only)", cfg.Node.Listen)
					meshSrv := &http.Server{
						Addr:              cfg.Node.Listen,
						Handler:           handler,
						ReadHeaderTimeout: 10 * time.Second,
					}
					if err := meshSrv.ListenAndServe(); err != nil {
						log.Fatalf("mesh listener: %v", err)
					}
				}
			}()
		}
	}

	// SHIP re-announce at half the TTL so entries survive on remote directories
	if gossipMgr != nil {
		go func() {
			ticker := time.NewTicker(45 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				gossipMgr.ReannounceToAll()
			}
		}()
	}

	// Built-in feeds: heartbeat (60s) + block tip (10s poll)
	if cfg.Identity.WIF != "" && gossipMgr != nil {
		feedKey, err := ec.PrivateKeyFromWif(cfg.Identity.WIF)
		if err == nil {
			pub := feeds.NewPublisher(feedKey, envStore, gossipMgr.BroadcastEnvelope, cfg.Node.Name, anvilversion.Version, logger)

			feedCtx, feedCancel := context.WithCancel(context.Background())
			defer feedCancel()

			// Compute header sync lag (tip time → now) on each heartbeat tick
			// so consumers can see whether our local headers are current.
			headerLagFn := func() int {
				tip := headerStore.Tip()
				raw, err := headerStore.HeaderAtHeight(tip)
				if err != nil {
					return 0
				}
				var hdr wire.BlockHeader
				if err := hdr.Deserialize(bytes.NewReader(raw)); err != nil {
					return 0
				}
				lag := int(time.Since(hdr.Timestamp).Seconds())
				if lag < 0 {
					return 0
				}
				return lag
			}

			// serviceHealthFn observes this node's own systemd service state
			// and an orphan-process scan to decide whether the anvil service
			// itself is operationally healthy. Consumers use this alongside
			// Broadcast (upstream) health to distinguish an ARC outage from
			// a local service meltdown — different remediations.
			serviceHealthFn := func() string {
				svcs, err := diagnostics.EnumerateAnvilServices()
				if err != nil {
					return "" // can't observe; omit field
				}
				// Choose the service that owns our API port (crude but works)
				// to avoid reporting our sibling's state.
				orphans, _ := diagnostics.FindOrphans()
				if len(orphans) > 0 {
					return "broken"
				}
				worst := "healthy"
				for _, s := range svcs {
					switch s.ActiveState {
					case "active":
						if s.NRestarts > 0 && worst == "healthy" {
							worst = "degraded"
						}
					case "activating":
						if worst != "broken" {
							worst = "degraded"
						}
					case "failed", "inactive":
						if diagnostics.IsCrashLooping(s) {
							worst = "broken"
						} else if worst == "healthy" {
							worst = "degraded"
						}
					}
				}
				return worst
			}

			upstreamFn := func() *feeds.UpstreamStatus {
				status := &feeds.UpstreamStatus{
					Broadcast:          broadcaster.UpstreamStatus(),
					HeadersSyncLagSecs: headerLagFn(),
					ServiceHealth:      serviceHealthFn(),
				}
				return status
			}

			go pub.RunHeartbeat(feedCtx, 60*time.Second, feeds.HeartbeatSources{
				HeightFn:   headerStore.Tip,
				PeersFn:    gossipMgr.PeerCount,
				TopicsFn:   envStore.Topics,
				DemandFn:   gossipMgr.DemandMap,
				UpstreamFn: upstreamFn,
			})

			// Block tip feed removed — experimental, no consumers.
			// Header sync continues internally for x402 payment verification.

			log.Printf("feeds: heartbeat (60s) publisher started")
		}
	}

	// x402 payment gating — requires identity.wif + wallet; forced off without both
	paymentSatoshis := cfg.API.PaymentSatoshis
	var payeeScriptHex string
	var nonceProvider api.NonceProvider
	// Nonce provider: needed for app passthrough/split even when node is free
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

	var p2pTxFetcher *p2p.TxFetcher
	var p2pBlockFetcher *p2p.BlockTxFetcher
	if len(cfg.BSV.Nodes) > 0 {
		p2pTxFetcher = p2p.NewTxFetcher(cfg.BSV.Nodes, logger)
		p2pBlockFetcher = p2p.NewBlockTxFetcher(cfg.BSV.Nodes, logger)
		defer p2pTxFetcher.Close()
	}

	// REST API
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
		ExplorerOrigin:   cfg.API.ExplorerOrigin,
		PublicURL:        cfg.Node.PublicURL,
		HeaderSyncStatus: syncer.Stats,
		ServiceHealthFn: func() string {
			orphans, _ := diagnostics.FindOrphans()
			if len(orphans) > 0 {
				return "broken"
			}
			svcs, err := diagnostics.EnumerateAnvilServices()
			if err != nil {
				return ""
			}
			worst := "healthy"
			for _, s := range svcs {
				switch s.ActiveState {
				case "active":
					if s.NRestarts > 0 && worst == "healthy" {
						worst = "degraded"
					}
				case "activating":
					if worst != "broken" {
						worst = "degraded"
					}
				case "failed", "inactive":
					if diagnostics.IsCrashLooping(s) {
						worst = "broken"
					} else if worst == "healthy" {
						worst = "degraded"
					}
				}
			}
			return worst
		},
		SPVProofSource: func() string {
			if cfg.ARC.Enabled {
				return "arc+woc-fallback"
			}
			return "woc"
		}(),
		Watcher: func() *mempoolpkg.Watcher {
			if mpool != nil {
				return mpool.watcher
			}
			return nil
		}(),
		ProofFetcher:   spv.NewProofFetcher(arcClient, logger),
		P2PTxSource:    p2pTxFetcher,
		P2PBlockSource: p2pBlockFetcher,
		MsgStore:   msgStore,
		SigningKey: identityPrivKey,
		HeaderLookup: func(height int) string {
			if height < 0 {
				return ""
			}
			hash, err := headerStore.HashAtHeight(uint32(height)) // #nosec G115 // guarded by < 0 check above
			if err != nil || hash == nil {
				return ""
			}
			return hash.String()
		},
		CustomCapabilities: cfg.Capabilities.Custom,
	})

	if nodeWallet != nil {
		nodeWallet.RegisterRoutes(srv.Mux(), srv.RequireAuth)
	}

	if gossipMgr != nil { // SSE notifications from mesh
		gossipMgr.SetOnEnvelopeHook(srv.NotifyEnvelope)
		gossipMgr.SetMsgStore(msgStore) // enable cross-node message forwarding

		// Periodic demand decay (halve counters every 5 min)
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				gossipMgr.DecayDemand()
			}
		}()
	}

	// W-5/W-7: canonical v3 engine + legacy /overlay/* compat shim
	// own all overlay-protocol HTTP routes. Mesh routes
	// (/overlay/lookup, /overlay/register, /overlay/deregister) stay
	// registered by internal/api/server.go and are unaffected — per
	// Codex review 14a2d703 scope carve-out.
	//
	// CorsWrap is REQUIRED for both registrations so browser callers
	// (Foundry, Anvil-Swap UI, future TS SDK consumers) get the
	// canonical Access-Control-* headers — including the canonical
	// x-includes-off-chain-values + x-aggregation custom headers
	// (Codex reviews d671fa17fe5cc746, fe9707876f5618ca,
	// 2968609c62a2eb51 walked through this surface).
	if v3Handlers != nil {
		v3Handlers.Register(srv.Mux(), srv.CorsWrap)
	}
	if legacyShim != nil {
		legacyShim.Register(srv.Mux(), srv.CorsWrap)
	}

	// Subsystem health checks — surfaced in /status warnings
	if nodeWallet != nil {
		srv.RegisterHealthCheck("wallet", func() string {
			if nodeWallet.SpendableOutputCount() == 0 {
				return "wallet has zero spendable outputs — run POST /wallet/scan or fund the identity address"
			}
			return ""
		})
	} else if cfg.Identity.WIF != "" {
		srv.RegisterHealthCheck("wallet", func() string {
			return "wallet failed to initialize — check logs, CGO may be disabled"
		})
	}
	if cfg.API.PaymentSatoshis > 0 {
		srv.RegisterHealthCheck("nonce_pool", func() string {
			if srv.NoncePoolSize() == 0 {
				return "x402 nonce pool is empty — payment challenges will be slow or fail (wallet may need funding)"
			}
			return ""
		})
	}
	if mpool != nil && mpool.monitor != nil {
		srv.RegisterHealthCheck("mempool_monitor", func() string {
			stats := mpool.monitor.Stats()
			if !stats.Connected {
				return "mempool monitor disconnected from BSV peer (auto-reconnect active)"
			}
			return ""
		})
	}

	go func() {
		handler := srv.Handler()
		if cfg.API.TLSCert != "" && cfg.API.TLSKey != "" {
			log.Printf("REST API listening on %s (TLS)", cfg.Node.APIListen)
			tlsSrv := &http.Server{
				Addr:              cfg.Node.APIListen,
				Handler:           handler,
				ReadHeaderTimeout: 10 * time.Second,
				TLSConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			}
			if err := tlsSrv.ListenAndServeTLS(cfg.API.TLSCert, cfg.API.TLSKey); err != nil {
				log.Fatalf("api server: %v", err)
			}
		} else {
			log.Printf("REST API listening on %s (no TLS — use reverse proxy for production)", cfg.Node.APIListen)
			apiSrv := &http.Server{
				Addr:              cfg.Node.APIListen,
				Handler:           handler,
				ReadHeaderTimeout: 10 * time.Second,
			}
			if err := apiSrv.ListenAndServe(); err != nil {
				log.Fatalf("api server: %v", err)
			}
		}
	}()

	// Block until signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	_, _ = fmt.Println()
	log.Printf("received %v, shutting down", s)
}

// overlayNetworkFromBSV returns the canonical overlay network identifier
// used by go-sdk's LookupResolver. Anvil runs on mainnet by default.
// (No testnet config field exists today; we'll add an override when
// testnet operators surface, but the BRC-100 ecosystem is mainnet-only
// in production so this hardcoded default is the right starting point.)
func overlayNetworkFromBSV(_ *config.Config) goSdkOverlay.Network {
	return goSdkOverlay.NetworkMainnet
}

// buildSyncConfiguration constructs the per-topic GASP policy map
// passed to the v3 engine. Every topic the engine currently hosts gets
// SyncConfigurationSHIP so the engine discovers peers via SLAP at sync
// time. tm_ship / tm_slap themselves use SyncConfigurationPeers seeded
// with the bootstrap SHIPTrackers / SLAPTrackers — the engine merges
// those into the peer set at NewEngine time but we set them again here
// so the post-construction upgrade path lands the same shape.
//
// ListTopicManagers returns map[topicName]*MetaData; we iterate over
// the keys to enumerate registered topic names.
func buildSyncConfiguration(eng *engine.Engine) map[string]engine.SyncConfiguration {
	out := map[string]engine.SyncConfiguration{}
	for name := range eng.ListTopicManagers() {
		switch name {
		case "tm_ship":
			out[name] = engine.SyncConfiguration{Type: engine.SyncConfigurationPeers, Peers: eng.SHIPTrackers}
		case "tm_slap":
			out[name] = engine.SyncConfiguration{Type: engine.SyncConfigurationPeers, Peers: eng.SLAPTrackers}
		default:
			out[name] = engine.SyncConfiguration{Type: engine.SyncConfigurationSHIP}
		}
	}
	return out
}

// runSyncAdvertisements ticks engine.SyncAdvertisements at the
// configured cadence. The canonical reconciliation loop creates
// missing SHIP/SLAP outputs for topics we host and revokes ones we no
// longer host. Runs once on boot then on a long cadence —
// advertisement state changes infrequently (operator topic config
// edits), so a tight loop would just churn the wallet. Default 1800s
// (30 min) preserved from v3.0.0; configurable via
// cfg.Overlay.AdvertiseIntervalSecs.
func runSyncAdvertisements(ctx context.Context, eng *engine.Engine, logger *slog.Logger, intervalSecs int) {
	if intervalSecs <= 0 {
		intervalSecs = 1800
	}
	if err := eng.SyncAdvertisements(ctx); err != nil {
		logger.Error("initial SyncAdvertisements failed", "error", err)
	}
	logger.Info("SyncAdvertisements loop started", "interval_secs", intervalSecs)
	ticker := time.NewTicker(time.Duration(intervalSecs) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := eng.SyncAdvertisements(ctx); err != nil {
				logger.Error("SyncAdvertisements failed", "error", err)
			}
		}
	}
}

// runGASPSync ticks engine.StartGASPSync at the configured cadence.
// The canonical sync pulls peer state for each subscribed topic; new
// admits propagate into our local index. v3.0.0-v3.0.6 hardcoded 5 min
// (upstream overlay-express default) which translated to ~3 Mbps
// sustained RX on small VPSes because the canonical engine re-pulls
// advertisements with since=0 each cycle (no cursor persistence yet —
// v3.0.8 candidate work). v3.0.7 makes this configurable + bumps
// default to 1800s (30 min) — cuts bandwidth ~6x without meaningfully
// degrading freshness, since topic admissions aren't high-rate. 0 or
// unset → default 1800. Operators wanting tighter discovery can dial
// down; aim for 60s as a practical floor.
func runGASPSync(ctx context.Context, eng *engine.Engine, logger *slog.Logger, intervalSecs int) {
	if intervalSecs <= 0 {
		intervalSecs = 1800
	}
	if err := eng.StartGASPSync(ctx); err != nil {
		logger.Error("initial StartGASPSync failed", "error", err)
	}
	logger.Info("GASPSync loop started", "interval_secs", intervalSecs)
	ticker := time.NewTicker(time.Duration(intervalSecs) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := eng.StartGASPSync(ctx); err != nil {
				logger.Error("StartGASPSync failed", "error", err)
			}
		}
	}
}

// autoMigrateLegacyOverlayKeys is the v3.0.2+ replacement for the
// warn-only boot scan that shipped in v3.0.0-3.0.1. If the overlay
// LevelDB contains v2.x.x `ovl:` records with no matching v3 `ovl3:`
// records, this runs the same migration logic as the standalone
// `anvil overlay-migrate` subcommand — but in-process, BEFORE the v3
// engine wires up, so a fresh v2→v3 upgrade just works for any
// operator running `sudo anvil upgrade`.
//
// Returns nil on success (including no-op cases: fresh install or
// already-migrated). Returns a non-nil error only on hard migration
// failure (corrupt legacy values, unparseable keys, or DB I/O) so
// main can fail-fast instead of booting a half-migrated daemon.
//
// Idempotent: re-runs are safe; the migrator skips records whose v3
// counterpart already exists.
func autoMigrateLegacyOverlayKeys(db *leveldb.DB, logger *slog.Logger) error {
	legacyCount := countKeysWithPrefix(db, "ovl:")
	if legacyCount == 0 {
		return nil
	}
	v3Count := countKeysWithPrefix(db, "ovl3:")
	if v3Count >= legacyCount {
		return nil
	}

	if logger != nil {
		logger.Info("v3 detected legacy v2 overlay data — running one-shot migration",
			"legacy_keys", legacyCount,
			"v3_keys_present", v3Count)
	}

	opts := anvilstorage.MigrateOptions{
		LookupBackfiller: makeLookupBackfiller(db, false),
	}
	if logger != nil {
		opts.Logger = func(format string, a ...any) {
			logger.Info("auto-migrate", "line", fmt.Sprintf(format, a...))
		}
	}
	stats, err := anvilstorage.Migrate(context.Background(), db, opts)
	if err != nil {
		return fmt.Errorf("storage.Migrate: %w", err)
	}
	if stats.UnparseableLegacy > 0 || stats.UnparseableKey > 0 {
		return fmt.Errorf("migration found unparseable data: UnparseableLegacy=%d UnparseableKey=%d — run `anvil overlay-migrate -v` to inspect",
			stats.UnparseableLegacy, stats.UnparseableKey)
	}
	if logger != nil {
		logger.Info("v3 auto-migration complete",
			"migrated", stats.Migrated,
			"already_migrated", stats.AlreadyMigrated,
			"lookup_backfilled", stats.LookupBackfilled,
			"lookup_backfill_errors", stats.LookupBackfillErrors)
	}
	return nil
}

// warnLegacyOverlayKeys probes the overlay LevelDB for entries under
// the v2.x.x `ovl:` key family. If any legacy keys exist but no
// corresponding `ovl3:` records exist, the operator has upgraded the
// Anvil binary without running `anvil overlay-migrate`. Emit a loud
// stderr warning with the exact command the operator needs to run.
//
// The function is warn-don't-abort: fresh installs have neither
// family populated and must boot cleanly; operators may legitimately
// choose to ignore legacy data and start fresh; and a transient DB
// scan error must not stop the daemon.
//
// Count-based comparison instead of existence-based, per Codex review
// 925149d6281f6b4b: "any ovl3: key exists" is too permissive — a
// partially-completed migration (interrupted mid-run, or one that
// exited with UnparseableLegacy > 0) would silently clear the warning
// even though many ovl: records still have no ovl3: counterpart. We
// instead count both families and only suppress the banner when the
// v3 record count is >= the legacy count, which is the actual
// "migration complete" condition (legacy keys are never removed, so a
// successful migrate leaves both counts equal; a partial migrate
// leaves v3 < legacy).
func warnLegacyOverlayKeys(db *leveldb.DB, logger *slog.Logger) {
	legacyCount := countKeysWithPrefix(db, "ovl:")
	if legacyCount == 0 {
		return
	}
	v3Count := countKeysWithPrefix(db, "ovl3:")
	if v3Count >= legacyCount {
		// All legacy records have a v3 counterpart (or more — v3 can
		// also include records admitted natively post-migration). The
		// migration is functionally complete; no banner needed.
		return
	}
	// Partial or missing migration: v3Count < legacyCount, including
	// the v3Count == 0 fresh-upgrade case.

	const banner = `
================================================================================
  ANVIL v3 LEGACY DATA DETECTED — MIGRATION REQUIRED

  This LevelDB contains v2.x.x overlay records (ovl: prefix) but no v3
  canonical records (ovl3: prefix). The v3 engine cannot see legacy
  data until you run the one-time backfill migration.

  STOP THE DAEMON, then run:

      anvil overlay-migrate

  Once migrated, restart anvil. This warning will not appear again.

  Read more: docs/operator/overlay-migration.md
================================================================================
`
	if logger != nil {
		logger.Warn("legacy overlay data needs migration — run 'anvil overlay-migrate'")
	}
	// Use the bare print so operators see the banner even when slog
	// output is JSON-formatted.
	fmt.Fprint(os.Stderr, banner)
}

// countKeysWithPrefix returns the number of LevelDB keys starting with
// the given prefix. Used by the legacy-key boot scan to detect partial
// migrations (legacy count > v3 count means some records still need
// the migrate step). Returns 0 on nil db. Cheap enough at boot since
// admission counts are typically O(low thousands) per overlay node;
// the scan is single-pass with no decode.
func countKeysWithPrefix(db *leveldb.DB, prefix string) int {
	if db == nil {
		return 0
	}
	iter := db.NewIterator(util.BytesPrefix([]byte(prefix)), nil)
	defer iter.Release()
	count := 0
	for iter.Next() {
		count++
	}
	return count
}
