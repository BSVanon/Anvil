package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BSVanon/Anvil/internal/config"
	anvilversion "github.com/BSVanon/Anvil/internal/version"
)

// cmdDoctor diagnoses node health and offers applicable remediations.
func cmdDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to config file")
	yes := fs.Bool("yes", false, "apply remediations without prompting (for scripts / automation)")
	locksOnly := fs.Bool("locks-only", false, "only resolve orphan-lock contention; skip other checks; safe for systemd ExecStartPre")
	noFix := fs.Bool("no-fix", false, "diagnostic-only mode (historical behavior; default is interactive fix)")

	// Legacy aliases — silently accept for backward compat with v2.2.x scripts.
	fixLegacy := fs.Bool("fix", false, "[alias] default behavior since v2.3.0")
	fixLocksLegacy := fs.Bool("fix-locks-only", false, "[alias] equivalent to --locks-only since v2.3.0")
	_ = fixLegacy // no-op; default is now fix-interactive
	_ = fs.Parse(args)

	// Collapse aliases
	if *fixLocksLegacy {
		*locksOnly = true
	}

	if *locksOnly {
		runLocksOnly()
		return
	}

	// Default mode since v2.3.0: fix-interactive. Operator gets y/N per
	// finding unless they explicitly pass --no-fix OR they pass --yes
	// (apply all).
	fix := !*noFix

	loadEnvFile(*configPath)

	fmt.Println("=== Anvil Doctor ===")
	switch {
	case *noFix:
		fmt.Println("  mode: diagnose only")
	case *yes:
		fmt.Println("  mode: diagnose + auto-fix (no prompts)")
	default:
		fmt.Println("  mode: diagnose + interactive fix (y/N per finding)")
	}
	issues := 0

	// ── 1. Config ──
	section("Config")
	cfg, err := config.Load(*configPath)
	if err != nil {
		fail("config load: %v", err)
		issues++
		fmt.Println("\nCannot proceed without valid config.")
		os.Exit(1)
	}
	pass("config loaded from %s", *configPath)

	if cfg.Identity.WIF == "" {
		// Check if the env file exists but wasn't loaded (e.g. permissions)
		configDir := filepath.Dir(*configPath)
		configBase := strings.TrimSuffix(filepath.Base(*configPath), filepath.Ext(*configPath))
		envPath := filepath.Join(configDir, configBase+".env")
		if _, err := os.Stat(envPath); err == nil {
			fail("no identity WIF in environment, but env file exists at %s — check file permissions or run under systemd", envPath)
		} else {
			fail("no identity WIF configured (set ANVIL_IDENTITY_WIF or create %s)", envPath)
		}
		issues++
	} else {
		pass("identity WIF present (%s)", doctorSecretFingerprint(cfg.Identity.WIF))
	}

	if cfg.API.AuthToken == "" {
		fail("auth token not derived (WIF missing or invalid)")
		issues++
	} else {
		pass("auth token derived (%s)", doctorSecretFingerprint(cfg.API.AuthToken))
	}
	if len(cfg.Mesh.Seeds) == 0 {
		warn("no mesh seeds configured — this node will not auto-connect to the mesh")
	} else {
		pass("%d mesh seed(s) configured", len(cfg.Mesh.Seeds))
		for _, seed := range cfg.Mesh.Seeds {
			if !strings.HasPrefix(seed, "wss://") {
				warn("mesh seed is not wss:// — %s", seed)
			}
		}
	}

	// ── 1b. Version ──
	section("Version")
	pass("running v%s", anvilversion.Version)
	if latest := doctorCheckLatest(); latest != "" {
		latestClean := strings.TrimPrefix(latest, "v")
		if versionNewerOrEqual(anvilversion.Version, latestClean) {
			pass("up to date (latest release: %s)", latest)
		} else {
			warn("update available: %s → run: sudo anvil upgrade", latest)
		}
	} else {
		warn("could not check GitHub for latest release")
	}

	// ── 2. Data directories ──
	section("Data Directories")
	requiredDirs := []string{"headers", "envelopes", "overlay", "wallet", "invoices", "proofs"}
	for _, sub := range requiredDirs {
		dir := filepath.Join(cfg.Node.DataDir, sub)
		if info, err := os.Stat(dir); err != nil {
			fail("%s: does not exist", dir)
			issues++
		} else if !info.IsDir() {
			fail("%s: not a directory", dir)
			issues++
		} else {
			pass("%s", dir)
		}
	}

	// Check ownership
	dataOwner := fileOwner(cfg.Node.DataDir)
	if dataOwner != "anvil" && dataOwner != "" {
		warn("%s owned by %q, expected \"anvil\"", cfg.Node.DataDir, dataOwner)
	}

	// ── 3. Systemd service ──
	section("Systemd Service")
	svcName := guessServiceName(cfg)
	if svcName != "" {
		status := serviceStatus(svcName)
		if status == "active" {
			pass("%s is running", svcName)
		} else if status == "inactive" || status == "failed" {
			fail("%s is %s — run: sudo systemctl start %s", svcName, status, svcName)
			issues++
		} else {
			warn("%s status: %s", svcName, status)
		}
	} else {
		warn("could not determine systemd service name")
	}

	// ── 4. Local API ──
	section("Local API")
	apiURL := fmt.Sprintf("http://127.0.0.1%s", normalizePort(cfg.Node.APIListen))
	statusResp, statusErr := doctorStatusProbe(apiURL)
	apiAvailable := statusErr == nil
	if apiAvailable {
		pass("API responding at %s", apiURL)
		if h, ok := statusResp["headers"].(map[string]interface{}); ok {
			if height, ok := h["height"].(float64); ok {
				pass("header height: %d", int(height))
			}
			if lag, ok := h["sync_lag_secs"].(float64); ok {
				if int(lag) > 1800 {
					warn("header sync lag: %ds", int(lag))
				} else {
					pass("header sync lag: %ds", int(lag))
				}
			}
		}
		if spvInfo, ok := statusResp["spv"].(map[string]interface{}); ok {
			if proofs, ok := spvInfo["proofs_stored"].(float64); ok {
				pass("stored proofs: %d", int(proofs))
			}
			if validations, ok := spvInfo["validations"].(map[string]interface{}); ok {
				if invalid, ok := validations["invalid"].(float64); ok && invalid > 0 {
					warn("SPV invalid count observed: %d", int(invalid))
				}
			}
		}
		if warnings, ok := statusResp["warnings"].([]interface{}); ok {
			for _, warning := range warnings {
				warn("node warning: %v", warning)
			}
		}
	} else {
		fail("API not responding at %s: %v — check: systemctl status %s", apiURL, statusErr, svcName)
		issues++
	}

	if apiAvailable {
		if corsOK(apiURL + "/status") {
			pass("CORS headers present")
		} else {
			warn("no CORS headers on /status — Explorer won't work")
		}
		issues += doctorX402DiscoveryCheck(cfg, apiURL)
	} else {
		skip("CORS headers: API not answering")
		skip("x402 discovery: API not answering")
	}

	// ── Overlay Health ──
	// Surfaces the node's own lookup-notify error rate (from /status), so a
	// broken submit→lookup path — like the V1-BEEF indexing bug an external dev
	// had to report twice — trips OUR check in seconds instead of landing only
	// in logs nobody watches.
	section("Overlay Health")
	if apiAvailable {
		if oh, ok := statusResp["overlay_health"].(map[string]interface{}); ok {
			recent, _ := oh["lookup_errors_recent_1h"].(float64)
			total, _ := oh["lookup_errors_total"].(float64)
			switch {
			case recent > 0:
				warn("%.0f lookup-notify error(s) in the last hour (%.0f since start) — a lookup can't index admitted outputs", recent, total)
				if byTopic, ok := oh["lookup_errors_by_topic"].(map[string]interface{}); ok {
					for topic, v := range byTopic {
						th, ok := v.(map[string]interface{})
						if !ok {
							continue
						}
						if r, _ := th["recent_1h"].(float64); r > 0 {
							le, _ := th["last_error"].(string)
							warn("  %s: %.0f recent — last: %s", topic, r, le)
						}
					}
				}
				if recent >= 10 {
					issues++ // sustained — a real problem, not just a heads-up
				}
			case total > 0:
				pass("no lookup-notify errors in the last hour (%.0f earlier, since start)", total)
			default:
				pass("no lookup-notify errors")
			}
		} else {
			pass("overlay health metrics not reported (older node)")
		}
	} else {
		skip("overlay health: API not answering")
	}

	// ── Gateway ──
	section("Gateway")
	issues += doctorGatewayChecksWithAPI(cfg, apiURL, liveTXTStatus, livePortBound, apiAvailable)

	// ── 5. External connectivity ──
	section("External Connectivity")

	// BSV seed nodes. Header sync needs only ONE reachable peer — the syncer
	// rotates past any that fail, and config.ensureFallbackSeeds intentionally
	// lists several so a single flaky/down seed is tolerated. So a down fallback
	// is a warning, not a fault; only fail the run when EVERY configured peer is
	// unreachable (a genuine can't-sync outage).
	reachableBSV := 0
	for _, node := range cfg.BSV.Nodes {
		host := strings.Split(node, ":")[0]
		if canResolve(host) {
			pass("BSV node reachable: %s", node)
			reachableBSV++
		} else {
			warn("BSV node unreachable: %s (fallback — sync uses another peer)", node)
		}
	}
	if len(cfg.BSV.Nodes) > 0 && reachableBSV == 0 {
		fail("no BSV peer reachable — header sync cannot proceed")
		issues++
	}

	// ARC
	if cfg.ARC.Enabled {
		arcResp := httpGet(cfg.ARC.URL + "/v1/policy")
		if arcResp != nil {
			pass("ARC responding: %s", cfg.ARC.URL)
		} else {
			warn("ARC not responding: %s (tx broadcast may fail)", cfg.ARC.URL)
		}
	}

	// WoC (used by UTXO scanner)
	wocResp := httpGet("https://api.whatsonchain.com/v1/bsv/main/chain/info")
	if wocResp != nil {
		pass("WhatsOnChain API reachable")
	} else {
		warn("WhatsOnChain unreachable (UTXO scanner will fail)")
	}

	// ── 6. Mesh peers ──
	section("Mesh Peers")
	if apiAvailable {
		// Try to get envelope count to verify store is working
		envResp := httpGet(apiURL + "/data?topic=*&limit=0")
		if envResp != nil {
			pass("envelope store responding")
		}
	} else {
		skip("envelope store: API not answering")
	}

	if apiAvailable {
		meshResp := httpGet(apiURL + "/mesh/status")
		if meshResp != nil {
			if mesh, ok := meshResp["mesh"].(map[string]interface{}); ok {
				if peers, ok := mesh["peers"].(float64); ok {
					if int(peers) > 0 {
						pass("live mesh peers: %d", int(peers))
					} else if len(cfg.Mesh.Seeds) > 0 {
						warn("live mesh peers: 0 — check firewall, seed config, and remote node health")
					}
				}
			}
		}
	} else {
		skip("local mesh status: API not answering")
	}

	// Check if any mesh seeds are configured and try their API
	for _, seed := range cfg.Mesh.Seeds {
		seedAPI := meshSeedToAPI(seed)
		if seedAPI != "" {
			peerStatus := httpGet(seedAPI + "/status")
			if peerStatus != nil {
				pass("mesh peer responding: %s", seedAPI)
			} else {
				warn("mesh peer not responding: %s", seedAPI)
			}
		}
	}

	// ── 7. Wallet ──
	section("Wallet")
	if !apiAvailable {
		skip("wallet: API not answering")
		skip("BRC-121: API not answering")
		skip("payment paths: API not answering")
	} else if cfg.API.AuthToken != "" {
		walletResp := httpGetAuth(apiURL+"/wallet/outputs", cfg.API.AuthToken)
		if walletResp != nil {
			if outputs, ok := walletResp["totalOutputs"].(float64); ok {
				pass("wallet responding: %d outputs", int(outputs))
				if total, ok := walletResp["outputs"].([]interface{}); ok {
					sats := 0
					for _, o := range total {
						if om, ok := o.(map[string]interface{}); ok {
							if s, ok := om["satoshis"].(float64); ok {
								sats += int(s)
							}
						}
					}
					if sats > 0 {
						pass("wallet balance: %d sats", sats)
					} else {
						warn("wallet has 0 sats — run: sudo anvil info  to get your funding address")
					}
				}
			}
		} else {
			warn("wallet not responding (may need funding)")
		}
		issues += doctorBRC121(apiURL, cfg.API.AuthToken)
		issues += doctorPaymentPathCheck(cfg, apiURL)
	} else {
		issues += doctorBRC121(apiURL, cfg.API.AuthToken)
		issues += doctorPaymentPathCheck(cfg, apiURL)
	}
	// ── 8. Self-healing checks (orphans, crash loops, version skew) ──
	section("Self-Healing Checks")
	issues += runSelfHealingChecksWithAPI(cfg.Node.DataDir, apiURL, fix, *yes, apiAvailable)

	// ── Summary ──
	fmt.Println()
	if issues == 0 {
		fmt.Println("=== All checks passed ===")
		os.Exit(0)
	} else {
		fmt.Printf("=== %d issue(s) found ===\n", issues)
		os.Exit(1)
	}
}
