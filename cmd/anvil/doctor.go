package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/diagnostics"
	anvilversion "github.com/BSVanon/Anvil/internal/version"
)

// cmdDoctor handles `anvil doctor` — diagnoses node health and offers to
// remediate any findings interactively (default behavior, v2.3.0+).
//
// Flags:
//
//	(none)          Diagnose + prompt y/N per finding that has a remediation.
//	                This is the default because operator ergonomics should
//	                not require flag knowledge. See 2026-04-17 post-mortem:
//	                prior "doctor is diagnostic, --fix is remediation"
//	                split meant operators kept hitting issues and not
//	                realizing a fix existed a flag away.
//
//	--yes           Apply all remediations without prompts. For scripts and
//	                the auto-run from `anvil upgrade`. Each remediation
//	                still runs its post-apply verification — a command that
//	                returns exit 0 means the condition is actually resolved.
//
//	--locks-only    Only run the orphan-kill remediation, exit 0 regardless.
//	                Narrow + safe for systemd ExecStartPre. Never touches
//	                destructive remediations (no header wipe, no service
//	                restart loops).
//
//	--no-fix        Diagnostic only. Historical read-only mode for operators
//	                who explicitly want to see state without any prompts.
//
// Legacy aliases (still accepted for backward compatibility with scripts
// written against v2.2.x releases):
//
//	--fix              equivalent to default behavior (fix-interactive)
//	--fix-locks-only   equivalent to --locks-only
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
		pass("identity WIF present (%s...)", cfg.Identity.WIF[:8])
	}

	if cfg.API.AuthToken == "" {
		fail("auth token not derived (WIF missing or invalid)")
		issues++
	} else {
		pass("auth token derived (%s...)", cfg.API.AuthToken[:12])
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
	statusResp := httpGet(apiURL + "/status")
	// v3.0.4: retry the initial probe with backoff if the daemon may
	// still be booting. `anvil upgrade` runs doctor immediately after
	// services restart, but the daemon can take 10-30 seconds to bind
	// the HTTP listener on busy nodes (large wallet load, header init,
	// ExecStartPre doctor pass). Without this retry, doctor false-flags
	// API as down even though the daemon comes up cleanly seconds later,
	// causing "Upgrade partial" reports for upgrades that actually
	// succeeded.
	//
	// Fast path: if the first probe succeeds, no retry. Slow path: poll
	// every 3s for up to 30s, then accept the original "not responding"
	// diagnosis if the daemon is genuinely down.
	if statusResp == nil {
		fmt.Println("  ⏳ API not yet responding — retrying for up to 30s (daemon may still be booting)...")
		retryDeadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(retryDeadline) {
			time.Sleep(3 * time.Second)
			if r := httpGet(apiURL + "/status"); r != nil {
				statusResp = r
				break
			}
		}
	}
	if statusResp != nil {
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
		fail("API not responding at %s", apiURL)
		issues++
	}

	// CORS check
	if corsOK(apiURL + "/status") {
		pass("CORS headers present")
	} else {
		warn("no CORS headers on /status — Explorer won't work")
	}

	// x402 discovery
	x402Resp := httpGet(apiURL + "/.well-known/x402")
	if cfg.API.PaymentSatoshis > 0 {
		if x402Resp != nil {
			pass("x402 discovery responding")
		} else {
			fail("x402 discovery not responding (payment_satoshis=%d but /.well-known/x402 returns 404)", cfg.API.PaymentSatoshis)
			issues++
		}
	} else {
		if x402Resp == nil {
			pass("x402 disabled (payment_satoshis=0)")
		}
	}

	// ── 5. External connectivity ──
	section("External Connectivity")

	// BSV seed node
	for _, node := range cfg.BSV.Nodes {
		host := strings.Split(node, ":")[0]
		if canResolve(host) {
			pass("BSV node reachable: %s", node)
		} else {
			fail("BSV node unreachable: %s", node)
			issues++
		}
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
	if statusResp != nil {
		// Try to get envelope count to verify store is working
		envResp := httpGet(apiURL + "/data?topic=*&limit=0")
		if envResp != nil {
			pass("envelope store responding")
		}
	}

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
	if cfg.API.AuthToken != "" {
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
	}

	// ── 8. Self-healing checks (orphans, crash loops, version skew) ──
	section("Self-Healing Checks")
	issues += runSelfHealingChecks(cfg.Node.DataDir, apiURL, fix, *yes)

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

// runSelfHealingChecks runs the four checks that cover every failure mode
// we've seen in production post-mortems: orphan processes, crash-looping
// systemd units, stale header stores, and version skew between the
// on-disk binary and a running process. Returns the number of unresolved
// issues (zero if fix applied everything, or if --fix wasn't set and
// nothing was found).
func runSelfHealingChecks(dataDir, apiURL string, fix, yes bool) int {
	unresolved := 0

	// ── Orphan anvil processes ──
	orphans, err := diagnostics.FindOrphans()
	if err != nil {
		warn("orphan scan failed: %v", err)
	} else if len(orphans) == 0 {
		pass("no orphan anvil processes")
	} else {
		for _, o := range orphans {
			fail("orphan anvil process PID=%d cmdline=%q", o.PID, truncStr(o.CmdLine, 80))
			if fix && confirm(yes, fmt.Sprintf("    Kill PID %d?", o.PID)) {
				if err := diagnostics.KillOrphan(o); err != nil {
					fmt.Printf("      ✗ kill failed: %v\n", err)
					unresolved++
				} else {
					fmt.Printf("      ✓ killed PID %d\n", o.PID)
				}
			} else {
				unresolved++
			}
		}
	}

	// ── Crash-looping systemd units ──
	svcs, err := diagnostics.EnumerateAnvilServices()
	if err != nil {
		warn("service scan failed: %v", err)
	} else {
		for _, s := range svcs {
			if diagnostics.IsCrashLooping(s) {
				fail("service %s crash-looping (NRestarts=%d, state=%s/%s)",
					s.Name, s.NRestarts, s.ActiveState, s.SubState)
				// Likely root cause is an orphan we may have just killed above;
				// a systemctl restart after orphan kill will usually clear it.
				if fix && confirm(yes, fmt.Sprintf("    Restart %s (journalctl -u %s for root cause) and verify it stays up?", s.Name, s.Name)) {
					if err := applyServiceRestartAndVerify(s.Name); err != nil {
						fmt.Printf("      ✗ %v\n", err)
						unresolved++
					}
				} else {
					unresolved++
				}
			}
		}
	}

	// ── Stale header store with prev-hash-mismatch ──
	// The presence of "prev hash mismatch" in the sync error is sufficient
	// to flag this regardless of lag severity — the stored chain is
	// reorg-incompatible with the current BSV tip and will NEVER recover
	// without a rebuild.
	//
	// IMPORTANT: the wipe alone does NOT complete the fix. Linux keeps
	// unlinked-file inodes alive for the running process, so anvil-a keeps
	// operating on the "ghost" header store until the process exits.
	// Pre-v2.3.0 the operator was told "restart the service to trigger
	// resync" but many forgot, leaving a wiped-yet-stuck node (observed
	// 2026-04-17). v2.3.0 folds the restart AND a post-restart verify
	// (lag dropped below pre-wipe value) into the remediation itself.
	if lag, errMsg, have := checkHeaderSyncHealth(apiURL); have {
		if strings.Contains(strings.ToLower(errMsg), "prev hash mismatch") {
			fail("header store stuck: lag=%ds with prev-hash-mismatch (reorg-incompatible, won't recover without rebuild)", lag)
			if fix && confirm(yes, fmt.Sprintf("    Wipe %s/headers/, restart anvil services, and verify resync starts?", dataDir)) {
				if err := applyHeaderRebuildAndVerify(dataDir, apiURL, svcs, lag); err != nil {
					fmt.Printf("      ✗ %v\n", err)
					unresolved++
				}
			} else {
				unresolved++
			}
		}
	}

	// ── Missing PrivateTmp drop-in (SQLite wallet at risk) ──
	// systemd unit template ships with ProtectSystem=strict +
	// ReadWritePaths=DataDir but pre-v3.0.2 did NOT include
	// PrivateTmp=true. Effect: /tmp is read-only for the daemon, and
	// wallet-toolbox's SQLite returns "disk I/O error: permission
	// denied" the first time it needs a temp file (sort, large temp
	// table) — which surfaces during CreateAction calls on bigger
	// wallets. Discovered in v3.0.0 production on anvil-a (443 MB
	// wallet); v3.0.1 fixed the deploy.go template for fresh installs;
	// v3.0.2 adds this self-heal for existing nodes whose unit files
	// were generated by an older template.
	for _, s := range svcs {
		if !needsPrivateTmpDropin(s.Name) {
			continue
		}
		fail("service %s has ProtectSystem=strict but PrivateTmp=no — SQLite wallet ops will fail with 'disk I/O error: permission denied'", s.Name)
		if fix && confirm(yes, fmt.Sprintf("    Create /etc/systemd/system/%s.service.d/private-tmp.conf with PrivateTmp=true and restart %s?", s.Name, s.Name)) {
			if err := applyPrivateTmpDropin(s.Name); err != nil {
				fmt.Printf("      ✗ %v\n", err)
				unresolved++
			}
		} else {
			unresolved++
		}
	}

	// ── Running-version != binary-on-disk ──
	onDisk := diagnostics.BinaryVersion(diagnostics.AnvilBinaryPath)
	running := anvilversion.Version
	if onDisk != "" && onDisk != running {
		fail("running version v%s ≠ binary on disk v%s (service needs restart)", running, onDisk)
		if fix && confirm(yes, "    Restart anvil services and verify they come up on the new binary?") {
			for _, s := range svcs {
				if s.ActiveState != "active" && s.ActiveState != "activating" {
					continue
				}
				if err := applyServiceRestartAndVerify(s.Name); err != nil {
					fmt.Printf("      ✗ %s: %v\n", s.Name, err)
					unresolved++
				}
			}
		} else {
			unresolved++
		}
	} else if onDisk != "" {
		pass("version match: running v%s = binary v%s", running, onDisk)
	}

	return unresolved
}

// needsPrivateTmpDropin returns true when systemd reports the unit
// as running under ProtectSystem=strict with PrivateTmp=no. That
// combination locks the daemon out of writing /tmp, which breaks
// wallet-toolbox's SQLite the first time it needs a temp file.
//
// Uses `systemctl show` (which respects drop-in overrides) so that an
// operator who manually added a PrivateTmp=true drop-in is correctly
// reported as fixed — we only flag units where the EFFECTIVE setting
// is still unsafe.
//
// Returns false on any error (systemctl missing, unit doesn't exist,
// parse fail) so we never false-positive flag a node that doesn't
// actually have systemd available.
func needsPrivateTmpDropin(svcName string) bool {
	out, err := exec.Command("systemctl", "show", svcName+".service",
		"--property=ProtectSystem", "--property=PrivateTmp").Output()
	if err != nil {
		return false
	}
	return parsePrivateTmpStatus(string(out))
}

// parsePrivateTmpStatus is the testable core of needsPrivateTmpDropin.
// Returns true iff the systemctl-show output reports both
// ProtectSystem=strict AND PrivateTmp=no.
func parsePrivateTmpStatus(systemctlShowOutput string) bool {
	protectStrict := false
	privateTmp := false
	for _, line := range strings.Split(systemctlShowOutput, "\n") {
		switch strings.TrimSpace(line) {
		case "ProtectSystem=strict":
			protectStrict = true
		case "PrivateTmp=yes", "PrivateTmp=true":
			privateTmp = true
		}
	}
	return protectStrict && !privateTmp
}

// applyPrivateTmpDropin creates a systemd drop-in that sets
// PrivateTmp=true for the given anvil service, reloads systemd, and
// restarts the service. Verifies the service comes back up + that
// the effective PrivateTmp value is now true.
//
// The drop-in is named private-tmp.conf so an operator inspecting
// /etc/systemd/system/anvil-*.service.d/ can immediately see what
// the override fixes.
func applyPrivateTmpDropin(svcName string) error {
	dropinDir := filepath.Join("/etc/systemd/system", svcName+".service.d")
	if err := os.MkdirAll(dropinDir, 0755); err != nil {
		return fmt.Errorf("create drop-in dir %s: %w", dropinDir, err)
	}
	dropinPath := filepath.Join(dropinDir, "private-tmp.conf")
	body := "[Service]\nPrivateTmp=true\n"
	if err := os.WriteFile(dropinPath, []byte(body), 0644); err != nil {
		return fmt.Errorf("write %s: %w", dropinPath, err)
	}
	fmt.Printf("      ✓ wrote %s\n", dropinPath)

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	fmt.Println("      ✓ systemctl daemon-reload")

	if err := applyServiceRestartAndVerify(svcName); err != nil {
		return fmt.Errorf("restart %s after drop-in: %w", svcName, err)
	}

	// Verify the override actually took effect via systemctl show
	if needsPrivateTmpDropin(svcName) {
		return fmt.Errorf("PrivateTmp still reported as 'no' after drop-in + reload — manual investigation needed")
	}
	fmt.Printf("      ✓ %s now running with PrivateTmp=true\n", svcName)
	return nil
}

// applyServiceRestartAndVerify performs the systemd reset-failed + restart
// cycle and confirms the service actually comes back up and stays up for
// ~5 seconds (long enough that a crash loop would re-trigger a failure).
// Returns nil only if the service is ActiveState=active when the function
// returns. Matches the header-rebuild pattern: detect → apply → verify.
func applyServiceRestartAndVerify(svcName string) error {
	_ = exec.Command("systemctl", "reset-failed", svcName+".service").Run()
	if err := exec.Command("systemctl", "restart", svcName+".service").Run(); err != nil {
		return fmt.Errorf("restart %s: %w", svcName, err)
	}
	fmt.Printf("      ✓ restart issued to %s\n", svcName)

	// A crash-loop service would go active → failed → activating within a
	// few seconds. Give systemd 5s to settle, then check the state.
	time.Sleep(5 * time.Second)

	svcs, err := diagnostics.EnumerateAnvilServices()
	if err != nil {
		return fmt.Errorf("re-enumerate services for verify: %w", err)
	}
	for _, s := range svcs {
		if s.Name != svcName {
			continue
		}
		if s.ActiveState == "active" && s.SubState == "running" {
			fmt.Printf("      ✓ %s verified active/running post-restart\n", svcName)
			return nil
		}
		return fmt.Errorf("%s is %s/%s after restart (not active/running) — check journalctl -u %s",
			svcName, s.ActiveState, s.SubState, svcName)
	}
	return fmt.Errorf("%s not found in systemd after restart", svcName)
}

// applyHeaderRebuildAndVerify executes the header-rebuild remediation
// end-to-end: wipe headers dir, restart any active anvil services, wait
// for re-sync to kick in, and verify the post-restart lag is STRICTLY
// LESS than the pre-wipe lag. Returns nil only if the full chain succeeded.
//
// This is the "apply + verify" pattern added in v2.3.0 to prevent
// half-done remediations from slipping through. Prior versions only did
// the wipe and told the operator to restart; many forgot, leaving a
// wiped-but-still-stuck node.
func applyHeaderRebuildAndVerify(dataDir, apiURL string, svcs []diagnostics.ServiceState, preLagSecs int) error {
	// Step 1: wipe on-disk header store
	if err := wipeHeadersDir(dataDir); err != nil {
		return fmt.Errorf("wipe %s/headers/: %w", dataDir, err)
	}
	fmt.Printf("      ✓ wiped %s/headers/\n", dataDir)

	// Step 2: restart anvil services so they drop the unlinked-inode handles
	// and start reading from the fresh (empty) header store.
	restartedAny := false
	for _, s := range svcs {
		if s.ActiveState == "active" || s.ActiveState == "activating" {
			if err := exec.Command("systemctl", "restart", s.Name+".service").Run(); err != nil {
				return fmt.Errorf("restart %s: %w", s.Name, err)
			}
			fmt.Printf("      ✓ restarted %s\n", s.Name)
			restartedAny = true
		}
	}
	if !restartedAny {
		// No services were active (unusual). Record the wipe as done but
		// note the operator will need to start at least one service themselves.
		fmt.Println("      ⚠ no active anvil services to restart — start one manually to trigger resync")
		return nil
	}

	// Step 3a: wait for the restarted daemon to come back up. On busy
	// nodes (large wallet load, header init) this can take 10-30s after
	// `systemctl restart`. Pre-v3.0.4 we'd start polling lag immediately
	// and the entire 45s window would expire while checkHeaderSyncHealth
	// returned have=false — best-seen lag never updated from preLag and
	// we'd report "did not decrease meaningfully" even though sync hadn't
	// even been measured.
	fmt.Println("      ⏳ waiting for daemon HTTP listener to come back up...")
	apiUpDeadline := time.Now().Add(60 * time.Second)
	apiReady := false
	for time.Now().Before(apiUpDeadline) {
		time.Sleep(3 * time.Second)
		if _, _, have := checkHeaderSyncHealth(apiURL); have {
			apiReady = true
			break
		}
	}
	if !apiReady {
		return fmt.Errorf("post-wipe daemon never bound its HTTP listener — check journalctl -u anvil-a")
	}

	// Step 3b: now that API is responsive, measure lag decrease.
	// Anvil catches up at thousands of headers/second on a modern VPS,
	// so a sync that's actually working will show ANY meaningful drop
	// within ~90 seconds. Success criterion is "dropped by more than
	// 60 seconds" rather than "less than half" — half-of-preLag (which
	// could be 18 days for a multi-week gap) is a much higher bar than
	// "sync is clearly progressing."
	fmt.Println("      ⏳ waiting for header resync to progress (up to 90s)...")
	deadline := time.Now().Add(90 * time.Second)
	bestLag := preLagSecs
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		lag, _, have := checkHeaderSyncHealth(apiURL)
		if !have {
			continue
		}
		if lag < bestLag {
			bestLag = lag
		}
		if lag > 0 && lag < preLagSecs-60 {
			fmt.Printf("      ✓ resync confirmed: lag dropped %ds → %ds\n", preLagSecs, lag)
			return nil
		}
	}
	return fmt.Errorf("post-wipe lag did not decrease meaningfully (pre=%ds, best-seen=%ds) — investigate manually", preLagSecs, bestLag)
}

// runLocksOnly is the safe subset of self-healing that is called from
// systemd's ExecStartPre. It only kills orphan anvil processes (so the
// service unit can actually bind LevelDB locks on its own next start).
// It MUST NOT block indefinitely, and MUST exit 0 regardless of what it
// finds — otherwise a transient diagnostic failure would block every start.
func runLocksOnly() {
	orphans, err := diagnostics.FindOrphans()
	if err != nil {
		fmt.Printf("anvil doctor --locks-only: orphan scan failed: %v\n", err)
		os.Exit(0)
	}
	for _, o := range orphans {
		fmt.Printf("anvil doctor --locks-only: killing orphan PID %d (%s)\n",
			o.PID, truncStr(o.CmdLine, 80))
		if err := diagnostics.KillOrphan(o); err != nil {
			fmt.Printf("anvil doctor --locks-only: kill PID %d failed: %v\n", o.PID, err)
		}
	}
	os.Exit(0)
}

// checkHeaderSyncHealth pokes /status to get the lag + last error, returning
// whether we have enough data to make a decision. Separate from the earlier
// /status probe because that one runs via httpGet which decodes into a map;
// we need to pull two specific fields without re-defining the whole shape.
//
// v3.0.5+ takes apiURL (the config-specified `http://127.0.0.1:<APIListen>`)
// instead of hardcoding :9333/:9334. Pre-v3.0.5 the function always queried
// :9333 first regardless of the -config flag the operator passed, which made
// `sudo anvil doctor -config /etc/anvil/node-b.toml` falsely report node-b as
// healthy when in fact node-b had its own prev-hash-mismatch — doctor was
// reading node-a's status, not node-b's. Threading apiURL through fixes that.
func checkHeaderSyncHealth(apiURL string) (lagSecs int, lastErr string, have bool) {
	// Use a short-lived probe to the local API. If the service isn't running
	// we can't get this info; return have=false to let the caller skip.
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(apiURL + "/status")
	if err != nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	var s struct {
		Headers struct {
			SyncLagSecs int `json:"sync_lag_secs"`
			Sync        struct {
				LastError string `json:"last_error"`
			} `json:"sync"`
		} `json:"headers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return 0, "", false
	}
	return s.Headers.SyncLagSecs, s.Headers.Sync.LastError, true
}

// wipeHeadersDir removes every entry under <dataDir>/headers/ without
// removing the directory itself. The service will repopulate on next start.
func wipeHeadersDir(dataDir string) error {
	hd := filepath.Join(dataDir, "headers")
	entries, err := os.ReadDir(hd)
	if err != nil {
		return fmt.Errorf("read %s: %w", hd, err)
	}
	for _, e := range entries {
		p := filepath.Join(hd, e.Name())
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	return nil
}

// confirm prompts the operator for a yes/no answer, returning true on "y"
// or "yes" (case-insensitive). If autoYes is set, returns true immediately
// without prompting (for unattended / scripted execution).
func confirm(autoYes bool, prompt string) bool {
	if autoYes {
		fmt.Println(prompt, "[auto-yes]")
		return true
	}
	fmt.Print(prompt, " [y/N] ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return false
	}
	ans := strings.ToLower(strings.TrimSpace(scanner.Text()))
	return ans == "y" || ans == "yes"
}

// truncStr returns s truncated to n characters with a trailing ellipsis if
// it was shortened. Used to keep long cmdlines readable in terminal output.
func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ── Output helpers ──

func section(name string) { fmt.Printf("\n── %s ──\n", name) }
func pass(f string, a ...interface{}) {
	fmt.Printf("  ✓ %s\n", fmt.Sprintf(f, a...))
}
func fail(f string, a ...interface{}) {
	fmt.Printf("  ✗ %s\n", fmt.Sprintf(f, a...))
}
func warn(f string, a ...interface{}) {
	fmt.Printf("  ⚠ %s\n", fmt.Sprintf(f, a...))
}

// ── Check helpers ──

func httpGet(url string) map[string]interface{} {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result
}

func httpGetAuth(url, token string) map[string]interface{} {
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result
}

func corsOK(url string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Head(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.Header.Get("Access-Control-Allow-Origin") != ""
}

func canResolve(host string) bool {
	cmd := exec.Command("getent", "hosts", host)
	return cmd.Run() == nil
}

func fileOwner(path string) string {
	out, err := exec.Command("stat", "-c", "%U", path).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func serviceStatus(name string) string {
	out, _ := exec.Command("systemctl", "is-active", name).Output()
	return strings.TrimSpace(string(out))
}

func guessServiceName(cfg *config.Config) string {
	port := normalizePort(cfg.Node.APIListen)
	if strings.HasSuffix(port, ":9334") {
		return "anvil-b"
	}
	return "anvil-a"
}

func normalizePort(listen string) string {
	if !strings.Contains(listen, ":") {
		return ":" + listen
	}
	// Extract :port from 0.0.0.0:9333
	parts := strings.Split(listen, ":")
	return ":" + parts[len(parts)-1]
}

// doctorCheckLatest returns the latest GitHub release tag, or "" on failure.
func doctorCheckLatest() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(githubAPI)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	var release struct {
		TagName string `json:"tag_name"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&release)
	return release.TagName
}

func meshSeedToAPI(seed string) string {
	// wss://anvil.sendbsv.com/mesh → https://anvil.sendbsv.com
	// ws://127.0.0.1:8333 → http://127.0.0.1:9333
	s := strings.Replace(seed, "wss://", "https://", 1)
	s = strings.Replace(s, "ws://", "http://", 1)
	// Strip path (e.g. /mesh)
	if idx := strings.Index(s[8:], "/"); idx >= 0 {
		s = s[:8+idx]
	}
	s = strings.Replace(s, ":8333", ":9333", 1)
	s = strings.Replace(s, ":8334", ":9334", 1)
	return s
}
