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

// cmdDoctor handles `anvil doctor` — validates config, dirs, connectivity,
// and mesh health. Without flags it's diagnostic-only (exits 0 if healthy,
// 1 if any check fails).
//
// With --fix it additionally offers to remediate:
//   - orphan anvil processes (e.g. manual starts that systemd isn't tracking)
//   - crash-looping systemd units (stopped stuck)
//   - stale header stores with prev-hash-mismatch errors
//   - running-process version ≠ binary-on-disk version
//
// With --yes remediations run without per-action prompts (for unattended use).
//
// With --fix-locks-only, only the orphan-kill remediation runs, all other
// checks are skipped, and the command exits 0 regardless of other issues.
// Designed to be called from a systemd ExecStartPre hook so a service whose
// prior instance left an orphan lock holder can start cleanly without
// operator intervention.
func cmdDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to config file")
	fix := fs.Bool("fix", false, "execute remediations for detected issues")
	yes := fs.Bool("yes", false, "skip confirmation prompts (use with --fix)")
	locksOnly := fs.Bool("fix-locks-only", false, "only resolve orphan-lock contention; skip other checks; implies --fix --yes")
	_ = fs.Parse(args)

	if *locksOnly {
		*fix = true
		*yes = true
		runFixLocksOnly()
		return
	}

	loadEnvFile(*configPath)

	fmt.Println("=== Anvil Doctor ===")
	if *fix {
		fmt.Println("  mode: diagnose + fix")
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
	issues += runSelfHealingChecks(cfg.Node.DataDir, *fix, *yes)

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
func runSelfHealingChecks(dataDir string, fix, yes bool) int {
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
				if fix && confirm(yes, fmt.Sprintf("    Restart %s (journalctl -u %s for root cause)?", s.Name, s.Name)) {
					if err := exec.Command("systemctl", "reset-failed", s.Name+".service").Run(); err != nil {
						fmt.Printf("      ✗ reset-failed: %v\n", err)
					}
					if err := exec.Command("systemctl", "restart", s.Name+".service").Run(); err != nil {
						fmt.Printf("      ✗ restart failed: %v\n", err)
						unresolved++
					} else {
						fmt.Printf("      ✓ restarted %s\n", s.Name)
					}
				} else {
					unresolved++
				}
			}
		}
	}

	// ── Stale header store with prev-hash-mismatch ──
	// The presence of "prev hash mismatch" in the sync error is sufficient
	// to flag this regardless of lag severity. The stored chain is
	// reorg-incompatible with the current BSV tip and will NEVER recover
	// without a rebuild — every additional minute of lag just makes the
	// diagnosis more obvious. v2.2.2 gated this on lag > 7200s which was
	// too conservative for operator-invoked --fix (observed 2026-04-17:
	// operator ran --fix at ~6260s lag, got no remediation offered,
	// had to wipe manually). Fixed in v2.2.3.
	if lag, errMsg, have := checkHeaderSyncHealth(dataDir); have {
		if strings.Contains(strings.ToLower(errMsg), "prev hash mismatch") {
			fail("header store stuck: lag=%ds with prev-hash-mismatch (reorg-incompatible, won't recover without rebuild)", lag)
			if fix && confirm(yes, fmt.Sprintf("    Wipe %s/headers/ and let the node resync from genesis (~30s)?", dataDir)) {
				if err := wipeHeadersDir(dataDir); err != nil {
					fmt.Printf("      ✗ wipe failed: %v\n", err)
					unresolved++
				} else {
					fmt.Printf("      ✓ wiped %s/headers/ — restart the service to trigger resync\n", dataDir)
				}
			} else {
				unresolved++
			}
		}
	}

	// ── Running-version != binary-on-disk ──
	onDisk := diagnostics.BinaryVersion(diagnostics.AnvilBinaryPath)
	running := anvilversion.Version
	if onDisk != "" && onDisk != running {
		fail("running version v%s ≠ binary on disk v%s (service needs restart)", running, onDisk)
		if fix && confirm(yes, "    Restart anvil services to pick up the new binary?") {
			for _, s := range svcs {
				if s.ActiveState == "active" || s.ActiveState == "activating" {
					if err := exec.Command("systemctl", "restart", s.Name+".service").Run(); err != nil {
						fmt.Printf("      ✗ restart %s: %v\n", s.Name, err)
						unresolved++
					} else {
						fmt.Printf("      ✓ restarted %s\n", s.Name)
					}
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

// runFixLocksOnly is the safe subset of self-healing that is called from
// systemd's ExecStartPre. It only kills orphan anvil processes (so the
// service unit can actually bind LevelDB locks on its own next start).
// It MUST NOT block indefinitely, and MUST exit 0 regardless of what it
// finds — otherwise a transient diagnostic failure would block every start.
func runFixLocksOnly() {
	orphans, err := diagnostics.FindOrphans()
	if err != nil {
		fmt.Printf("anvil doctor --fix-locks-only: orphan scan failed: %v\n", err)
		os.Exit(0)
	}
	for _, o := range orphans {
		fmt.Printf("anvil doctor --fix-locks-only: killing orphan PID %d (%s)\n",
			o.PID, truncStr(o.CmdLine, 80))
		if err := diagnostics.KillOrphan(o); err != nil {
			fmt.Printf("anvil doctor --fix-locks-only: kill PID %d failed: %v\n", o.PID, err)
		}
	}
	os.Exit(0)
}

// checkHeaderSyncHealth pokes /status to get the lag + last error, returning
// whether we have enough data to make a decision. Separate from the earlier
// /status probe because that one runs via httpGet which decodes into a map;
// we need to pull two specific fields without re-defining the whole shape.
func checkHeaderSyncHealth(dataDir string) (lagSecs int, lastErr string, have bool) {
	// Use a short-lived probe to the local API. If the service isn't running
	// we can't get this info; return have=false to let the caller skip.
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:9333/status")
	if err != nil {
		// Try 9334 (Node B) as a fallback
		resp, err = client.Get("http://127.0.0.1:9334/status")
		if err != nil {
			return 0, "", false
		}
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
