package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/diagnostics"
	anvilversion "github.com/BSVanon/Anvil/internal/version"
)

const (
	githubRepo   = "BSVanon/Anvil"
	githubAPI    = "https://api.github.com/repos/" + githubRepo + "/releases/latest"
	githubDL     = "https://github.com/" + githubRepo + "/releases/download"
	githubLatest = "https://github.com/" + githubRepo + "/releases/latest/download"
)

// cmdUpgrade handles `anvil upgrade` — downloads the latest release binary,
// replaces the installed binary, and restarts systemd services.
//
// Safe by design:
//   - Downloads to temp file first, only overwrites on success
//   - Verifies the new binary runs (help subcommand)
//   - Restarts only services that were running
//   - No config or data changes — only the binary
func cmdUpgrade(args []string) {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	installDir := fs.String("install-dir", "/opt/anvil", "directory containing the anvil binary")
	version := fs.String("version", "latest", "version to install (e.g. v0.5.0, or 'latest')")
	check := fs.Bool("check", false, "check for updates without installing")
	force := fs.Bool("force", false, "install even if already on the latest version")
	healthTimeout := fs.Duration("health-timeout", 300*time.Second, "maximum time to wait for restarted service APIs")
	_ = fs.Parse(args)
	if *healthTimeout <= 0 {
		fatal("--health-timeout must be greater than zero")
	}

	current := anvilversion.Version

	// Resolve latest version from GitHub
	latest, downloadURL := resolveRelease(*version)

	if *check {
		printVersionCheck(current, latest)
		return
	}

	// Compare without "v" prefix — don't downgrade
	latestClean := strings.TrimPrefix(latest, "v")
	if versionNewerOrEqual(current, latestClean) && !*force {
		if current == latestClean {
			fmt.Printf("  Already on %s (latest). Use --force to reinstall.\n", current)
		} else {
			fmt.Printf("  Current %s is ahead of release %s. Use --force to downgrade.\n", current, latest)
		}
		return
	}

	assertRoot()

	fmt.Println("=== Anvil Upgrade ===")
	fmt.Printf("  current:  %s\n", current)
	fmt.Printf("  target:   %s\n", latest)
	fmt.Println()

	// Download to temp file
	step("Downloading binary")
	tmpFile, err := os.CreateTemp("", "anvil-upgrade-*")
	if err != nil {
		fatal("create temp file: " + err.Error())
	}
	tmpPath := tmpFile.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	resp, err := http.Get(downloadURL)
	if err != nil {
		fatal("download failed: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fatal(fmt.Sprintf("download returned %d (URL: %s)", resp.StatusCode, downloadURL))
	}

	written, err := io.Copy(tmpFile, resp.Body)
	_ = tmpFile.Close()
	if err != nil {
		fatal("download write failed: " + err.Error())
	}
	_ = os.Chmod(tmpPath, 0755)
	ok(fmt.Sprintf("Downloaded %s (%.1f MB)", latest, float64(written)/(1024*1024)))

	// Verify SHA256 checksum against checksums.txt from the same release
	step("Verifying checksum")
	checksumURL := ""
	if *version == "latest" {
		checksumURL = githubLatest + "/checksums.txt"
	} else {
		v := latest
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		checksumURL = githubDL + "/" + v + "/checksums.txt"
	}
	chkResp, err := http.Get(checksumURL)
	if err != nil {
		fatal("download checksums.txt failed: " + err.Error())
	}
	defer chkResp.Body.Close()
	if chkResp.StatusCode != 200 {
		fatal(fmt.Sprintf("checksums.txt returned %d", chkResp.StatusCode))
	}
	chkBody, err := io.ReadAll(chkResp.Body)
	if err != nil {
		fatal("read checksums.txt: " + err.Error())
	}

	expectedHash := ""
	binaryFile := binaryName()
	for _, line := range strings.Split(string(chkBody), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == binaryFile {
			expectedHash = parts[0]
			break
		}
	}
	if expectedHash == "" {
		fatal("no checksum found for " + binaryFile + " in checksums.txt")
	}

	actualHash, err := fileSHA256(tmpPath)
	if err != nil {
		fatal("compute checksum: " + err.Error())
	}
	if actualHash != expectedHash {
		fatal(fmt.Sprintf("SHA256 MISMATCH!\n  expected: %s\n  got:      %s\n  The binary may have been tampered with.", expectedHash, actualHash))
	}
	ok("SHA256 verified: " + actualHash[:16] + "...")

	// Verify the new binary runs
	step("Verifying new binary")
	out, err := exec.Command(tmpPath, "help").CombinedOutput()
	if err != nil {
		fatal(fmt.Sprintf("new binary failed to run: %v\n%s", err, string(out)))
	}
	ok("Binary verified")

	// Find running services to restart after
	step("Checking running services")
	services := runningAnvilServices()
	if len(services) > 0 {
		fmt.Printf("    running: %s\n", strings.Join(services, ", "))
	} else {
		fmt.Println("    no anvil services running")
	}

	// Install binary atomically BEFORE stopping services.
	// Strategy: write to temp file in install dir (same filesystem),
	// then os.Rename (atomic on Linux). Services keep running until
	// the new binary is fully on disk.
	step("Installing binary")
	destBin := filepath.Join(*installDir, "anvil")
	if err := os.MkdirAll(*installDir, 0755); err != nil {
		fatal("create install dir: " + err.Error())
	}

	// Backup old binary for rollback
	backupBin := destBin + ".bak"
	backedUp := false
	if _, err := os.Stat(destBin); err == nil {
		if err := copyFileE(destBin, backupBin, 0755); err != nil {
			fmt.Printf("    WARNING: could not backup old binary: %v\n", err)
		} else {
			backedUp = true
		}
	}

	// Atomic replace: copy tmp → install dir staging file, then rename
	stagingBin := destBin + ".new"
	if err := copyFileE(tmpPath, stagingBin, 0755); err != nil {
		fatal("write staging binary failed: " + err.Error())
	}
	if err := os.Rename(stagingBin, destBin); err != nil {
		_ = os.Remove(stagingBin)
		fatal("atomic rename failed: " + err.Error())
	}

	// Update symlink atomically: create new symlink, then rename over old
	symlinkPath := "/usr/local/bin/anvil"
	symlinkTmp := symlinkPath + ".new"
	_ = os.Remove(symlinkTmp)
	if err := os.Symlink(destBin, symlinkTmp); err != nil {
		fmt.Printf("    WARNING: symlink create failed: %v\n", err)
	} else if err := os.Rename(symlinkTmp, symlinkPath); err != nil {
		_ = os.Remove(symlinkTmp)
		fmt.Printf("    WARNING: symlink rename failed: %v\n", err)
	}
	ok("Binary installed: " + destBin)

	// Stop services and kill any orphan anvil processes.
	//
	// systemctl stop only affects processes systemd is tracking. Real-world
	// failure mode (seen in production 2026-04-17): a prior instance of
	// anvil-a crashed but its PID remained running outside systemd's view,
	// holding LevelDB LOCK files. The shared binary got replaced but the
	// orphan kept serving on the port, so the "upgrade succeeded" only in
	// the sense that the tool thought it did.
	//
	// The fix is two-layered:
	//   1. Stop every anvil-*.service systemd knows about.
	//   2. Enumerate ALL anvil processes on the host via diagnostics.FindOrphans
	//      (any /opt/anvil/anvil PID that isn't a tracked systemd MainPID)
	//      and kill them. Includes processes systemd forgot, manual starts,
	//      or prior crashed-but-not-reaped children.
	// After that, /var/lib/anvil*/*/LOCK are all free for the new binary.
	for _, svc := range services {
		_ = exec.Command("systemctl", "stop", svc).Run()
	}
	if len(services) > 0 {
		time.Sleep(1 * time.Second)
		for _, svc := range services {
			killZombieOnPort(apiPort(strings.TrimPrefix(svc, "anvil-")))
		}
		ok("Services stopped")
	}

	// Orphan sweep AFTER systemd stops so we don't kill the MainPIDs systemd
	// just asked to exit gracefully.
	if orphans, err := diagnostics.FindOrphans(); err == nil && len(orphans) > 0 {
		for _, o := range orphans {
			fmt.Printf("    killing orphan anvil PID %d (%s)\n", o.PID, truncateCmd(o.CmdLine, 70))
			if err := diagnostics.KillOrphan(o); err != nil {
				fmt.Printf("    WARNING: failed to kill orphan PID %d: %v\n", o.PID, err)
			}
		}
	}

	// Ensure every anvil-*.service unit file has the ExecStartPre self-heal
	// hook. Without this, operators who installed on a version prior to
	// v2.2.0 keep old unit files forever — they get the binary improvements
	// from each upgrade but never pick up the systemd-level orphan-auto-heal.
	// Runs AFTER stop so units aren't mid-start when we edit them, and
	// BEFORE service restart so the new hook takes effect on this boot.
	if added := ensureExecStartPreHook(); added > 0 {
		if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
			fmt.Printf("    WARNING: systemctl daemon-reload failed: %v\n", err)
		}
		fmt.Printf("    added self-heal ExecStartPre hook to %d unit file(s)\n", added)
	}

	// Same reasoning, for a gateway unit's bind-80/443 capabilities: an
	// operator who deployed a gateway node before this existed would
	// otherwise keep a unit that can never bind 80 or 443, forever,
	// across every future upgrade.
	if added := ensureGatewayCapabilities(); added > 0 {
		if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
			fmt.Printf("    WARNING: systemctl daemon-reload failed: %v\n", err)
		}
		fmt.Printf("    added gateway bind capabilities to %d unit file(s)\n", added)
	}

	// One-time data migration for the v2 → v3 transition. v3.0.0 is the
	// first release whose engine reads from `ovl3:` LevelDB keys instead
	// of `ovl:`. The migration walks every legacy entry and writes the
	// canonical v3 record + lookup indexes. Without this step, a v3
	// binary boots cleanly but serves no overlay records until BEEF
	// arrives. The subcommand is idempotent so re-runs are safe.
	//
	// We run it AFTER the binary is installed (so we exec the v3 binary)
	// and AFTER services are stopped (so nothing is writing to the
	// LevelDB), but BEFORE services restart (so the new engine never
	// sees the legacy-only state). Each anvil-*.service has its own
	// config file → its own data dir → its own migrate pass.
	migrationRan := false
	if needsV3Migrate(current, latestClean) {
		step("Migrating overlay storage (v2 → v3)")
		serviceConfigs := extractServiceConfigs("/etc/systemd/system", services)
		if len(serviceConfigs) == 0 {
			fmt.Println("    no per-service config paths found in systemd unit files")
			fmt.Println("    Run manually:  sudo anvil overlay-migrate -config <path>")
		} else {
			var migrateFails []string
			migrateUser := serviceRunAsUser("/etc/systemd/system", services)
			for _, svc := range services {
				cfgPath, ok := serviceConfigs[svc]
				if !ok {
					continue
				}
				fmt.Printf("    %s → %s (as user %s)\n", svc, cfgPath, migrateUser)
				// Drop privileges to the service's User= so the new LevelDB
				// files land with the same ownership as the existing data
				// (production: anvil:anvil). Without this, root-owned SST
				// files appear in /var/lib/anvil/overlay/*; harmless at
				// runtime since the dir is anvil-owned, but bad hygiene.
				cmd := exec.Command("sudo", "-u", migrateUser, destBin, "overlay-migrate", "-config", cfgPath)
				migrationRan = true
				out, runErr := cmd.CombinedOutput()
				fmt.Print(string(out))
				if runErr != nil {
					migrateFails = append(migrateFails, svc)
				}
			}
			if len(migrateFails) > 0 {
				fmt.Printf("    overlay-migrate failed for: %s\n", strings.Join(migrateFails, ", "))
				fatal("overlay-migrate failed after a data migration was started; automatic rollback is unsafe because an older binary may not read migrated data\n" +
					"manual intervention required for units: " + strings.Join(migrateFails, ", ") + "\n" +
					"inspect the migration output above and keep the new binary in place while repairing the affected data")
			}
			ok(fmt.Sprintf("Overlay migrated for %d node(s)", len(serviceConfigs)))
		}
	}

	// Restart only services that were running before the upgrade, then require
	// each readable, configured API to answer /status before accepting the new
	// binary. A migration makes automatic binary rollback unsafe.
	if len(services) > 0 {
		endpoints, markerPaths, configFailures := serviceHealthEndpoints("/etc/systemd/system", services)
		for _, svc := range services {
			if err, failed := configFailures[svc]; failed {
				fmt.Printf("    WARNING: skipping health check for %s: %v\n", svc, err)
			}
		}
		step("Restarting services")
		fmt.Printf("    waiting up to %v for configured /status endpoints\n", *healthTimeout)
		plan := upgradeRestartPlan{
			services:        services,
			endpoints:       endpoints,
			markerPaths:     markerPaths,
			destination:     destBin,
			backup:          backupBin,
			backupAvailable: backedUp,
			migrationRan:    migrationRan,
			timeout:         *healthTimeout,
		}
		if err := restartServicesWithHealth(plan, productionUpgradeHealthDeps()); err != nil {
			fatal(err.Error())
		}
		ok("Services restarted and healthy: " + strings.Join(services, ", "))
	}

	// Clean up backup
	if backedUp {
		_ = os.Remove(backupBin)
	}

	allVerified := true
	// Auto-run doctor --yes so any lingering post-upgrade issues (stale
	// headers after a reorg, a unit stuck in activating, version skew
	// between services) get detected and fixed without the operator
	// having to remember. FOOLPROOF self-heal: every upgrade ends with
	// a diagnose+fix+verify pass. v2.3.0+.
	step("Running post-upgrade self-heal (anvil doctor --yes)")
	doctorCmd := exec.Command(destBin, "doctor", "--yes")
	doctorCmd.Stdout = os.Stdout
	doctorCmd.Stderr = os.Stderr
	if err := doctorCmd.Run(); err != nil {
		// Doctor returns non-zero when it finds unresolved issues; that
		// isn't an upgrade failure in itself — the new binary IS installed.
		// Surface the warning and let the operator act on the output.
		fmt.Printf("    WARNING: post-upgrade doctor reported unresolved issues: %v\n", err)
		allVerified = false
	}

	fmt.Println()
	if allVerified {
		fmt.Printf("  Upgrade complete: %s → %s\n", current, latest)
	} else {
		fmt.Printf("  Upgrade partial: binary is %s but some issues need manual follow-up (see doctor output above)\n", latest)
	}
	fmt.Println()
}
