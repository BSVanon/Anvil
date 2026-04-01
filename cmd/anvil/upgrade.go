package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

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
	_ = fs.Parse(args)

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

	// Stop services and kill any zombie processes holding ports.
	// systemctl stop can miss processes started outside systemd (manual runs),
	// leaving the old binary serving on the port. Without this, the upgrade
	// silently fails and the old version keeps running.
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

	// Restart services — roll back if all fail to start
	if len(services) > 0 {
		step("Restarting services")
		startFails := 0
		for _, svc := range services {
			if err := exec.Command("systemctl", "start", svc).Run(); err != nil {
				fmt.Printf("    WARNING: failed to start %s: %v\n", svc, err)
				startFails++
			}
		}
		if startFails == len(services) && backedUp {
			fmt.Println("    All services failed to start — rolling back")
			if err := os.Rename(backupBin, destBin); err == nil {
				for _, svc := range services {
					_ = exec.Command("systemctl", "start", svc).Run()
				}
				fatal("upgrade rolled back — all services failed with new binary")
			}
			fatal("rollback also failed — manual intervention required")
		}
		time.Sleep(2 * time.Second)
		ok("Services restarted: " + strings.Join(services, ", "))
	}

	// Clean up backup
	if backedUp {
		_ = os.Remove(backupBin)
	}

	// Verify each service is running the new version — catches zombie processes,
	// failed starts, and port conflicts that systemctl doesn't report.
	step("Verifying upgrade")
	time.Sleep(2 * time.Second)
	allVerified := true
	for _, svc := range services {
		port := apiPort(strings.TrimPrefix(svc, "anvil-"))
		runningVersion := fetchRunningVersion(port)
		latestClean := strings.TrimPrefix(latest, "v")
		if runningVersion == latestClean {
			ok(fmt.Sprintf("%s on :%s running v%s", svc, port, runningVersion))
		} else if runningVersion != "" {
			fmt.Printf("  ✗ %s on :%s still running v%s (expected %s)\n", svc, port, runningVersion, latestClean)
			fmt.Printf("    Try: sudo systemctl restart %s\n", svc)
			allVerified = false
		} else {
			fmt.Printf("  ✗ %s on :%s not responding\n", svc, port)
			allVerified = false
		}
	}

	fmt.Println()
	if allVerified {
		fmt.Printf("  Upgrade complete: %s → %s\n", current, latest)
	} else {
		fmt.Printf("  Upgrade partial: binary is %s but some services need manual restart\n", latest)
	}
	fmt.Println()
}

// resolveRelease determines the download URL for a given version.
func resolveRelease(version string) (tag, url string) {
	binary := binaryName()

	if version == "latest" {
		tag = fetchLatestTag()
		return tag, githubLatest + "/" + binary
	}

	// Normalize: ensure "v" prefix
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	return version, githubDL + "/" + version + "/" + binary
}

// fetchLatestTag queries the GitHub API for the latest release tag.
func fetchLatestTag() string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(githubAPI)
	if err != nil {
		fatal("GitHub API request failed: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fatal(fmt.Sprintf("GitHub API returned %d", resp.StatusCode))
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		fatal("parse GitHub response: " + err.Error())
	}
	if release.TagName == "" {
		fatal("no releases found on GitHub")
	}
	return release.TagName
}

// binaryName returns the expected release artifact name for this platform.
func binaryName() string {
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		return "anvil-linux-amd64"
	case "arm64":
		return "anvil-linux-arm64"
	default:
		fatal("unsupported architecture: " + arch)
		return ""
	}
}

// runningAnvilServices returns systemd service names that are currently active.
func runningAnvilServices() []string {
	var running []string
	for _, svc := range []string{"anvil-a", "anvil-b"} {
		out, err := exec.Command("systemctl", "is-active", svc).Output()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			running = append(running, svc)
		}
	}
	return running
}

// copyFileE copies src to dst with given permissions, returning any error.
// Unlike copyFile (deploy.go), this does not call fatal — the caller decides.
func copyFileE(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return out.Close()
}

func printVersionCheck(current, latest string) {
	fmt.Printf("  current: %s\n", current)
	fmt.Printf("  latest:  %s\n", latest)
	latestClean := strings.TrimPrefix(latest, "v")
	if current == latestClean || current == latest {
		fmt.Println("  up to date")
	} else if versionNewerOrEqual(current, latestClean) {
		fmt.Println("  up to date (ahead of latest release)")
	} else {
		fmt.Println("  upgrade available")
		fmt.Println()
		fmt.Println("  Run: sudo anvil upgrade")
	}
}

// versionNewerOrEqual returns true if a >= b using simple semver comparison.
func versionNewerOrEqual(a, b string) bool {
	ap := parseVersion(a)
	bp := parseVersion(b)
	for i := 0; i < 3; i++ {
		if ap[i] > bp[i] {
			return true
		}
		if ap[i] < bp[i] {
			return false
		}
	}
	return true // equal
}

func parseVersion(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	var parts [3]int
	_, _ = fmt.Sscanf(v, "%d.%d.%d", &parts[0], &parts[1], &parts[2])
	return parts
}

// fileSHA256 computes the SHA256 hash of a file and returns it as a hex string.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// killZombieOnPort finds and kills any process listening on the given port.
// Handles the case where systemctl stop misses processes started outside systemd.
func killZombieOnPort(port string) {
	out, err := exec.Command("fuser", fmt.Sprintf("%s/tcp", port)).Output()
	if err != nil || len(out) == 0 {
		return // nothing on this port
	}
	pids := strings.Fields(strings.TrimSpace(string(out)))
	for _, pid := range pids {
		fmt.Printf("    killing zombie PID %s on port %s\n", pid, port)
		_ = exec.Command("kill", "-9", pid).Run()
	}
	time.Sleep(500 * time.Millisecond)
}

// fetchRunningVersion queries a node's /status endpoint and returns the version string.
func fetchRunningVersion(port string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s/status", port))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var status struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return ""
	}
	return status.Version
}

// checkForUpdate queries GitHub for the latest release and logs if behind.
// Called once on startup in a goroutine — never blocks the node.
func checkForUpdate(logger *slog.Logger) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(githubAPI)
	if err != nil {
		return // silent — don't spam logs if offline
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil || release.TagName == "" {
		return
	}
	latestClean := strings.TrimPrefix(release.TagName, "v")
	current := anvilversion.Version
	if !versionNewerOrEqual(current, latestClean) {
		logger.Warn("update available",
			"current", current,
			"latest", release.TagName,
			"upgrade", "sudo anvil upgrade")
	}
}
