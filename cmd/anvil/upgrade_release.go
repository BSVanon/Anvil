package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/diagnostics"
	anvilversion "github.com/BSVanon/Anvil/internal/version"
)

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

// runningAnvilServices returns systemd service names whose units exist on
// this host AND are in a state we should try to restart after upgrade.
// "activating" is included because a crash-looping service (our production
// scenario) is technically activating, not active, and we still want to
// restart it on the new binary — the orphan kill we do first should let it
// come up cleanly.
func runningAnvilServices() []string {
	states, err := diagnostics.EnumerateAnvilServices()
	if err != nil {
		// Fall back to the historical hardcoded list if enumeration fails
		// (e.g. systemctl not installed in a test env). Preserves the prior
		// behavior exactly.
		var running []string
		for _, svc := range []string{"anvil-a", "anvil-b"} {
			out, err := exec.Command("systemctl", "is-active", svc).Output()
			if err == nil && strings.TrimSpace(string(out)) == "active" {
				running = append(running, svc)
			}
		}
		return running
	}
	var running []string
	for _, s := range states {
		if s.ActiveState == "active" || s.ActiveState == "activating" {
			running = append(running, s.Name)
		}
	}
	return running
}

// truncateCmd returns s truncated to n characters with a trailing ellipsis
// if it was shortened. Kept here (not shared with doctor.go) to avoid
// introducing a shared file just for a single helper.
func truncateCmd(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
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

// verifyServiceOnVersion polls a service's /status endpoint until it
// reports the expected version, or returns an error after timeout.
func verifyServiceOnVersion(svc, port, expected string, timeout time.Duration, get func(string) string) error {
	deadline := time.Now().Add(timeout)
	const pollInterval = 3 * time.Second
	for {
		running := get(port)
		if running == expected {
			return nil
		}
		if running != "" {
			return fmt.Errorf("%s on :%s running v%s, expected v%s (try: sudo systemctl restart %s)",
				svc, port, running, expected, svc)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s on :%s not responding after %v (check: sudo journalctl -u %s)",
				svc, port, timeout, svc)
		}
		time.Sleep(pollInterval)
	}
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
