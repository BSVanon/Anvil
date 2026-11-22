package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
)

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
func skip(f string, a ...interface{}) {
	fmt.Printf("  - %s (skipped)\n", fmt.Sprintf(f, a...))
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

func doctorStatusProbe(apiURL string) (map[string]interface{}, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(apiURL + "/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /status returned %s", resp.Status)
	}
	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
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
