package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/config"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// everything it printed, so doctorGatewayChecks's pass/fail/warn output
// (which prints directly, like the rest of cmdDoctor) can be asserted on
// without a dependency-injected writer.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// noTXTStatus and foundTXTStatus are stub txtStatus functions —
// doctorGatewayChecks must never make a real DNS lookup in a test.
func noTXTStatus(ctx context.Context, domain string) string { return "no _ordfs TXT record found" }
func foundTXTStatus(ctx context.Context, domain string) string {
	return "ordfs=" + domain + "_origin_0"
}

// noAPIURL and noPortBound are this test file's default apiURL/portBound
// stubs: a port on loopback nothing listens on (httpGet fails fast,
// returning nil rather than hanging) and a bind check that always
// reports unbound. Every test below that doesn't care about the TLS
// bind/replication checks specifically uses these, so that behaviour
// stays opt-in per test rather than the default.
const noAPIURL = "http://127.0.0.1:1"

func noPortBound(addr string) bool { return false }

func TestDoctorGatewayChecks_DisabledShortCircuits(t *testing.T) {
	cfg := &config.Config{}
	var called bool
	issues := doctorGatewayChecks(cfg, noAPIURL, func(ctx context.Context, domain string) string {
		called = true
		return "ordfs=x"
	}, noPortBound)
	if issues != 0 {
		t.Errorf("issues = %d, want 0 for a disabled gateway", issues)
	}
	if called {
		t.Error("doctorGatewayChecks called txtStatus although the gateway is disabled")
	}
}

func TestDoctorGatewayChecks_ModeAlwaysReported(t *testing.T) {
	cfg := &config.Config{}
	cfg.Node.Mode = "gateway"
	out := captureStdout(t, func() { doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, noPortBound) })
	if !bytes.Contains([]byte(out), []byte("mode: gateway")) {
		t.Errorf("expected output to report the mode, got:\n%s", out)
	}

	cfg2 := &config.Config{}
	out2 := captureStdout(t, func() { doctorGatewayChecks(cfg2, noAPIURL, noTXTStatus, noPortBound) })
	if !bytes.Contains([]byte(out2), []byte("mode: standard")) {
		t.Errorf("expected an empty mode to report as standard, got:\n%s", out2)
	}
}

func TestDoctorGatewayChecks_SitesFileParseErrorIsAnIssue(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Gateway.Enabled = true
	// A directory where a file is expected makes os.ReadFile fail with a
	// real I/O error (not os.IsNotExist), which readSiteEntries propagates.
	cfg.Gateway.SitesFile = dir

	issues := doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, noPortBound)
	if issues < 1 {
		t.Errorf("issues = %d, want at least 1 when the sites file fails to parse", issues)
	}
}

func TestDoctorGatewayChecks_NoSitesConfiguredIsNotAnIssue(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.Enabled = true
	cfg.Gateway.SitesFile = t.TempDir() + "/gateway-sites.conf" // does not exist
	cfg.Overlay.NamedPeers = []string{"https://peer.example"}
	cfg.Mesh.AllowedPeers = []string{"02" + strings.Repeat("a", 64)}

	issues := doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, noPortBound)
	if issues != 0 {
		t.Errorf("issues = %d, want 0 for an enabled gateway with no sites yet and a closed posture", issues)
	}
}

func TestDoctorGatewayChecks_TXTStatusIsWarnNotIssue(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Gateway.Enabled = true
	cfg.Gateway.SitesFile = dir + "/gateway-sites.conf"
	cfg.Overlay.NamedPeers = []string{"https://peer.example"}
	cfg.Mesh.AllowedPeers = []string{"02" + strings.Repeat("a", 64)}
	if err := os.WriteFile(cfg.Gateway.SitesFile, []byte("domain example.com\n"), 0640); err != nil {
		t.Fatal(err)
	}

	t.Run("missing TXT record", func(t *testing.T) {
		var issues int
		out := captureStdout(t, func() { issues = doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, noPortBound) })
		if issues != 0 {
			t.Errorf("issues = %d, want 0 — a missing TXT record is a warning, not an issue", issues)
		}
		if !bytes.Contains([]byte(out), []byte("example.com")) {
			t.Errorf("expected output to mention example.com, got:\n%s", out)
		}
	})

	t.Run("found TXT record", func(t *testing.T) {
		var issues int
		out := captureStdout(t, func() { issues = doctorGatewayChecks(cfg, noAPIURL, foundTXTStatus, noPortBound) })
		if issues != 0 {
			t.Errorf("issues = %d, want 0", issues)
		}
		if !bytes.Contains([]byte(out), []byte("ordfs=")) {
			t.Errorf("expected output to show the resolved origin, got:\n%s", out)
		}
	})
}

func TestDoctorGatewayChecks_ClosedPostureWarnings(t *testing.T) {
	base := func() *config.Config {
		cfg := &config.Config{}
		cfg.Gateway.Enabled = true
		cfg.Gateway.SitesFile = t.TempDir() + "/gateway-sites.conf"
		cfg.Overlay.NamedPeers = []string{"https://peer.example"}
		cfg.Mesh.AllowedPeers = []string{"02" + strings.Repeat("a", 64)}
		cfg.Gateway.AcceptTOS = true // part of a genuinely warning-free posture now too
		return cfg
	}

	t.Run("fully closed posture: no warnings, no issues", func(t *testing.T) {
		cfg := base()
		var issues int
		out := captureStdout(t, func() { issues = doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, noPortBound) })
		if issues != 0 {
			t.Errorf("issues = %d, want 0", issues)
		}
		if bytes.Contains([]byte(out), []byte("⚠")) {
			t.Errorf("expected no warnings for a fully closed posture, got:\n%s", out)
		}
	})

	t.Run("public_url set warns but is not an issue", func(t *testing.T) {
		cfg := base()
		cfg.Node.PublicURL = "https://gateway.example.org:9333"
		var issues int
		out := captureStdout(t, func() { issues = doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, noPortBound) })
		if issues != 0 {
			t.Errorf("issues = %d, want 0", issues)
		}
		if !bytes.Contains([]byte(out), []byte("public_url")) {
			t.Errorf("expected a public_url warning, got:\n%s", out)
		}
	})

	t.Run("empty named_peers warns but is not an issue", func(t *testing.T) {
		cfg := base()
		cfg.Overlay.NamedPeers = nil
		var issues int
		out := captureStdout(t, func() { issues = doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, noPortBound) })
		if issues != 0 {
			t.Errorf("issues = %d, want 0", issues)
		}
		if !bytes.Contains([]byte(out), []byte("named_peers")) {
			t.Errorf("expected a named_peers warning, got:\n%s", out)
		}
	})

	t.Run("empty allowed_peers warns but is not an issue", func(t *testing.T) {
		cfg := base()
		cfg.Mesh.AllowedPeers = nil
		var issues int
		out := captureStdout(t, func() { issues = doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, noPortBound) })
		if issues != 0 {
			t.Errorf("issues = %d, want 0", issues)
		}
		if !bytes.Contains([]byte(out), []byte("allowed_peers")) {
			t.Errorf("expected an allowed_peers warning, got:\n%s", out)
		}
	})

	t.Run("default public header fallback peer warns but is not an issue", func(t *testing.T) {
		defaultPeer := config.DefaultHeaderFallbackPeers()[0]
		cfg := base()
		cfg.BSV.HeaderFallbackPeers = []string{defaultPeer}
		var issues int
		out := captureStdout(t, func() { issues = doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, noPortBound) })
		if issues != 0 {
			t.Errorf("issues = %d, want 0", issues)
		}
		if !bytes.Contains([]byte(out), []byte(defaultPeer)) {
			t.Errorf("expected a warning naming %s, got:\n%s", defaultPeer, out)
		}
	})

	t.Run("a non-default header fallback peer does not warn", func(t *testing.T) {
		defaultPeer := config.DefaultHeaderFallbackPeers()[0]
		cfg := base()
		cfg.BSV.HeaderFallbackPeers = []string{"https://peer.example"}
		out := captureStdout(t, func() { doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, noPortBound) })
		if bytes.Contains([]byte(out), []byte(defaultPeer)) {
			t.Errorf("did not expect the default-peer warning when it is not configured, got:\n%s", out)
		}
	})
}
