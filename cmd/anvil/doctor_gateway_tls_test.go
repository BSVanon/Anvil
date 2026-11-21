package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/gateway"
)

// generateDoctorTestCertBlob returns a self-signed ECDSA certificate and
// key for domain, PEM-concatenated key-then-certificate — the same
// on-disk shape autocert's own cachePut writes (see
// internal/gateway/acmecache.go's parseLeafCertificate) — so
// doctorGatewayChecks's cert-state check has a real, parseable entry to
// read back without a real ACME issuance.
func generateDoctorTestCertBlob(t *testing.T, domain string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestDoctorGatewayTLSChecks_PortBoundReportsIssue confirms an unbound
// 443 or 80 is reported as a genuine issue — the one TLS finding that
// is, since a gateway that can't be reached isn't serving anything.
func TestDoctorGatewayTLSChecks_PortBoundReportsIssue(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.Enabled = true
	cfg.Gateway.SitesFile = t.TempDir() + "/gateway-sites.conf"
	cfg.Gateway.HTTPSListen = ":443"
	cfg.Gateway.HTTPListen = ":80"

	t.Run("both unbound", func(t *testing.T) {
		var issues int
		out := captureStdout(t, func() {
			issues = doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, noPortBound)
		})
		if issues != 2 {
			t.Errorf("issues = %d, want 2 (443 and 80 both unbound)", issues)
		}
		if !strings.Contains(out, "443 not bound") || !strings.Contains(out, "80 not bound") {
			t.Errorf("expected both ports reported not bound, got:\n%s", out)
		}
	})

	t.Run("both bound", func(t *testing.T) {
		allBound := func(addr string) bool { return true }
		var issues int
		out := captureStdout(t, func() {
			issues = doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, allBound)
		})
		if issues != 0 {
			t.Errorf("issues = %d, want 0 when both ports are bound", issues)
		}
		if !strings.Contains(out, "443 bound") || !strings.Contains(out, "80 bound") {
			t.Errorf("expected both ports reported bound, got:\n%s", out)
		}
	})
}

// TestDoctorGatewayTLSChecks_CertState covers the three per-site states
// doctor must distinguish: none yet, valid until a date (read from the
// on-disk cache), and the last error (read from the sidecar
// RecordIssuanceError writes) — the required "read from the cache and
// the manager" check. Present and LastError are set directly on a Cache
// rather than exercised through a real TLS handshake, matching this
// file's existing style of testing doctorGatewayChecks's own logic, not
// internal/gateway's (already covered there).
func TestDoctorGatewayTLSChecks_CertState(t *testing.T) {
	dataDir := t.TempDir()
	sitesPath := filepath.Join(dataDir, "gateway-sites.conf")
	sites := "domain none-yet.example.org\ndomain has-cert.example.org\ndomain has-error.example.org\n"
	if err := os.WriteFile(sitesPath, []byte(sites), 0640); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Gateway.Enabled = true
	cfg.Gateway.SitesFile = sitesPath
	cfg.Node.DataDir = dataDir

	cache := gateway.NewCache(filepath.Join(dataDir, "acme"), nil, nil, nil, nil)
	blob := generateDoctorTestCertBlob(t, "has-cert.example.org")
	if err := cache.Put(context.Background(), "has-cert.example.org", blob); err != nil {
		t.Fatal(err)
	}
	cache.RecordIssuanceError("has-error.example.org", "acme: missing Manager.Prompt to accept server's terms of service")

	out := captureStdout(t, func() { doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, noPortBound) })
	if !strings.Contains(out, "none-yet.example.org: no certificate issued yet") {
		t.Errorf("expected a 'no certificate issued yet' line for none-yet.example.org, got:\n%s", out)
	}
	if !strings.Contains(out, "has-cert.example.org: certificate valid until") {
		t.Errorf("expected a 'certificate valid until' line for has-cert.example.org, got:\n%s", out)
	}
	if !strings.Contains(out, "has-error.example.org: certificate error") || !strings.Contains(out, "missing Manager.Prompt") {
		t.Errorf("expected a certificate-error line naming the recorded error for has-error.example.org, got:\n%s", out)
	}
}

// TestDoctorGatewayTLSChecks_ReplicationPossible is the required
// "challenge replication is possible: at least one allowed peer is
// connected" check: it's silent with allowed_peers empty (already
// covered by the closed-posture warning), warns when configured but no
// peer answers /mesh/status, and passes when one does.
func TestDoctorGatewayTLSChecks_ReplicationPossible(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.Enabled = true
	cfg.Gateway.SitesFile = t.TempDir() + "/gateway-sites.conf"
	cfg.Mesh.AllowedPeers = []string{"02" + strings.Repeat("a", 64)}

	t.Run("API reachable but zero peers", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/mesh/status", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"mesh":{"peers":0}}`))
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()

		out := captureStdout(t, func() { doctorGatewayChecks(cfg, ts.URL, noTXTStatus, noPortBound) })
		if !strings.Contains(out, "replication configured but no mesh peer is connected") {
			t.Errorf("expected a 'no mesh peer connected' warning, got:\n%s", out)
		}
	})

	// The API itself being unreachable is already the top-level "API not
	// responding" failure cmdDoctor reports earlier — this check doesn't
	// duplicate that, the same convention the existing generic mesh-peer
	// check (doctor.go) already follows.
	t.Run("API unreachable says nothing extra", func(t *testing.T) {
		out := captureStdout(t, func() { doctorGatewayChecks(cfg, noAPIURL, noTXTStatus, noPortBound) })
		if strings.Contains(out, "replication") {
			t.Errorf("expected no replication line when the API itself is unreachable, got:\n%s", out)
		}
	})

	t.Run("a peer is connected", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/mesh/status", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"mesh":{"peers":1}}`))
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()

		out := captureStdout(t, func() { doctorGatewayChecks(cfg, ts.URL, noTXTStatus, noPortBound) })
		if !strings.Contains(out, "replication possible: 1 allowed peer(s) connected") {
			t.Errorf("expected a 'replication possible' pass line, got:\n%s", out)
		}
	})
}
