package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// generateTestCert creates a self-signed TLS cert+key in temp files.
func generateTestCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "anvil-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certFile, _ := os.CreateTemp("", "anvil-test-cert-*.pem")
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certFile.Close()
	t.Cleanup(func() { os.Remove(certFile.Name()) })

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyFile, _ := os.CreateTemp("", "anvil-test-key-*.pem")
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyFile.Close()
	t.Cleanup(func() { os.Remove(keyFile.Name()) })

	return certFile.Name(), keyFile.Name()
}

func TestTLSServerServes(t *testing.T) {
	certPath, keyPath := generateTestCert(t)

	srv := testServer(t)

	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	// Start TLS server
	httpSrv := &http.Server{
		Addr:    addr,
		Handler: srv.Handler(),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	go func() {
		if err := httpSrv.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
			t.Logf("TLS server error: %v", err)
		}
	}()
	defer httpSrv.Close()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Make HTTPS request with the test cert trusted
	certPEM, _ := os.ReadFile(certPath)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}

	resp, err := client.Get("https://" + addr + "/status")
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["node"] != "anvil" {
		t.Fatalf("expected node=anvil, got %v", body["node"])
	}

	// Verify TLS version
	if resp.TLS == nil {
		t.Fatal("expected TLS connection info")
	}
	if resp.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("expected TLS 1.2+, got %x", resp.TLS.Version)
	}

	t.Logf("TLS serving: status=200 tls_version=%x", resp.TLS.Version)
}
