package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

// generateTestCertBlob returns a self-signed ECDSA certificate and key for
// domain, PEM-concatenated in exactly the order autocert's own cachePut
// writes a cache entry: the private key block first, then the certificate
// block (golang.org/x/crypto/acme/autocert@v0.59.0/acme/autocert/autocert.go:517-549;
// encodeECDSAKey at :552-559). cacheGet (:470-515) decodes the first PEM
// block as the key and treats the remainder as the certificate chain, so a
// seeded blob must use this order to be read back by a real
// autocert.Manager exactly as a freshly issued certificate would be.
func generateTestCertBlob(t *testing.T, domain string) []byte {
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

// TestHTTPSHandshake_AllowedHostSucceedsAndRoutes proves the 443
// handshake end to end: a real crypto/tls client dial against a real
// NewHTTPSServer listener, served from a certificate seeded directly into
// the Cache (standing in for one autocert would have issued), with the
// plaintext HTTP request that follows the handshake proving the connection
// reaches Router and is dispatched to the right handler by Host.
//
// The dial forces TLS 1.2 with a single ECDHE_ECDSA cipher suite so
// supportsECDSA (autocert.go:327-371) deterministically picks the plain
// (non-"+rsa") cache key this test seeds — leaving that choice to a
// client's default suite order would make the test depend on which TLS
// version happens to be negotiated.
func TestHTTPSHandshake_AllowedHostSucceedsAndRoutes(t *testing.T) {
	const domain = "allowed.example.org"
	blob := generateTestCertBlob(t, domain)
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	if err := cache.dir.Put(context.Background(), domain, blob); err != nil {
		t.Fatal(err)
	}

	manager := NewACMEManager(ACMEManagerConfig{Cache: cache, APIHost: domain})
	router := &Router{
		API:     http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "api-ok") }),
		APIHost: domain,
	}
	srv := NewHTTPSServer(":0", router, manager, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(ln, "", "")
	defer srv.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         domain,
				InsecureSkipVerify: true, // self-signed test cert; no CA to verify against
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS12,
				CipherSuites:       []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+ln.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = domain // the HTTP Host header Router dispatches on, independent of the dial address

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "api-ok" {
		t.Fatalf("status=%d body=%q, want 200 \"api-ok\" (the request should route through Router to API)", resp.StatusCode, body)
	}
}

// TestHTTPSHandshake_ACMETLS1HelloGetsTokenCert proves the acme-tls/1
// case: a ClientHello whose only ALPN protocol is "acme-tls/1" asks
// for the tls-alpn-01 challenge cert, not the site's regular certificate —
// and, per wantsTokenCert's own position in GetCertificate
// (autocert.go:278-289, checked before the "regular domain" branch at
// :291-314 that calls m.hostPolicy()), this never calls HostPolicy at all.
// This test's manager has neither a Policy nor an APIHost — a connection
// asking for the regular certificate would be refused — so the handshake
// succeeding at all, returning the seeded "+token" leaf, is itself proof
// HostPolicy was never consulted for this request.
func TestHTTPSHandshake_ACMETLS1HelloGetsTokenCert(t *testing.T) {
	const domain = "challenge.example.org"
	blob := generateTestCertBlob(t, domain)
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	if err := cache.dir.Put(context.Background(), domain+"+token", blob); err != nil {
		t.Fatal(err)
	}

	manager := NewACMEManager(ACMEManagerConfig{Cache: cache}) // no Policy, no APIHost
	srv := NewHTTPSServer(":0", http.NotFoundHandler(), manager, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(ln, "", "")
	defer srv.Close()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
		NextProtos:         []string{"acme-tls/1"},
	})
	if err != nil {
		t.Fatalf("tls.Dial with acme-tls/1: %v", err)
	}
	defer conn.Close()

	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		t.Fatal("handshake returned no peer certificate")
	}
	if got := peers[0].Subject.CommonName; got != domain {
		t.Fatalf("leaf CommonName = %q, want %q (the seeded +token cert)", got, domain)
	}
}
