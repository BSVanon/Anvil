package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/certgate"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestCertificatePrivacyAndStats(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	srv, _ := messageHandlerServer(t, messagingOptionsNone())
	srv.logger = logger

	refused := newSenderPropertyFixture(t)
	refusalGate := refused.gate(t, func(c *certgate.Config) {
		c.RevealFields = map[string][]string{refused.typ: {"role"}}
	})
	sensitiveField := base64.StdEncoding.EncodeToString([]byte("private certificate field"))
	cert := refused.certificate(t, refused.subject.PubKey(), refused.outpoint)
	cert.Keyring = map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
		wallet.CertificateFieldNameUnder50Bytes("role"): wallet.StringBase64(sensitiveField),
	}
	if err := refusalGate.Verify(t.Context(), refused.subject.PubKey(), cert); err == nil {
		t.Fatal("certificate with unverifiable field was admitted")
	}
	srv.identityPub = hex.EncodeToString(refused.subject.PubKey().Compressed())
	srv.certificateGate = CertificateAdmission{Gate: refusalGate, RequireSender: true}
	endpoint := "/sendMessage/private-endpoint"
	clientIP := "198.51.100.77"
	body, _ := json.Marshal(map[string]string{
		"recipient": srv.identityPub, "messageBox": "box", "body": "hello",
	})
	req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.RemoteAddr = clientIP + ":4444"
	srv.handleSendMessage(httptest.NewRecorder(), req)

	revoked := newSenderPropertyFixture(t)
	revokedGate := revoked.gate(t, nil)
	if err := revokedGate.Verify(t.Context(), revoked.subject.PubKey(), revoked.certificate(t, revoked.subject.PubKey(), revoked.outpoint)); err != nil {
		t.Fatal(err)
	}
	revokedGate.SetSpendVerifier(func(_ context.Context, _, _ string) error { return nil })
	revoked.watcher.callback(revoked.outpoint.String(), strings.Repeat("a", 64))
	deadline := time.Now().Add(time.Second)
	for revokedGate.Stats()["certgate_revoked"] == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	srv.certificateGate = CertificateAdmission{Gate: revokedGate}

	statsResponse := httptest.NewRecorder()
	srv.handleStats(statsResponse, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if statsResponse.Code != http.StatusOK {
		t.Fatalf("stats status = %d", statsResponse.Code)
	}
	var stats map[string]any
	if err := json.Unmarshal(statsResponse.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	wantCounters := map[string]bool{
		"certgate_verified": true, "certgate_refused": true,
		"certgate_revoked": true, "certgate_check_errors": true,
	}
	for key := range stats {
		if strings.HasPrefix(key, "certgate_") {
			if !wantCounters[key] {
				t.Fatalf("unexpected certificate statistic %q", key)
			}
			delete(wantCounters, key)
		}
	}
	if len(wantCounters) != 0 {
		t.Fatalf("missing certificate statistics: %v", wantCounters)
	}

	logged := logs.String()
	for _, secret := range []string{sensitiveField, clientIP, endpoint} {
		if strings.Contains(logged, secret) {
			t.Fatalf("log exposed private value %q: %s", secret, logged)
		}
	}
}
