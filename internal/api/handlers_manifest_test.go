package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
)

// TestAnvilManifestIncludesCustomCapabilities verifies operator-declared
// capability entries surface in /.well-known/anvil. This is the mechanism
// that lets a federation node advertise an AVOS oracle relay (or any other
// operator-specific capability) without Anvil code changes.
func TestAnvilManifestIncludesCustomCapabilities(t *testing.T) {
	hdir, _ := os.MkdirTemp("", "anvil-manifest-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, _ := headers.NewTestStore(hdir)
	t.Cleanup(func() { hs.Close() })

	pdir, _ := os.MkdirTemp("", "anvil-manifest-proofs-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, _ := spv.NewProofStore(pdir)
	t.Cleanup(func() { ps.Close() })

	edir, _ := os.MkdirTemp("", "anvil-manifest-envs-*")
	t.Cleanup(func() { os.RemoveAll(edir) })
	es, _ := envelope.NewStore(edir, 3600, 65536)
	t.Cleanup(func() { es.Close() })

	customCaps := []map[string]interface{}{
		{
			"type":          "avos-offer-oracle",
			"description":   "MNEE ⇄ BSV oracle-attested swap",
			"oracle_pubkey": "02abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			"mailbox":       "avos.offer@node-identity",
			"access":        "POST /sendMessage (messageBox: avos.offer)",
			"payment":       "free",
		},
		{
			"type":        "custom-data-relay",
			"description": "Relays a proprietary data feed",
			"access":      "GET /data?topic=example:feed",
			"payment":     "HTTP-402",
		},
	}

	srv := NewServer(ServerConfig{
		HeaderStore:        hs,
		ProofStore:         ps,
		EnvelopeStore:      es,
		Validator:          spv.NewValidator(hs),
		Broadcaster:        txrelay.NewBroadcaster(txrelay.NewMempool(), nil, slog.Default()),
		AuthToken:          "test-token",
		Logger:             slog.Default(),
		NodeName:           "test-node",
		CustomCapabilities: customCaps,
	})

	req := httptest.NewRequest("GET", "/.well-known/anvil", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var manifest map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &manifest); err != nil {
		t.Fatalf("invalid manifest JSON: %v", err)
	}

	caps, ok := manifest["capabilities"].([]interface{})
	if !ok {
		t.Fatal("manifest missing capabilities array")
	}

	// Look for both custom entries; both should be present alongside the
	// built-in capabilities. Exact-shape check proves the passthrough preserves
	// operator-declared fields like oracle_pubkey that Anvil has no native
	// awareness of.
	foundAVOS := false
	foundCustomRelay := false
	for _, c := range caps {
		cm, _ := c.(map[string]interface{})
		switch cm["type"] {
		case "avos-offer-oracle":
			foundAVOS = true
			if cm["oracle_pubkey"] != customCaps[0]["oracle_pubkey"] {
				t.Errorf("oracle_pubkey not passed through: got %v", cm["oracle_pubkey"])
			}
			if cm["mailbox"] != customCaps[0]["mailbox"] {
				t.Errorf("mailbox not passed through: got %v", cm["mailbox"])
			}
		case "custom-data-relay":
			foundCustomRelay = true
		}
	}

	if !foundAVOS {
		t.Error("avos-offer-oracle capability missing from manifest")
	}
	if !foundCustomRelay {
		t.Error("custom-data-relay capability missing from manifest")
	}
}

// TestAnvilManifestWorksWithoutCustomCapabilities ensures the default path
// (no operator-declared capabilities) still produces a valid manifest with
// only built-in entries.
func TestAnvilManifestWorksWithoutCustomCapabilities(t *testing.T) {
	srv := testServer(t)

	req := httptest.NewRequest("GET", "/.well-known/anvil", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var manifest map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &manifest)
	caps, ok := manifest["capabilities"].([]interface{})
	if !ok || len(caps) == 0 {
		t.Fatal("expected at least built-in capabilities (spv-verification, header-chain)")
	}
}
