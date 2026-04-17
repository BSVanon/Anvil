package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestBroadcastAcceptsX402WhenGateConfigured verifies that /broadcast now
// accepts x402 payment as an alternative to auth token (authOrPay migration).
// Without credentials, a paymentGate-configured server should return 402 with
// a challenge — not 401. This pre-wires the wallet's eventual x402 client
// without requiring a second federation rollout to flip the middleware.
func TestBroadcastAcceptsX402WhenGateConfigured(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)

	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader("whatever"))
	req.Host = "localhost"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 (payment required) when no auth on paymentGate-enabled broadcast, got %d: %s",
			w.Code, w.Body.String())
	}
}

// TestBroadcastAuthTokenStillWorksWithPaymentGate verifies backward compatibility:
// a valid auth token bypasses the payment gate (E.1 short-term path).
func TestBroadcastAuthTokenStillWorksWithPaymentGate(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)

	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader("garbage"))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Valid auth → reaches handler → handler rejects invalid BEEF (422)
	// Key assertion: NOT 402 (payment gate bypassed), NOT 401 (auth valid)
	if w.Code == http.StatusPaymentRequired {
		t.Fatalf("valid auth token should bypass x402 gate, got 402")
	}
	if w.Code == http.StatusUnauthorized {
		t.Fatalf("valid auth token should not return 401, got 401: %s", w.Body.String())
	}
}

// testServerWithARC builds a broadcast-capable server whose ARC client
// points at an operator-provided httptest.Server. Used to exercise the
// ARC transport-failure path end-to-end.
func testServerWithARC(t *testing.T, arcURL string) *Server {
	t.Helper()

	hdir, _ := os.MkdirTemp("", "anvil-arc-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, _ := headers.NewTestStore(hdir)
	t.Cleanup(func() { hs.Close() })

	pdir, _ := os.MkdirTemp("", "anvil-arc-proofs-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, _ := spv.NewProofStore(pdir)
	t.Cleanup(func() { ps.Close() })

	edir, _ := os.MkdirTemp("", "anvil-arc-envs-*")
	t.Cleanup(func() { os.RemoveAll(edir) })
	es, _ := envelope.NewStore(edir, 3600, 65536)
	t.Cleanup(func() { es.Close() })

	arc := txrelay.NewARCClient(arcURL, "")
	broadcaster := txrelay.NewBroadcaster(txrelay.NewMempool(), arc, slog.Default())

	return NewServer(ServerConfig{
		HeaderStore:   hs,
		ProofStore:    ps,
		EnvelopeStore: es,
		Validator:     spv.NewValidator(hs),
		Broadcaster:   broadcaster,
		AuthToken:     "test-token",
		Logger:        slog.Default(),
	})
}

// buildValidBEEF produces a BEEF binary the validator accepts (without a
// merkle path, so it yields ConfidenceUnconfirmed — not invalid — and the
// handler proceeds past the 422 rejection to the ARC-submit branch).
// Used by end-to-end broadcast tests exercising the ARC path.
func buildValidBEEF(t *testing.T) []byte {
	t.Helper()
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: mustDecodeScript(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"),
	})
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("build BEEF: %v", err)
	}
	out, err := beef.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatalf("atomic bytes: %v", err)
	}
	return out
}

// TestBroadcastRejectsBypassWhenPaymentGateZeroPriced is the regression test
// for the high-severity auth bypass Codex caught in the Path C audit.
//
// Production setup that triggered the bug: node has identity.WIF + wallet
// (nonce provider configured for app passthrough/split payments) but
// payment_satoshis=0 for its own endpoints. Before the fix, /broadcast would
// delegate to paymentGate.Middleware → resolvePayees returned no payees for
// a zero-priced path → middleware treated empty payees as free pass-through
// → anyone could relay transactions without auth.
//
// Fix: authOrPayBinary now only delegates to paymentGate when the endpoint
// has a positive price. Zero-priced endpoints fall through to the
// auth-required branch.
func TestBroadcastRejectsBypassWhenPaymentGateZeroPriced(t *testing.T) {
	// testServerWithPaymentGate creates a gate with non-zero price. We need
	// a zero-priced gate to trigger the original bug scenario, so we build
	// the server manually.
	srv := testServer(t)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats:      0, // node is free — reproduces production config
		PayeeScriptHex: testPayeeScript(t),
		NonceProvider:  &DevNonceProvider{},
	})
	srv.mux = http.NewServeMux()
	srv.routes()

	// Unauthenticated request, no x402 headers. Must be rejected.
	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader("whatever"))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Fatalf("HIGH SEVERITY: /broadcast accepted unauthenticated request on zero-priced gate — auth bypass")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /broadcast on zero-priced gate, got %d: %s",
			w.Code, w.Body.String())
	}
}

// TestBroadcastARCTransportFailureReportsValidatedOnly is the regression test
// for the bug Codex caught: when ARC returns a non-2xx (transport failure),
// BroadcastToARC swallows the error into a result with Status="error" and nil
// error. The handler must recognize this and set arcStatus.Submitted=false
// (we don't know if ARC received the tx), so deriveBroadcastStatus lands on
// "validated-only" instead of "queued". Wallet consumers rely on this to
// correctly failover to another broadcast upstream.
func TestBroadcastARCTransportFailureReportsValidatedOnly(t *testing.T) {
	// Mock ARC that always returns 500 — simulates outage / reachability failure.
	mockARC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream overloaded", http.StatusInternalServerError)
	}))
	defer mockARC.Close()

	srv := testServerWithARC(t, mockARC.URL)
	beef := buildValidBEEF(t)

	req := httptest.NewRequest("POST", "/broadcast?arc=true", bytes.NewReader(beef))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (valid BEEF), got %d: %s", w.Code, w.Body.String())
	}

	var resp BroadcastResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	if resp.ARC == nil {
		t.Fatal("expected arc field to be populated when ?arc=true")
	}
	if resp.ARC.Submitted {
		t.Errorf("arc.submitted must be false on transport failure — we don't know if tx reached miners (got submitted=true, tx_status=%q)", resp.ARC.TxStatus)
	}
	if resp.ARC.Error == "" {
		t.Errorf("arc.error should carry the transport-failure message")
	}
	if resp.Status != BroadcastStatusValidatedOnly {
		t.Errorf("expected status=%q for transport failure, got %q (wallet would not retry via another upstream)",
			BroadcastStatusValidatedOnly, resp.Status)
	}
}

// TestDeriveBroadcastStatus covers the status derivation table from
// ANVIL_NODE_HANDOFF.md. Wallet consumers rely on this single field for
// failover decisions, so every branch needs to be pinned with a test.
func TestDeriveBroadcastStatus(t *testing.T) {
	tests := []struct {
		name       string
		confidence string
		arc        *ARCStatus
		want       string
	}{
		{
			name:       "invalid confidence always rejects",
			confidence: spv.ConfidenceInvalid,
			arc:        nil,
			want:       BroadcastStatusRejected,
		},
		{
			name:       "invalid confidence rejects even if ARC later reports SEEN",
			confidence: spv.ConfidenceInvalid,
			arc:        &ARCStatus{Submitted: true, TxStatus: "SEEN_ON_NETWORK"},
			want:       BroadcastStatusRejected,
		},
		{
			name:       "ARC REJECTED maps to rejected",
			confidence: spv.ConfidenceSPVVerified,
			arc:        &ARCStatus{Submitted: true, TxStatus: "REJECTED"},
			want:       BroadcastStatusRejected,
		},
		{
			name:       "ARC DOUBLE_SPEND_ATTEMPTED maps to rejected",
			confidence: spv.ConfidenceSPVVerified,
			arc:        &ARCStatus{Submitted: true, TxStatus: "DOUBLE_SPEND_ATTEMPTED"},
			want:       BroadcastStatusRejected,
		},
		{
			name:       "ARC SEEN_ON_NETWORK maps to propagated",
			confidence: spv.ConfidenceSPVVerified,
			arc:        &ARCStatus{Submitted: true, TxStatus: "SEEN_ON_NETWORK"},
			want:       BroadcastStatusPropagated,
		},
		{
			name:       "ARC MINED maps to propagated",
			confidence: spv.ConfidenceSPVVerified,
			arc:        &ARCStatus{Submitted: true, TxStatus: "MINED"},
			want:       BroadcastStatusPropagated,
		},
		{
			name:       "ARC intermediate RECEIVED maps to queued (not validated-only)",
			confidence: spv.ConfidenceSPVVerified,
			arc:        &ARCStatus{Submitted: true, TxStatus: "RECEIVED"},
			want:       BroadcastStatusQueued,
		},
		{
			name:       "ARC intermediate ANNOUNCED_TO_NETWORK maps to queued",
			confidence: spv.ConfidenceSPVVerified,
			arc:        &ARCStatus{Submitted: true, TxStatus: "ANNOUNCED_TO_NETWORK"},
			want:       BroadcastStatusQueued,
		},
		{
			name:       "ARC intermediate ACCEPTED_BY_NETWORK maps to queued",
			confidence: spv.ConfidenceSPVVerified,
			arc:        &ARCStatus{Submitted: true, TxStatus: "ACCEPTED_BY_NETWORK"},
			want:       BroadcastStatusQueued,
		},
		{
			name:       "ARC intermediate STORED maps to queued",
			confidence: spv.ConfidenceSPVVerified,
			arc:        &ARCStatus{Submitted: true, TxStatus: "STORED"},
			want:       BroadcastStatusQueued,
		},
		{
			name:       "no ARC attempt returns validated-only",
			confidence: spv.ConfidenceSPVVerified,
			arc:        nil,
			want:       BroadcastStatusValidatedOnly,
		},
		{
			name:       "ARC HTTP failure (submitted=false) returns validated-only",
			confidence: spv.ConfidenceSPVVerified,
			arc:        &ARCStatus{Submitted: false, Error: "connection refused"},
			want:       BroadcastStatusValidatedOnly,
		},
		{
			name:       "partially verified + no ARC is validated-only",
			confidence: spv.ConfidencePartiallyVerified,
			arc:        nil,
			want:       BroadcastStatusValidatedOnly,
		},
		{
			name:       "unconfirmed + no ARC is validated-only",
			confidence: spv.ConfidenceUnconfirmed,
			arc:        nil,
			want:       BroadcastStatusValidatedOnly,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveBroadcastStatus(tc.confidence, tc.arc)
			if got != tc.want {
				t.Errorf("deriveBroadcastStatus(%q, %+v) = %q, want %q",
					tc.confidence, tc.arc, got, tc.want)
			}
		})
	}
}
