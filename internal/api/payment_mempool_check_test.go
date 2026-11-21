package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/txrelay"
)

// The operator's require_mempool setting fails closed: with an ARC client the
// proof path holds a proof to the network-acceptance statuses, and with none
// it refuses the proof rather than skip the check.

// mempoolCheckServer is a node charging 100 sats on every route, with the
// require_mempool setting require and the ARC client arc (nil for none).
func mempoolCheckServer(t *testing.T, require bool, arc *txrelay.ARCClient) *Server {
	t.Helper()
	srv := testServer(t)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{},
		RequireMempool: require, ARCClient: arc,
	})
	srv.mux = http.NewServeMux()
	srv.routes()
	return srv
}

// payStatsByProof answers a challenge for GET /stats with a proof that pays
// the node its price, and returns the node's answer to the paid request.
func payStatsByProof(t *testing.T, srv *Server, wantRequired bool) *httptest.ResponseRecorder {
	t.Helper()
	ch := getChallenge(t, srv, http.MethodGet, "/stats")
	if ch.RequireMempoolAccept != wantRequired {
		t.Fatalf("challenge require_mempool_accept = %v, want %v", ch.RequireMempoolAccept, wantRequired)
	}
	return getWithHeaders(srv, "/stats", map[string]string{HeaderX402Proof: buildProof(t, ch, 100, testPayeeScript(t))})
}

// TestRequiredMempoolCheckWithoutARCRefusesProof: a node that requires
// mempool acceptance and has no ARC client refuses every proof with
// ERR_MEMPOOL_CHECK_UNAVAILABLE, instead of accepting it unchecked.
func TestRequiredMempoolCheckWithoutARCRefusesProof(t *testing.T) {
	srv := mempoolCheckServer(t, true, nil)
	requirePaymentCode(t, payStatsByProof(t, srv, true), codeMempoolCheckUnavailable)
}

// TestRequiredMempoolCheckWithARCIsEnforced: with an ARC client the check is
// made, so a non-final status is answered as ambiguous and SEEN_ON_NETWORK
// is served (every status: TestProofPaymentNeedsNetworkAcceptance).
func TestRequiredMempoolCheckWithARCIsEnforced(t *testing.T) {
	refused := mempoolCheckServer(t, true, mockARCWithStatus(t, "SEEN_IN_ORPHAN_MEMPOOL", 0))
	w := payStatsByProof(t, refused, true)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("orphan status: got %d %s, want 503", w.Code, w.Body.String())
	}
	if codeOf(t, w) != codePaymentSubmitUncertain {
		t.Fatalf("orphan status: got code %s, want %s", codeOf(t, w), codePaymentSubmitUncertain)
	}

	accepted := mempoolCheckServer(t, true, mockARCWithStatus(t, "SEEN_ON_NETWORK", 0))
	if w := payStatsByProof(t, accepted, true); w.Code != http.StatusOK {
		t.Fatalf("ARC status SEEN_ON_NETWORK: got %d %s, want 200", w.Code, w.Body.String())
	}
}

// TestMempoolCheckIsOffByDefault: a gate configured without the setting
// issues challenges that do not require mempool acceptance, and a node with
// no ARC client still takes a proof.
func TestMempoolCheckIsOffByDefault(t *testing.T) {
	srv := mempoolCheckServer(t, false, nil)
	if w := payStatsByProof(t, srv, false); w.Code != http.StatusOK {
		t.Fatalf("default setting, no ARC: got %d %s, want 200", w.Code, w.Body.String())
	}
}
