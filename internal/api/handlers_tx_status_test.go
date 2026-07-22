package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

const statusTxID = "2222222222222222222222222222222222222222222222222222222222222222"

// addStatusChain appends n synthetic linked headers (PoW skipped in the test
// store) so the header tip advances to a known height for confirmation math.
func addStatusChain(t *testing.T, srv *Server, n int) {
	t.Helper()
	prev, err := srv.headerStore.HashAtHeight(srv.headerStore.Tip())
	if err != nil {
		t.Fatal(err)
	}
	merkle, err := chainhash.NewHashFromStr("abcdef0000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	start := srv.headerStore.Tip() + 1
	hdrs := make([]*wire.BlockHeader, 0, n)
	for i := 0; i < n; i++ {
		hdr := wire.NewBlockHeader(1, prev, merkle, 0x1d00ffff, uint32(i))
		hdr.Timestamp = time.Unix(1231006506+int64(i)*600, 0)
		hdrs = append(hdrs, hdr)
		h := hdr.BlockHash()
		prev = &h
	}
	if err := srv.headerStore.AddHeaders(start, hdrs); err != nil {
		t.Fatal(err)
	}
}

// statusServer builds a test server whose fetcher's WoC upstream is the given mock.
func statusServer(t *testing.T, woc http.HandlerFunc) *Server {
	t.Helper()
	mock := httptest.NewServer(woc)
	t.Cleanup(mock.Close)
	fetcher := spv.NewProofFetcher(nil, slog.Default())
	fetcher.SetBaseURL(mock.URL)
	return testServerWithFetcher(t, fetcher)
}

func getStatus(t *testing.T, srv *Server, txid string) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest("GET", "/tx/"+txid+"/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var body map[string]interface{}
	if len(w.Body.Bytes()) > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &body)
	}
	return w.Code, body
}

func TestTxStatusMinedConfirmations(t *testing.T) {
	srv := statusServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"blockheight":8}`))
	})
	addStatusChain(t, srv, 10) // tip = 10

	code, body := getStatus(t, srv, statusTxID)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, body)
	}
	if body["txStatus"] != "MINED" {
		t.Fatalf("expected txStatus=MINED, got %v", body["txStatus"])
	}
	if body["blockHeight"].(float64) != 8 {
		t.Fatalf("expected blockHeight=8, got %v", body["blockHeight"])
	}
	if body["currentHeight"].(float64) != 10 {
		t.Fatalf("expected currentHeight=10, got %v", body["currentHeight"])
	}
	// confirmations = currentHeight - blockHeight + 1 = 10 - 8 + 1 = 3
	if body["confirmations"].(float64) != 3 {
		t.Fatalf("expected confirmations=3, got %v", body["confirmations"])
	}
	if body["source"] != "woc" {
		t.Fatalf("expected source=woc, got %v", body["source"])
	}
}

func TestTxStatusMempoolReturnsZeroConfirmations(t *testing.T) {
	srv := statusServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"blockheight":0}`))
	})
	code, body := getStatus(t, srv, statusTxID)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, body)
	}
	if body["txStatus"] != "SEEN_ON_NETWORK" {
		t.Fatalf("expected txStatus=SEEN_ON_NETWORK, got %v", body["txStatus"])
	}
	if body["confirmations"].(float64) != 0 {
		t.Fatalf("expected confirmations=0, got %v", body["confirmations"])
	}
	if _, present := body["blockHeight"]; present {
		t.Fatalf("blockHeight must be omitted for an unmined tx, got %v", body["blockHeight"])
	}
}

func TestTxStatusMinedBeyondLocalTip(t *testing.T) {
	// tip stays at genesis (0); tx mined at height 5 the node hasn't synced yet.
	srv := statusServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"blockheight":5}`))
	})
	code, body := getStatus(t, srv, statusTxID)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, body)
	}
	if body["txStatus"] != "MINED" || body["blockHeight"].(float64) != 5 {
		t.Fatalf("expected txStatus=MINED blockHeight=5, got %v", body)
	}
	// blockHeight (5) > currentHeight (0) → confirmations clamped to 0, unambiguous.
	if body["confirmations"].(float64) != 0 {
		t.Fatalf("expected confirmations=0 when blockHeight>currentHeight, got %v", body["confirmations"])
	}
	if body["currentHeight"].(float64) != 0 {
		t.Fatalf("expected currentHeight=0 (genesis), got %v", body["currentHeight"])
	}
}

func TestTxStatusNotFound(t *testing.T) {
	srv := statusServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	code, _ := getStatus(t, srv, statusTxID)
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown tx, got %d", code)
	}
}

func TestTxStatusUpstreamDownReturns502(t *testing.T) {
	srv := statusServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	code, _ := getStatus(t, srv, statusTxID)
	if code != http.StatusBadGateway {
		t.Fatalf("expected 502 when upstream is down, got %d", code)
	}
}

func TestTxStatusBadTxid(t *testing.T) {
	srv := statusServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"blockheight":8}`))
	})
	code, _ := getStatus(t, srv, "tooshort")
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed txid, got %d", code)
	}
}

// A 64-CHARACTER but non-hex txid must be rejected locally (400) — never proxied
// to ARC/WoC (regression for Codex fa86bf72: length check alone let garbage
// through and could return a misleading upstream answer).
func TestTxStatusRejectsNonHexTxid(t *testing.T) {
	upstreamCalled := false
	srv := statusServer(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"blockheight":8}`))
	})
	nonHex := "zz" + statusTxID[2:] // 64 chars, 'z' is not hex
	if len(nonHex) != 64 {
		t.Fatalf("test setup: expected 64-char txid, got %d", len(nonHex))
	}
	code, _ := getStatus(t, srv, nonHex)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for 64-char non-hex txid, got %d", code)
	}
	if upstreamCalled {
		t.Fatal("non-hex txid must be rejected locally — upstream must NOT be called")
	}
}

// /tx/{txid}/status is openPublic, so it must serve free even when the operator
// prices openRead endpoints — the portability guarantee Satsu relies on for
// cross-operator confirmation polling.
func TestTxStatusOpenPublicUnderPaymentGate(t *testing.T) {
	srv := statusServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"blockheight":0}`)) // mempool → 200 mined:false
	})
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats:      100,
		PayeeScriptHex: testPayeeScript(t),
		NonceProvider:  &DevNonceProvider{},
	})
	srv.mux = http.NewServeMux()
	srv.routes()

	// Sanity: a normal openRead path IS gated (402) at this price — proves the
	// gate is live, so a non-402 on /tx/status means it genuinely bypasses it.
	req := httptest.NewRequest("GET", "/headers/tip", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("/headers/tip: expected 402 under priced gate, got %d", w.Code)
	}

	code, body := getStatus(t, srv, statusTxID)
	if code == http.StatusPaymentRequired {
		t.Fatal("/tx/{txid}/status must bypass the payment gate (openPublic)")
	}
	if code != http.StatusOK {
		t.Fatalf("expected 200 under priced gate, got %d: %v", code, body)
	}
	if body["txStatus"] != "SEEN_ON_NETWORK" {
		t.Fatalf("expected txStatus=SEEN_ON_NETWORK, got %v", body["txStatus"])
	}
}

// statusServerWithARC builds a test server whose fetcher resolves via a mock ARC
// (its WoC upstream must never be reached when ARC answers).
func statusServerWithARC(t *testing.T, arc http.HandlerFunc) *Server {
	t.Helper()
	arcMock := httptest.NewServer(arc)
	t.Cleanup(arcMock.Close)
	wocMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("WoC must not be called when ARC answers")
	}))
	t.Cleanup(wocMock.Close)
	fetcher := spv.NewProofFetcher(txrelay.NewARCClient(arcMock.URL, ""), slog.Default())
	fetcher.SetBaseURL(wocMock.URL)
	return testServerWithFetcher(t, fetcher)
}

// A stale-block ARC status surfaces via txStatus but reports 0 confirmations and
// omits blockHeight — it is not an active-chain confirmation (regression for
// Codex 891e013b: blockHeight>0 alone must not read as "confirmed").
func TestTxStatusStaleBlockHandler(t *testing.T) {
	srv := statusServerWithARC(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"x","txStatus":"MINED_IN_STALE_BLOCK","blockHeight":900500}`))
	})
	code, body := getStatus(t, srv, statusTxID)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, body)
	}
	if body["txStatus"] != "MINED_IN_STALE_BLOCK" {
		t.Fatalf("expected txStatus passthrough, got %v", body["txStatus"])
	}
	if body["confirmations"].(float64) != 0 {
		t.Fatalf("expected confirmations=0 for a stale block, got %v", body["confirmations"])
	}
	if _, present := body["blockHeight"]; present {
		t.Fatalf("blockHeight must be omitted for a non-active-chain status, got %v", body["blockHeight"])
	}
	if body["source"] != "arc" {
		t.Fatalf("expected source=arc, got %v", body["source"])
	}
}

// ARC MINED without a block height must not produce a bogus confirmation count
// (currentHeight+1) — it yields 0 confirmations and omits blockHeight, with the
// raw txStatus still surfaced (regression for Codex bb1152de).
func TestTxStatusMinedWithoutHeightHandler(t *testing.T) {
	srv := statusServerWithARC(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"x","txStatus":"MINED"}`)) // no blockHeight
	})
	addStatusChain(t, srv, 10) // currentHeight = 10, to expose a bogus +1 count
	code, body := getStatus(t, srv, statusTxID)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, body)
	}
	if body["txStatus"] != "MINED" {
		t.Fatalf("expected txStatus=MINED passthrough, got %v", body["txStatus"])
	}
	if body["confirmations"].(float64) != 0 {
		t.Fatalf("expected confirmations=0 (no usable height), got %v", body["confirmations"])
	}
	if _, present := body["blockHeight"]; present {
		t.Fatalf("blockHeight must be omitted when ARC gave no height, got %v", body["blockHeight"])
	}
}
