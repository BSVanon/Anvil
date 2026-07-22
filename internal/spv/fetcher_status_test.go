package spv

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/txrelay"
)

const statusTestTxID = "1111111111111111111111111111111111111111111111111111111111111111"

// wocOnly builds a ProofFetcher with no ARC client (WoC-only) pointed at a mock.
func wocOnly(t *testing.T, handler http.HandlerFunc) *ProofFetcher {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	f := NewProofFetcher(nil, slog.Default())
	f.SetBaseURL(srv.URL)
	return f
}

func TestTxStatusMined(t *testing.T) {
	f := wocOnly(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"blockheight":900100}`))
	})
	st, err := f.TxStatus(statusTestTxID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !st.Found || !st.Mined || st.BlockHeight != 900100 {
		t.Fatalf("got %+v, want Found+Mined+BlockHeight=900100", st)
	}
	if st.Status != "MINED" || st.Source != BEEFSourceWoC {
		t.Fatalf("got status=%q source=%q, want MINED/woc", st.Status, st.Source)
	}
}

func TestTxStatusMempoolUnconfirmed(t *testing.T) {
	f := wocOnly(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"blockheight":0}`))
	})
	st, err := f.TxStatus(statusTestTxID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !st.Found || st.Mined || st.BlockHeight != 0 {
		t.Fatalf("got %+v, want Found + !Mined", st)
	}
	if st.Status != "SEEN_ON_NETWORK" || st.Source != BEEFSourceWoC {
		t.Fatalf("got status=%q source=%q, want SEEN_ON_NETWORK/woc", st.Status, st.Source)
	}
}

func TestTxStatusNotFoundIsNotAnError(t *testing.T) {
	f := wocOnly(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	st, err := f.TxStatus(statusTestTxID)
	if err != nil {
		t.Fatalf("404 should be a clean not-found, not an error: %v", err)
	}
	if st.Found {
		t.Fatalf("got Found=true, want not found")
	}
}

func TestTxStatusUpstreamErrorPropagates(t *testing.T) {
	f := wocOnly(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := f.TxStatus(statusTestTxID)
	if err == nil {
		t.Fatal("a 5xx upstream must surface as an error (caller emits 502), not not-found")
	}
}

// fetcherWithARC wires both a mock ARC and a mock WoC so the ARC-first/WoC-fallback
// branch can be exercised directly.
func fetcherWithARC(t *testing.T, arc, woc http.HandlerFunc) *ProofFetcher {
	t.Helper()
	arcSrv := httptest.NewServer(arc)
	t.Cleanup(arcSrv.Close)
	wocSrv := httptest.NewServer(woc)
	t.Cleanup(wocSrv.Close)
	f := NewProofFetcher(txrelay.NewARCClient(arcSrv.URL, ""), slog.Default())
	f.SetBaseURL(wocSrv.URL)
	return f
}

// When ARC answers, TxStatus uses it and never touches WoC.
func TestTxStatusARCFirstShortCircuitsWoC(t *testing.T) {
	f := fetcherWithARC(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"txid":"x","txStatus":"MINED","blockHeight":900200}`))
		},
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("WoC must not be called when ARC answers")
			w.WriteHeader(http.StatusInternalServerError)
		},
	)
	st, err := f.TxStatus(statusTestTxID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !st.Found || !st.Mined || st.BlockHeight != 900200 {
		t.Fatalf("got %+v, want ARC's Found+Mined+BlockHeight=900200", st)
	}
	if st.Status != "MINED" || st.Source != BEEFSourceARC {
		t.Fatalf("got status=%q source=%q, want MINED/arc", st.Status, st.Source)
	}
}

// A non-MINED ARC status (e.g. a double-spend flag) is passed through verbatim,
// not flattened to a bool — this is why we adopted the canonical txStatus field.
func TestTxStatusARCStatusPassthrough(t *testing.T) {
	f := fetcherWithARC(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"txid":"x","txStatus":"DOUBLE_SPEND_ATTEMPTED"}`))
		},
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("WoC must not be called when ARC answers")
		},
	)
	st, err := f.TxStatus(statusTestTxID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.Status != "DOUBLE_SPEND_ATTEMPTED" || st.Mined || st.Source != BEEFSourceARC {
		t.Fatalf("got %+v, want DOUBLE_SPEND_ATTEMPTED passthrough, unmined, source=arc", st)
	}
}

// When ARC errors (outage or unknown tx), TxStatus falls back to WoC.
func TestTxStatusARCErrorFallsBackToWoC(t *testing.T) {
	f := fetcherWithARC(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError) // ARC down / unknown
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"blockheight":900300}`))
		},
	)
	st, err := f.TxStatus(statusTestTxID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !st.Found || !st.Mined || st.BlockHeight != 900300 {
		t.Fatalf("got %+v, want WoC fallback Found+Mined+BlockHeight=900300", st)
	}
	if st.Source != BEEFSourceWoC {
		t.Fatalf("got source=%q, want woc (fallback)", st.Source)
	}
}

// A stale-block ARC status carries a blockHeight but is NOT an active-chain
// confirmation — it must not report mined, and blockHeight must be suppressed so
// the handler yields 0 confirmations (regression for Codex 891e013b).
func TestTxStatusStaleBlockNotConfirmed(t *testing.T) {
	f := fetcherWithARC(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"txid":"x","txStatus":"MINED_IN_STALE_BLOCK","blockHeight":900500}`))
		},
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("WoC must not be called when ARC answers")
		},
	)
	st, err := f.TxStatus(statusTestTxID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.Mined {
		t.Fatalf("MINED_IN_STALE_BLOCK must not be treated as mined (got %+v)", st)
	}
	if st.BlockHeight != 0 {
		t.Fatalf("blockHeight must be 0 for a non-active-chain status, got %d", st.BlockHeight)
	}
	if st.Status != "MINED_IN_STALE_BLOCK" {
		t.Fatalf("txStatus must pass through verbatim, got %q", st.Status)
	}
}

// ARC MINED without a block height (absent JSON ⇒ blockHeight 0) cannot yield a
// real confirmation count, so it must NOT be treated as mined — otherwise the
// handler would emit confirmations = currentHeight+1 (regression for Codex bb1152de).
func TestTxStatusMinedWithoutHeightNotConfirmed(t *testing.T) {
	f := fetcherWithARC(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"txid":"x","txStatus":"MINED"}`)) // no blockHeight
		},
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("WoC must not be called when ARC answers")
		},
	)
	st, err := f.TxStatus(statusTestTxID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.Mined {
		t.Fatalf("MINED without a height must not be treated as mined (got %+v)", st)
	}
	if st.BlockHeight != 0 {
		t.Fatalf("blockHeight must be 0, got %d", st.BlockHeight)
	}
	if st.Status != "MINED" {
		t.Fatalf("txStatus must pass through, got %q", st.Status)
	}
}
