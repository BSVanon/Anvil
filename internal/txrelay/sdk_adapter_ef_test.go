package txrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// arcCaptureServer spins up a fake ARC that records the exact request body it
// receives, so tests can assert which wire format the broadcaster sent.
func arcCaptureServer(t *testing.T) (*httptest.Server, <-chan []byte) {
	t.Helper()
	got := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case got <- body:
		default:
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(ARCResponse{TxID: "abc", Status: "SEEN_ON_NETWORK"})
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

// TestSDKBroadcaster_ARCReceivesExtendedFormat is the regression for the DEX-
// reported ARC "460 Missing input scripts ... parent transaction not found":
// when the tx carries its source outputs (they ride in the submitted BEEF, which
// the engine's SPV already relied on), the broadcaster must hand ARC EXTENDED
// FORMAT — not a bare raw tx that forces ARC to fetch parents it doesn't have.
func TestSDKBroadcaster_ARCReceivesExtendedFormat(t *testing.T) {
	srv, got := arcCaptureServer(t)
	inner := NewBroadcaster(NewMempool(), NewARCClient(srv.URL, ""), slog.Default())
	sdk := NewSDKBroadcasterWithLogger(inner, slog.Default())

	tx := buildSpendableChildTx(t) // input carries SourceTransaction → EF-able
	ef, err := tx.EF()
	if err != nil {
		t.Fatalf("test tx must be EF-able: %v", err)
	}
	if bytes.Equal(ef, tx.Bytes()) {
		t.Fatal("EF and raw must differ for a tx with a source output")
	}

	if _, failure := sdk.BroadcastCtx(context.Background(), tx); failure != nil {
		t.Fatalf("local admit must succeed: %+v", failure)
	}

	select {
	case body := <-got:
		if !bytes.Equal(body, ef) {
			t.Fatalf("ARC must receive extended format (len=%d), got len=%d (raw len=%d)",
				len(ef), len(body), len(tx.Bytes()))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ARC was never called")
	}
}

// TestSDKBroadcaster_ARCFallsBackToRaw confirms the safe fallback: a tx whose
// inputs lack source outputs can't be serialised as extended format, so the
// broadcaster sends raw — no worse than before, ARC stays best-effort.
func TestSDKBroadcaster_ARCFallsBackToRaw(t *testing.T) {
	srv, got := arcCaptureServer(t)
	inner := NewBroadcaster(NewMempool(), NewARCClient(srv.URL, ""), slog.Default())
	sdk := NewSDKBroadcasterWithLogger(inner, slog.Default())

	// An input with a source txid but NO SourceTransaction/sourceOutput → EF() fails.
	tx := transaction.NewTransaction()
	tx.Version = 1
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       buildSpendableChildTx(t).TxID(),
		SourceTxOutIndex: 0,
		SequenceNumber:   0xffffffff,
	})
	lock, _ := script.NewFromHex("76a9140000000000000000000000000000000000000000ac")
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 900, LockingScript: lock})

	if _, err := tx.EF(); err == nil {
		t.Fatal("a tx without source outputs must NOT be EF-able")
	}
	raw := tx.Bytes()

	if _, failure := sdk.BroadcastCtx(context.Background(), tx); failure != nil {
		t.Fatalf("local admit must succeed: %+v", failure)
	}

	select {
	case body := <-got:
		if !bytes.Equal(body, raw) {
			t.Fatalf("ARC must receive the raw fallback (len=%d), got len=%d", len(raw), len(body))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ARC was never called")
	}
}
