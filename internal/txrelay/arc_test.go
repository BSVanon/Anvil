package txrelay

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

func TestARCClientSubmit(t *testing.T) {
	// Mock ARC server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/tx" {
			t.Fatalf("expected /v1/tx, got %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/octet-stream" {
			t.Fatalf("expected octet-stream, got %s", r.Header.Get("Content-Type"))
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ARCResponse{
			TxID:   "abc123",
			Status: "SEEN_ON_NETWORK",
		})
	}))
	defer srv.Close()

	client := NewARCClient(srv.URL, "")
	resp, err := client.Submit([]byte{0x01, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TxID != "abc123" {
		t.Fatalf("expected txid abc123, got %s", resp.TxID)
	}
	if resp.Status != "SEEN_ON_NETWORK" {
		t.Fatalf("expected SEEN_ON_NETWORK, got %s", resp.Status)
	}
}

func TestARCClientSubmitWithAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-key" {
			t.Fatalf("expected Bearer test-key, got %s", auth)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ARCResponse{TxID: "def456", Status: "SEEN_ON_NETWORK"})
	}))
	defer srv.Close()

	client := NewARCClient(srv.URL, "test-key")
	resp, err := client.Submit([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TxID != "def456" {
		t.Fatalf("got %s", resp.TxID)
	}
}

func TestARCClientSubmitError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid tx"}`))
	}))
	defer srv.Close()

	client := NewARCClient(srv.URL, "")
	_, err := client.Submit([]byte{0x01})
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
}

func TestARCClientSubmitRejected(t *testing.T) {
	// ARC returns 200 but with a non-acceptance status
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ARCResponse{
			TxID:   "bad123",
			Status: "REJECTED",
		})
	}))
	defer srv.Close()

	client := NewARCClient(srv.URL, "")
	resp, err := client.Submit([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	// The client should return the response — it's the caller's job to check status
	if resp.Status != "REJECTED" {
		t.Fatalf("expected REJECTED, got %s", resp.Status)
	}
}

func TestBroadcastToARCRejectsNonAccepted(t *testing.T) {
	// Mock ARC that returns DOUBLE_SPEND_ATTEMPTED
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ARCResponse{
			TxID:   "ds123",
			Status: "DOUBLE_SPEND_ATTEMPTED",
		})
	}))
	defer srv.Close()

	arc := NewARCClient(srv.URL, "")
	b := NewBroadcaster(NewMempool(), arc, slog.Default())

	// Need a valid raw tx for the broadcaster to parse
	tx := transaction.NewTransaction()
	tx.Version = 1
	raw := tx.Bytes()

	result, err := b.BroadcastToARC(raw)
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted {
		t.Fatal("DOUBLE_SPEND_ATTEMPTED should not be accepted")
	}
	if result.Status != "DOUBLE_SPEND_ATTEMPTED" {
		t.Fatalf("expected DOUBLE_SPEND_ATTEMPTED, got %s", result.Status)
	}
}

func TestBroadcastToARCAcceptsSeenOnNetwork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ARCResponse{
			TxID:   "good123",
			Status: "SEEN_ON_NETWORK",
		})
	}))
	defer srv.Close()

	arc := NewARCClient(srv.URL, "")
	b := NewBroadcaster(NewMempool(), arc, slog.Default())

	tx := transaction.NewTransaction()
	tx.Version = 1
	raw := tx.Bytes()

	result, err := b.BroadcastToARC(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatal("SEEN_ON_NETWORK should be accepted")
	}
}

func TestARCClientQueryStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ARCResponse{
			TxID:        "abc123",
			Status:      "MINED",
			BlockHeight: 850000,
			MerklePath:  "deadbeef",
		})
	}))
	defer srv.Close()

	client := NewARCClient(srv.URL, "")
	resp, err := client.QueryStatus("abc123")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "MINED" {
		t.Fatalf("expected MINED, got %s", resp.Status)
	}
	if resp.BlockHeight != 850000 {
		t.Fatalf("expected height 850000, got %d", resp.BlockHeight)
	}
}
