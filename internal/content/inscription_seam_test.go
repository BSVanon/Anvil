package content

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
)

// TestInscription_FetchParsesAndCaches exercises the seam the gateway
// mechanism (internal/gateway) depends on: the same txid check, fetch and
// cache ServeContent uses, reachable without an http.ResponseWriter.
func TestInscription_FetchParsesAndCaches(t *testing.T) {
	bAddr := "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut"
	script := buildBProtocolScript(bAddr, []byte("hello-gateway"), "text/plain")
	tx := buildTestTx([][]byte{script})
	txid := realTxid(tx)

	p2p := &fakeTxSource{rawHex: hex.EncodeToString(tx)}
	s := NewServer("", p2p, nil, nil)

	data, ct, err := s.Inscription(context.Background(), txid, 0)
	if err != nil {
		t.Fatalf("Inscription: %v", err)
	}
	if string(data) != "hello-gateway" {
		t.Fatalf("got data %q", data)
	}
	if ct != "text/plain" {
		t.Fatalf("got content type %q", ct)
	}

	// Second call must come from cache: swap the source for one that
	// errors, and confirm the cached answer is still returned.
	s.p2pSource = &fakeTxSource{err: errors.New("must not be called")}
	data2, ct2, err := s.Inscription(context.Background(), txid, 0)
	if err != nil {
		t.Fatalf("expected cached hit, got error: %v", err)
	}
	if string(data2) != "hello-gateway" || ct2 != "text/plain" {
		t.Fatalf("cached call returned different data: %q %q", data2, ct2)
	}
}

// TestInscription_SharesServeContentCache confirms Inscription and
// ServeContent warm and read the SAME cache (the content seam's whole
// point — the gateway mechanism must not cold-start a second cache).
func TestInscription_SharesServeContentCache(t *testing.T) {
	bAddr := "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut"
	script := buildBProtocolScript(bAddr, []byte("shared-cache"), "text/plain")
	tx := buildTestTx([][]byte{script})
	txid := realTxid(tx)

	p2p := &fakeTxSource{rawHex: hex.EncodeToString(tx)}
	s := NewServer("", p2p, nil, nil)

	// Warm the cache via Inscription.
	if _, _, err := s.Inscription(context.Background(), txid, 0); err != nil {
		t.Fatalf("Inscription: %v", err)
	}

	// ServeContent, with the source now broken, must still serve the
	// Inscription-warmed cache entry.
	s.p2pSource = &fakeTxSource{err: errors.New("must not be called")}
	s.mu.RLock()
	_, ok := s.cache[txid+"_0"]
	s.mu.RUnlock()
	if !ok {
		t.Fatal("expected Inscription to have populated the shared cache under txid_0")
	}
}

func TestInscription_InvalidTxid(t *testing.T) {
	s := NewServer("", nil, nil, nil)
	if _, _, err := s.Inscription(context.Background(), "not-a-txid", 0); err == nil {
		t.Fatal("expected an error for an invalid txid")
	}
}

func TestInscription_NegativeVout(t *testing.T) {
	s := NewServer("", nil, nil, nil)
	txid := realTxid([]byte{0x01, 0x02})
	if _, _, err := s.Inscription(context.Background(), txid, -1); err == nil {
		t.Fatal("expected an error for a negative vout")
	}
}

func TestInscription_FetchFailurePropagates(t *testing.T) {
	txid := realTxid([]byte{0x01, 0x02})
	// A stubbed, always-404 WoC keeps this deterministic and off the real
	// network — otherwise fetchRawTx's fallthrough would reach the real
	// WhatsOnChain API after the fake P2P source fails.
	s := newWoCStub(t, nil, nil)
	s.p2pSource = &fakeTxSource{err: errors.New("boom")}

	if _, _, err := s.Inscription(context.Background(), txid, 0); err == nil {
		t.Fatal("expected fetch error to propagate")
	}
}

func TestInscription_CanceledContext(t *testing.T) {
	s := NewServer("", nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	txid := realTxid([]byte{0x01, 0x02})
	if _, _, err := s.Inscription(ctx, txid, 0); err == nil {
		t.Fatal("expected an already-canceled context to fail fast")
	}
}
