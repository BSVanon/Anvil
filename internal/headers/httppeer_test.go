package headers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/libsv/go-p2p/wire"
)

// serveChain exposes /headers/tip + /headers/range for a synthetic peer chain,
// indexed by height (rawByHeight[0] = genesis, [h] = the header at height h) —
// mirroring Anvil's real header endpoints (octet-stream range, 50-cap).
func serveChain(t *testing.T, rawByHeight [][]byte) *httptest.Server {
	t.Helper()
	tipHeight := len(rawByHeight) - 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/headers/tip"):
			var hdr wire.BlockHeader
			_ = hdr.Deserialize(bytes.NewReader(rawByHeight[tipHeight]))
			h := hdr.BlockHash()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"height":    tipHeight,
				"hash":      h.String(),
				"chainwork": "0",
			})
		case strings.HasPrefix(r.URL.Path, "/headers/range"):
			from, _ := strconv.Atoi(r.URL.Query().Get("from"))
			count, _ := strconv.Atoi(r.URL.Query().Get("count"))
			if count > 50 {
				http.Error(w, "count > 50", http.StatusBadRequest)
				return
			}
			if from < 0 || count < 1 || from+count-1 > tipHeight {
				http.Error(w, "range exceeds tip", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			for i := 0; i < count; i++ {
				_, _ = w.Write(rawByHeight[from+i])
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func rawHeader(t *testing.T, hdr *wire.BlockHeader) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := hdr.Serialize(&buf); err != nil {
		t.Fatalf("serialize header: %v", err)
	}
	return buf.Bytes()
}

// chainToRaw builds the height-indexed raw slice for a store's genesis plus a
// synthetic chain (chain[i] is at height i+1).
func chainToRaw(t *testing.T, genesisRaw []byte, chain []*wire.BlockHeader) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(chain)+1)
	out = append(out, genesisRaw)
	for _, h := range chain {
		out = append(out, rawHeader(t, h))
	}
	return out
}

// TestSyncFromHTTPPeer_ForwardCatchUp: a node far behind catches up from a peer
// over HTTP, across the 50-header batch cap (chain of 120 → 3 batches).
func TestSyncFromHTTPPeer_ForwardCatchUp(t *testing.T) {
	store := tmpStore(t)
	genesis, _ := store.HashAtHeight(0)
	genesisRaw, err := store.HeaderAtHeight(0)
	if err != nil {
		t.Fatalf("genesis raw: %v", err)
	}

	chain, _ := buildChain(genesis, 120, saltA, 1000)
	if err := store.AddHeaders(1, chain[:5]); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	if store.Tip() != 5 {
		t.Fatalf("primed tip = %d, want 5", store.Tip())
	}

	srv := serveChain(t, chainToRaw(t, genesisRaw, chain))
	syncer := NewSyncer(store, wire.MainNet, slog.Default())

	tip, err := syncer.SyncFromHTTPPeer(srv.URL)
	if err != nil {
		t.Fatalf("SyncFromHTTPPeer: %v", err)
	}
	if tip != 120 || store.Tip() != 120 {
		t.Fatalf("tip = %d / store %d, want 120", tip, store.Tip())
	}
	ourTipHash, _ := store.HashAtHeight(120)
	wantTip := chain[119].BlockHash()
	if !ourTipHash.IsEqual(&wantTip) {
		t.Fatal("tip hash mismatch after catch-up")
	}
}

// TestSyncFromHTTPPeer_ReorgToHeavierPeerChain: our tip sits on a shorter fork;
// the peer's chain shares a prefix then diverges heavier. The fallback must find
// the common ancestor and reorg to the peer's (heavier) chain — most-work still
// enforced, so a lighter peer chain would be rejected.
func TestSyncFromHTTPPeer_ReorgToHeavierPeerChain(t *testing.T) {
	store := tmpStore(t)
	genesis, _ := store.HashAtHeight(0)
	genesisRaw, _ := store.HeaderAtHeight(0)

	// Our chain: A1..A5 (heights 1-5).
	ours, _ := buildChain(genesis, 5, saltA, 1000)
	if err := store.AddHeaders(1, ours); err != nil {
		t.Fatalf("seed our chain: %v", err)
	}

	// Peer chain: shares heights 1-3 (A1-A3), then a heavier branch B4..B8.
	a3 := ours[2].BlockHash()
	branch, _ := buildChain(&a3, 5, saltB, 5000)
	peerChain := append(append([]*wire.BlockHeader{}, ours[:3]...), branch...)

	srv := serveChain(t, chainToRaw(t, genesisRaw, peerChain))
	syncer := NewSyncer(store, wire.MainNet, slog.Default())

	tip, err := syncer.SyncFromHTTPPeer(srv.URL)
	if err != nil {
		t.Fatalf("SyncFromHTTPPeer: %v", err)
	}
	if tip != 8 || store.Tip() != 8 {
		t.Fatalf("tip = %d / store %d, want 8 after reorg", tip, store.Tip())
	}
	// Heights 1-3 unchanged (A3), height 4+ reorged to the peer branch (B4, B8).
	if h3, _ := store.HashAtHeight(3); !h3.IsEqual(&a3) {
		t.Fatal("height 3 should still be the shared A3")
	}
	b4 := branch[0].BlockHash()
	if h4, _ := store.HashAtHeight(4); !h4.IsEqual(&b4) {
		t.Fatal("height 4 should have reorged to the peer branch B4")
	}
	b8 := branch[4].BlockHash()
	if h8, _ := store.HashAtHeight(8); !h8.IsEqual(&b8) {
		t.Fatal("tip should be the peer branch B8")
	}
}

// TestHTTPHeaderSource_RejectsShortRange: a peer returning fewer headers than
// requested must be rejected — the forward-catch-up loop applies each batch at
// store.Tip()+1, so a short batch would silently desync heights.
func TestHTTPHeaderSource_RejectsShortRange(t *testing.T) {
	hdr := wire.NewBlockHeader(1, mustTestHash(saltA), mustTestHash(saltB), 0x1d00ffff, 0)
	oneRaw := rawHeader(t, hdr)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/headers/range") {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(oneRaw) // always 1 header, ignoring count
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	src := NewHTTPHeaderSource(srv.URL)
	if _, err := src.HeadersFrom(1, 3); err == nil {
		t.Fatal("expected an error when the peer returns fewer than the requested count")
	}
}

// TestSyncFromHTTPPeer_PeerNotAheadIsNoOp: a reachable-but-stale peer must be a
// no-op (leave our tip unchanged) so the caller moves on to the next peer.
func TestSyncFromHTTPPeer_PeerNotAheadIsNoOp(t *testing.T) {
	store := tmpStore(t)
	genesis, _ := store.HashAtHeight(0)
	genesisRaw, _ := store.HeaderAtHeight(0)
	chain, _ := buildChain(genesis, 10, saltA, 1000)
	if err := store.AddHeaders(1, chain); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	// Peer only has genesis + first 5 → behind us.
	srv := serveChain(t, chainToRaw(t, genesisRaw, chain[:5]))
	syncer := NewSyncer(store, wire.MainNet, slog.Default())
	tip, err := syncer.SyncFromHTTPPeer(srv.URL)
	if err != nil {
		t.Fatalf("SyncFromHTTPPeer: %v", err)
	}
	if tip != 10 || store.Tip() != 10 {
		t.Fatalf("stale peer should be a no-op: tip=%d store=%d, want 10", tip, store.Tip())
	}
}

// TestSyncFromHTTPPeers_SkipsStaleAdvancesFromNext pins the caller sequencing: a
// stale (not-ahead) first peer is skipped and we advance from a healthy second.
func TestSyncFromHTTPPeers_SkipsStaleAdvancesFromNext(t *testing.T) {
	store := tmpStore(t)
	genesis, _ := store.HashAtHeight(0)
	genesisRaw, _ := store.HeaderAtHeight(0)
	chain, _ := buildChain(genesis, 10, saltA, 1000)
	if err := store.AddHeaders(1, chain[:3]); err != nil { // we're at tip 3
		t.Fatalf("seed store: %v", err)
	}

	stale := serveChain(t, chainToRaw(t, genesisRaw, chain[:2])) // tip 2, behind us
	fresh := serveChain(t, chainToRaw(t, genesisRaw, chain))     // tip 10, ahead

	syncer := NewSyncer(store, wire.MainNet, slog.Default())
	tip, advanced := syncer.SyncFromHTTPPeers([]string{stale.URL, fresh.URL})
	if !advanced {
		t.Fatal("expected advancement from the second (fresh) peer")
	}
	if tip != 10 || store.Tip() != 10 {
		t.Fatalf("tip = %d / store %d, want 10", tip, store.Tip())
	}
}
