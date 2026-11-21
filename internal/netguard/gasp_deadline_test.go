package netguard

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/gasp"
)

// TestGuard_GASPHeaderStallIsBounded verifies that before withinHeaderDeadline,
// only the body read
// had a deadline, so a peer that sent its response headers late -- or never
// -- blocked the whole exchange with no bound, and since GASP sync runs one
// peer and topic at a time on the root context, one such peer froze every
// later one too. A peer that otherwise answers honestly, just past the
// guard's header timeout, is now cut off at about that timeout instead of
// being waited out.
func TestGuard_GASPHeaderStallIsBounded(t *testing.T) {
	body, err := json.Marshal(&gasp.Node{GraphID: gaspOutpoint, RawTx: hex.EncodeToString(honestTx(t))})
	if err != nil {
		t.Fatalf("marshal gasp.Node: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(500 * time.Millisecond) // past the 100ms header timeout below
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	g := &guard{base: http.DefaultTransport, maxBytes: MaxResponseBytes, headerTimeout: 100 * time.Millisecond}
	start := time.Now()
	_, err = engine.NewOverlayGASPRemote(srv.URL, "tm_x", &http.Client{Transport: g}, 8).
		RequestNode(context.Background(), nil, gaspOutpoint, false)
	took := time.Since(start)
	t.Logf("peer answers at 500ms, header timeout 100ms: cut off after %v, err=%v", took, err)
	if err == nil {
		t.Fatal("want the header stall cut off, got a node back")
	}
	if took > 400*time.Millisecond {
		t.Errorf("cut off after %v, want well under the peer's 500ms answer, about the 100ms header timeout", took)
	}
}

// TestGuard_GASPSyncTrickleIsCutByMinRate verifies that before isGASPSync,
// a /requestSyncResponse 200
// fell through RoundTrip's generic cappedBody wrap, capped on size alone,
// with no deadline and no minimum rate -- unlike a /requestForeignGASPNode
// reply, which already read under both. A peer that answers headers
// promptly and then trickles its body far below the minimum rate is now cut
// off once its grace period passes, the same as a GASP node reply already
// was.
func TestGuard_GASPSyncTrickleIsCutByMinRate(t *testing.T) {
	const declared = 4 << 20
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(declared))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(" "))
		w.(http.Flusher).Flush()
		select {
		case <-stop:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	g := &guard{base: http.DefaultTransport, maxBytes: MaxResponseBytes, minRate: 64 << 10, grace: 150 * time.Millisecond}
	start := time.Now()
	_, err := engine.NewOverlayGASPRemote(srv.URL, "tm_x", &http.Client{Transport: g}, 8).
		GetInitialResponse(context.Background(), &gasp.InitialRequest{Version: 1})
	took := time.Since(start)
	t.Logf("declared %d, trickle stalled after one byte: cut off after %v, err=%v", declared, took, err)
	if err == nil {
		t.Fatal("want the trickle cut off, got a response back")
	}
	if !strings.Contains(err.Error(), "below") {
		t.Errorf("want the minimum-rate cutoff, got: %v", err)
	}
	if took > 3*time.Second {
		t.Fatalf("the cutoff took %v, want about the 150ms grace period", took)
	}
}

// TestGuard_GASPSyncHonestReplyStillPasses: checkGASPSync must not have
// broken the ordinary case while bounding it -- an honest, promptly-sent
// InitialResponse is still read and decoded correctly through the guard.
func TestGuard_GASPSyncHonestReplyStillPasses(t *testing.T) {
	want := &gasp.InitialResponse{Since: 42, UTXOList: []*gasp.Output{{OutputIndex: 1, Score: 2.5}}}
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal InitialResponse: %v", err)
	}
	url, _ := serveAnswer(t, "application/json", body, false)
	got, err := engine.NewOverlayGASPRemote(url, "tm_x", http.DefaultClient, 8).
		GetInitialResponse(context.Background(), &gasp.InitialRequest{Version: 1})
	if err != nil {
		t.Fatalf("GetInitialResponse: %v", err)
	}
	if got.Since != want.Since || len(got.UTXOList) != 1 || got.UTXOList[0].OutputIndex != want.UTXOList[0].OutputIndex {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// TestGASPReadTimeout pins gaspReadTimeout's formula directly: GASPReadBase
// plus declared length over
// GASPReadRate, capped at GASPReadMax, with an undeclared (-1) length
// getting the cap outright. A behavioral test paced in real time, like
// TestGuard_GASPNodeHonestLargeReplyAtModerateRatePasses below, can only
// confirm the deadline was generous enough for one case; this confirms the
// exact arithmetic for several, including the cap, with no sleeping.
func TestGASPReadTimeout(t *testing.T) {
	cases := []struct {
		name          string
		contentLength int64
		want          time.Duration
	}{
		{"undeclared length gets the cap outright", -1, GASPReadMax},
		{"zero length is just the base", 0, GASPReadBase},
		{"20 MiB grows the base by 40s", 20 << 20, GASPReadBase + 40*time.Second},
		// 1 GiB is past the formula's own ~75 MiB breakeven (where base
		// plus the size term first exceeds GASPReadMax) while staying well
		// under the ~8.59 GiB declared length that overflows the
		// contentLength*time.Second multiplication itself (found while
		// writing this test, reported separately, not fixed here: it
		// makes gaspReadTimeout return a negative duration, which
		// bodyread.Read treats as no deadline at all).
		{"a length past the cap's own breakeven is still capped", 1 << 30, GASPReadMax},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := gaspReadTimeout(c.contentLength); got != c.want {
				t.Errorf("gaspReadTimeout(%d) = %v, want %v", c.contentLength, got, c.want)
			}
		})
	}
}

// gaspPacedNodeReply builds a gasp.Node reply of about n total bytes, padding
// TxMetadata with ASCII so its size is predictable without needing raw,
// unescaped wire bytes (unlike gaspnode_amplify_test.go, this test is not
// exercising json.Marshal's HTML-escaping, so a plain Marshal is fine).
func gaspPacedNodeReply(t *testing.T, n int) []byte {
	t.Helper()
	pad := n - 200 // leave room for the JSON structure and hex rawTx
	if pad < 0 {
		pad = 0
	}
	body, err := json.Marshal(&gasp.Node{
		GraphID:    gaspOutpoint,
		RawTx:      hex.EncodeToString(honestTx(t)),
		TxMetadata: strings.Repeat("a", pad),
	})
	if err != nil {
		t.Fatalf("marshal gasp.Node: %v", err)
	}
	return body
}

// pacedWrite writes body in chunks at about ratePerSec bytes/s, flushing
// after each one, for servers in this file that need to hold a real wall
// clock pace rather than send everything at once.
func pacedWrite(w http.ResponseWriter, body []byte, ratePerSec int) {
	const tick = 250 * time.Millisecond
	chunk := int(float64(ratePerSec) * tick.Seconds())
	if chunk < 1 {
		chunk = 1
	}
	flusher, _ := w.(http.Flusher)
	for off := 0; off < len(body); off += chunk {
		end := off + chunk
		if end > len(body) {
			end = len(body)
		}
		if _, err := w.Write(body[off:end]); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		if end < len(body) {
			time.Sleep(tick)
		}
	}
}

// TestGuard_GASPNodeHonestLargeReplyAtModerateRatePasses verifies that a
// 20 MB /requestForeignGASPNode
// reply (what a roughly 10 MB transaction and its proof hex out to) from a
// peer sustaining about 1 MB/s -- comfortably over bodyread's minimum rate,
// and well under gaspReadTimeout's 70s allowance for this size -- must not
// be refused. The guard here uses the same minRate and grace Install gives
// http.DefaultClient, so this also confirms the shared readGASPReply path
// did not pick up some other, shorter deadline by mistake.
func TestGuard_GASPNodeHonestLargeReplyAtModerateRatePasses(t *testing.T) {
	const size = 20 << 20 // 20 MB
	const rate = 1 << 20  // about 1 MB/s
	body := gaspPacedNodeReply(t, size)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		pacedWrite(w, body, rate)
	}))
	defer srv.Close()

	g := &guard{base: http.DefaultTransport, maxBytes: MaxResponseBytes, minRate: bodyread.MinReadRate, grace: bodyread.ReadGrace}
	start := time.Now()
	node, err := engine.NewOverlayGASPRemote(srv.URL, "tm_x", &http.Client{Transport: g}, 8).
		RequestNode(context.Background(), nil, gaspOutpoint, false)
	took := time.Since(start)
	t.Logf("%d-byte reply paced at about %d B/s: took %v, err=%v", len(body), rate, took, err)
	if err != nil {
		t.Fatalf("want the paced reply accepted, got: %v", err)
	}
	if node == nil || node.RawTx == "" {
		t.Fatalf("want a decoded node with its transaction, got %+v", node)
	}
	// Sanity on the pacing itself (it really took close to 20s, not an
	// instant send the deadline logic never had to matter for) and a loose
	// upper bound well short of the 180s cap or the computed 70s deadline.
	if took < 10*time.Second {
		t.Errorf("reply arrived in %v, want the pacing to have held it to approximately 20s", took)
	}
	if took > 90*time.Second {
		t.Errorf("reply took %v, want comfortably under the ~70s deadline this size computes to", took)
	}
}

// TestGuard_GASPNodeTrickleStillCutByMinRate verifies the minimum-rate check
// on the /requestForeignGASPNode
// path itself (TestGuard_GASPSyncTrickleIsCutByMinRate covers the same
// guarantee on /requestSyncResponse): readGASPReply is shared by both
// checkGASPNode and checkGASPSync, so introducing gaspReadTimeout's
// size-scaled overall deadline must not have loosened or dropped the
// bodyread minimum-rate floor checkGASPNode already read under.
func TestGuard_GASPNodeTrickleStillCutByMinRate(t *testing.T) {
	const declared = 4 << 20
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", strconv.Itoa(declared))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(" "))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-stop:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	g := &guard{base: http.DefaultTransport, maxBytes: MaxResponseBytes, minRate: 64 << 10, grace: 150 * time.Millisecond}
	start := time.Now()
	_, err := engine.NewOverlayGASPRemote(srv.URL, "tm_x", &http.Client{Transport: g}, 8).
		RequestNode(context.Background(), nil, gaspOutpoint, false)
	took := time.Since(start)
	t.Logf("declared %d, GASP node trickle stalled after one byte: cut off after %v, err=%v", declared, took, err)
	if err == nil {
		t.Fatal("want the trickle cut off, got a node back")
	}
	if !strings.Contains(err.Error(), "below") {
		t.Errorf("want the minimum-rate cutoff, got: %v", err)
	}
	if took > 3*time.Second {
		t.Fatalf("the cutoff took %v, want about the 150ms grace period", took)
	}
}
