package netguard

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
)

// gaspUpgradeStreamBytes is how much a hostile peer streams on the hijacked
// connection after its unrequested 101, in
// TestGuard_RefusesUnrequestedSwitchingProtocolsFast: large enough that
// go-overlay-services' unbounded io.ReadAll of a non-200 body (the B2 gap
// this test closes) would be unmistakable in heap and time if the guard
// ever let it through.
const gaspUpgradeStreamBytes = 32 << 20

// gaspUpgradeHeapBound and gaspUpgradeTimeBound are far under what reading
// gaspUpgradeStreamBytes would cost: the guard must refuse the 101 before
// the base transport's body is ever read at all, from net/http's own
// hijacked-connection special case for a 101 (cold review round 4 cycle 6b,
// B2).
const (
	gaspUpgradeHeapBound = 8 << 20
	gaspUpgradeTimeBound = 2 * time.Second
)

// TestGuard_RefusesUnrequestedSwitchingProtocolsFast is cold review round 4
// cycle 6b's B2 reproduction, through the real GASP client: a peer answers a
// /requestForeignGASPNode POST (which never asks for an upgrade) with 101
// Switching Protocols and then streams bytes on the hijacked connection.
// go-overlay-services' doNodeRequest treats any non-200 reply's body as an
// ordinary error body and reads it in full with io.ReadAll, no cap -- for a
// 101, net/http hands that body on as the raw, unbounded connection, so
// without RoundTrip's own refusal (requestedUpgrade) this peer could stream
// without limit, at no cost to itself, on every node Anvil's GASP sync asks
// it for. Refused instead, fast and with bounded heap: requestedUpgrade
// (guard.go) refuses it before go-overlay-services ever sees a response, so
// its own unbounded read is never reached.
func TestGuard_RefusesUnrequestedSwitchingProtocolsFast(t *testing.T) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: x-evil\r\n\r\n")
		_ = buf.Flush()
		chunk := bytes.Repeat([]byte{'a'}, 1<<20)
		for sent := 0; sent < gaspUpgradeStreamBytes; sent += len(chunk) {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	var err error
	start := time.Now()
	peak, base := hostiletest.HeapPeak(func() {
		_, err = engine.NewOverlayGASPRemote(srv.URL, "tm_x", http.DefaultClient, 8).
			RequestNode(context.Background(), nil, gaspOutpoint, false)
	})
	took := time.Since(start)
	t.Logf("101 + %d MiB stream: refused in %v, heap peak %.1f MiB over %.1f MiB base, err=%v",
		gaspUpgradeStreamBytes>>20, took, mib(peak), mib(base), err)

	if err == nil {
		t.Fatal("want the unrequested 101 refused, got a node back")
	}
	if took > gaspUpgradeTimeBound {
		t.Errorf("refused after %v, want under %v", took, gaspUpgradeTimeBound)
	}
	if peak > gaspUpgradeHeapBound {
		t.Errorf("heap peak %d bytes over base, want under %d (the stream must never be read)", peak, gaspUpgradeHeapBound)
	}
}
