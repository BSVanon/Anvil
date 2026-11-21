package netguard

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestGuard_WithinHeaderDeadlineLeaksNoGoroutine checks that
// withinHeaderDeadline's
// context.WithCancel can start a goroutine to propagate a parent context's
// own cancellation, which only stops once cancel is called -- forgetting to
// call it on every path (an error before headers arrive, headers arriving
// normally, or the response body eventually being closed) would leak one
// per exchange. 250 guarded GASP node exchanges across five reply shapes
// (honest, refused, undecodable, over cap, short body) must leave the
// goroutine count where it started, not growing with the exchange count.
func TestGuard_WithinHeaderDeadlineLeaksNoGoroutine(t *testing.T) {
	honest := gaspNodeReply(t, honestTx(t))
	bad := gaspNodeReply(t, malformedReparseTx(t))
	shapes := map[string]http.HandlerFunc{
		"honest": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(honest)))
			_, _ = w.Write(honest)
		},
		"refused": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(bad)))
			_, _ = w.Write(bad)
		},
		"undecodable": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("nope"))
		},
		"over cap": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(int(MaxResponseBytes)+1))
			w.WriteHeader(http.StatusOK)
		},
		"short": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1000")
			_, _ = w.Write(bytes.Repeat([]byte{' '}, 10))
		},
	}
	var srvs []*httptest.Server
	for _, h := range shapes {
		srv := httptest.NewServer(h)
		srvs = append(srvs, srv)
		t.Cleanup(srv.Close)
	}

	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	time.Sleep(200 * time.Millisecond)
	before := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		for _, srv := range srvs {
			_, _ = engine.NewOverlayGASPRemote(srv.URL, "tm_x", http.DefaultClient, 8).
				RequestNode(context.Background(), nil, &transaction.Outpoint{Index: uint32(i)}, false)
		}
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()

	var after int
	for j := 0; j < 40; j++ {
		time.Sleep(50 * time.Millisecond)
		after = runtime.NumGoroutine()
		if after <= before {
			break
		}
	}
	t.Logf("goroutines before %d, after 250 guarded GASP exchanges (5 shapes): %d", before, after)
	if after > before+2 {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Errorf("possible goroutine leak (before %d, after %d):\n%s", before, after, buf[:n])
	}
}
