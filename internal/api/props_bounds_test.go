package api

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
)

func TestBoundsPropertyPaymentHeadersAreRefusedBeforeDecode(t *testing.T) {
	for _, kind := range []string{"proof", "direct", "brc121"} {
		t.Run(kind, func(t *testing.T) {
			value := strings.Repeat("x", maxPaymentHeaderBytes+1)
			if kind == "brc121" {
				f := newBRC121Fix(t, 100)
				srv := testServer(t)
				srv.paymentGate = f.pg
				rebuildRoutes(srv)
				headers := f.payment(t, 100, brc121Pay{})
				headers[headerBRC121Beef] = value
				w := getWithHeaders(srv, "/stats", headers)
				if w.Code != http.StatusPaymentRequired || f.arc.calls.Load() != 0 {
					t.Fatalf("oversized BRC-121 header = %d %s, ARC calls %d", w.Code, w.Body.String(), f.arc.calls.Load())
				}
				return
			}
			usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
				return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
			})
			srv := testServerWithPaymentGate(t, 100)
			srv.paymentGate.arcClient = usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
				return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
			})
			header := map[string]string{"proof": HeaderX402Proof, "direct": HeaderBSVPayment}[kind]
			w := getWithHeaders(srv, "/stats", map[string]string{header: value})
			if w.Code != http.StatusRequestHeaderFieldsTooLarge {
				t.Fatalf("oversized %s header = %d %s", kind, w.Code, w.Body.String())
			}
		})
	}
}

func TestBoundsPropertyPaymentBodiesAreBounded(t *testing.T) {
	rows := []struct {
		name  string
		setup func(*testing.T) *Server
		size  int
		want  int
	}{
		{"challenge body", func(t *testing.T) *Server { return testServerWithPaymentGate(t, 100) }, int(paymentBodyLimits.Max) + 1, http.StatusRequestEntityTooLarge},
		{"signed envelope body", func(t *testing.T) *Server { return testServer(t) }, int(maxSignedEnvelopeBody) + 1, http.StatusBadRequest},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			srv := row.setup(t)
			w := serveRouteCase(srv, pricedRouteCase{method: http.MethodPost, path: "/data", body: bytes.Repeat([]byte{'x'}, row.size)}, nil)
			if w.Code != row.want {
				t.Fatalf("oversized body = %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestBoundsPropertyConcurrentReadsAndDecodesShareLimits(t *testing.T) {
	t.Run("body read", func(t *testing.T) {
		oldReads, oldLimits := paymentBodyReads, paymentBodyLimits
		paymentBodyReads = bodyread.NewPermits(1)
		paymentBodyLimits.Grace = 10 * time.Millisecond
		t.Cleanup(func() { paymentBodyReads, paymentBodyLimits = oldReads, oldLimits })
		release, err := paymentBodyReads.Acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		srv := testServerWithPaymentGate(t, 100)
		w := serveRouteCase(srv, pricedRouteCase{method: http.MethodPost, path: "/data", body: []byte(`{}`)}, nil)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("full body-read pool = %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("direct decode", func(t *testing.T) {
		old := directPaymentSubmitSlots
		directPaymentSubmitSlots = make(chan struct{}, 1)
		directPaymentSubmitSlots <- struct{}{}
		t.Cleanup(func() { directPaymentSubmitSlots = old })
		srv := testServerWithPaymentGate(t, 100)
		srv.paymentGate.arcClient = usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
			return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
		})
		w := getWithHeaders(srv, "/stats", map[string]string{HeaderBSVPayment: "not-a-transaction"})
		if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != codeDirectPaymentBusy {
			t.Fatalf("full decode pool = %d %s", w.Code, w.Body.String())
		}
	})
}
