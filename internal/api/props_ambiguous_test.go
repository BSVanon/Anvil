package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/BSVanon/Anvil/internal/txrelay"
)

func TestAmbiguousOutcomePropertyHandlerPaths(t *testing.T) {
	for _, kind := range []string{"proof", "direct", "brc121"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			if kind != "brc121" {
				usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
					if calls.Add(1) == 1 {
						return arcJSONResponse(t, r, "QUEUED"), nil
					}
					return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
				})
			}
			srv, f, brc, direct, raw := replayPropertyServer(t)
			if kind == "proof" {
				f.pg.requireMempool = true
			}
			if kind == "brc121" {
				f.pg.brc121.submit = func(_ context.Context, p *brc121Payment, _ bool) (*txrelay.ARCResponse, error) {
					if calls.Add(1) == 1 {
						return nil, errors.New("network reply unavailable")
					}
					return &txrelay.ARCResponse{TxID: p.txid.String(), Status: "SEEN_ON_NETWORK"}, nil
				}
			}

			headers := map[string]string{}
			switch kind {
			case "proof":
				gate := f.pg.brc121
				f.pg.brc121 = nil
				challenge := getChallenge(t, srv, http.MethodGet, "/stats")
				f.pg.brc121 = gate
				headers[HeaderX402Proof] = proofCarrying(t, challenge, raw)
			case "direct":
				headers[HeaderBSVPayment] = direct
			case "brc121":
				headers = brc
			}
			pay := func() *httptest.ResponseRecorder { return getWithHeaders(srv, "/stats", headers) }
			first, second, third := pay(), pay(), pay()
			if first.Code != http.StatusServiceUnavailable || !noPaymentOffer(first) {
				t.Fatalf("ambiguous response = %d %s, headers %v", first.Code, first.Body.String(), first.Header())
			}
			if second.Code != http.StatusOK || third.Code != http.StatusPaymentRequired {
				t.Fatalf("retry statuses = %d, %d; want 200, 402", second.Code, third.Code)
			}
			if calls.Load() != 2 {
				t.Fatalf("network submissions = %d, want 2", calls.Load())
			}
		})
	}
}
