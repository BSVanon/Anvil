package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type pricedRouteCase struct {
	name   string
	method string
	path   string
	body   []byte
}

func pricedRouteCases() []pricedRouteCase {
	return []pricedRouteCase{
		{"status", http.MethodGet, "/status", nil},
		{"stats", http.MethodGet, "/stats", nil},
		{"header tip", http.MethodGet, "/headers/tip", nil},
		{"header range", http.MethodGet, "/headers/range?start=0&count=1", nil},
		{"transaction BEEF", http.MethodGet, "/tx/" + strings.Repeat("0", 64) + "/beef", nil},
		{"data query", http.MethodGet, "/data?topic=example:route-x", nil},
		{"data subscription", http.MethodGet, "/data/subscribe?topic=example:route-x", nil},
		{"overlay lookup", http.MethodGet, "/overlay/lookup", nil},
		{"topics", http.MethodGet, "/topics", nil},
		{"topic", http.MethodGet, "/topics/example:route-x", nil},
		{"identity", http.MethodGet, "/identity/" + strings.Repeat("0", 66), nil},
		{"watch list", http.MethodGet, "/mempool/watch", nil},
		{"watch history", http.MethodGet, "/mempool/watch/history", nil},
		{"watch subscription", http.MethodGet, "/mempool/watch/subscribe", nil},
		{"broadcast", http.MethodPost, "/broadcast", []byte("not-a-beef")},
		{"data publish", http.MethodPost, "/data", []byte(`{}`)},
	}
}

func serveRouteCase(srv *Server, row pricedRouteCase, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(row.method, row.path, bytes.NewReader(row.body))
	req.Host = "localhost"
	if strings.Contains(row.path, "/subscribe") && len(headers) > 0 {
		ctx, cancel := context.WithCancel(req.Context())
		cancel()
		req = req.WithContext(ctx)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func challengeForRoute(t *testing.T, srv *Server, row pricedRouteCase) *X402Challenge {
	t.Helper()
	w := serveRouteCase(srv, row, nil)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("challenge status = %d: %s", w.Code, w.Body.String())
	}
	var challenge X402Challenge
	if err := json.Unmarshal(w.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	return &challenge
}

func TestRouteCredentialPropertyPricedRoutesRejectNoCredential(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	for _, row := range pricedRouteCases() {
		t.Run(row.name, func(t *testing.T) {
			w := serveRouteCase(srv, row, nil)
			if w.Code != http.StatusPaymentRequired && w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 or 402: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestRouteCredentialPropertyOperatorBypassesPricedGate(t *testing.T) {
	for _, row := range pricedRouteCases() {
		t.Run(row.name, func(t *testing.T) {
			srv := testServerWithPaymentGate(t, 100)
			w := serveRouteCase(srv, row, map[string]string{"Authorization": "Bearer test-token"})
			if w.Code == http.StatusPaymentRequired || w.Code == http.StatusUnauthorized {
				t.Fatalf("operator stopped at credential gate: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestRouteCredentialPropertyPaymentsReachAllowedRoutes(t *testing.T) {
	rows := []pricedRouteCase{
		{"read", http.MethodGet, "/stats", nil},
		{"publish", http.MethodPost, "/data", []byte(`{}`)},
		{"broadcast", http.MethodPost, "/broadcast", []byte("not-a-beef")},
	}
	for _, kind := range []string{"proof", "direct", "brc121"} {
		for _, row := range rows {
			t.Run(kind+"/"+row.name, func(t *testing.T) {
				var w *httptest.ResponseRecorder
				if kind == "brc121" {
					f := newBRC121Fix(t, 100)
					srv := testServer(t)
					srv.paymentGate = f.pg
					rebuildRoutes(srv)
					w = serveRouteCase(srv, row, f.payment(t, 100, brc121Pay{}))
				} else {
					usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
						return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
					})
					srv := testServerWithPaymentGate(t, 100)
					srv.paymentGate.arcClient = usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
						return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
					})
					headers := map[string]string{}
					if kind == "proof" {
						ch := challengeForRoute(t, srv, row)
						headers[HeaderX402Proof] = buildProof(t, ch, 100, testPayeeScript(t))
					} else {
						headers[HeaderBSVPayment] = signedEFPaying(t, paidOut{testPayeeScript(t), 100})
					}
					w = serveRouteCase(srv, row, headers)
				}
				if w.Code == http.StatusPaymentRequired || w.Code == http.StatusUnauthorized || w.Code == http.StatusServiceUnavailable {
					t.Fatalf("verified %s credential stopped at gate: %d %s", kind, w.Code, w.Body.String())
				}
				if w.Header().Get(HeaderX402Receipt) == "" {
					t.Fatal("verified payment produced no receipt")
				}
			})
		}
	}
}

func TestRouteCredentialPropertyNarrowCredentialsStayNarrow(t *testing.T) {
	t.Run("app token", func(t *testing.T) {
		srv := testServerWithPaymentGate(t, 100)
		key, _ := ec.NewPrivateKey()
		seedEnvelope(t, srv.envelopeStore, "example:token-x", tokenModel(key))
		resolver := NewTopicMonetizationResolver(srv.envelopeStore)
		srv.paymentGate = testGateWithAppPayments(t, 100, srv.envelopeStore)
		srv.tokenGate = NewTokenGate(resolver, true)
		rebuildRoutes(srv)
		token := mintAppToken(key, "example:token-x")
		rows := []struct {
			path string
			want int
		}{{"/data?topic=example:token-x", http.StatusOK}, {"/stats?topic=example:token-x", http.StatusPaymentRequired}}
		for _, row := range rows {
			w := serveRouteCase(srv, pricedRouteCase{method: http.MethodGet, path: row.path}, map[string]string{"X-App-Token": token})
			if w.Code != row.want {
				t.Fatalf("%s status = %d, want %d", row.path, w.Code, row.want)
			}
		}
	})

	t.Run("signed envelope", func(t *testing.T) {
		srv := testServer(t)
		key, _ := ec.NewPrivateKey()
		env := &envelope.Envelope{Type: "data", Topic: "example:signed-x", Payload: `{"ok":true}`, TTL: 60, Timestamp: time.Now().Unix()}
		env.Sign(key)
		body, _ := json.Marshal(env)
		rows := []struct {
			path string
			want int
		}{{"/data", http.StatusOK}, {"/broadcast", http.StatusUnauthorized}}
		for _, row := range rows {
			w := serveRouteCase(srv, pricedRouteCase{method: http.MethodPost, path: row.path, body: body}, nil)
			if w.Code != row.want {
				t.Fatalf("%s status = %d, want %d: %s", row.path, w.Code, row.want, w.Body.String())
			}
		}
	})
}
