package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

const (
	propertyPrivateTopic  = "example:private-x"
	propertyPrivateSecret = "private-marker-x"
	propertyPrivatePubkey = "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66"
)

func storePropertyPrivate(srv *Server) {
	now := time.Now().Unix()
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: propertyPrivateTopic, Payload: propertyPrivateSecret,
		Pubkey: propertyPrivatePubkey, Signature: "3045022100abcd", TTL: 60, Timestamp: now, Private: true,
	})
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: "identity:" + propertyPrivatePubkey, Payload: `{"private-marker-x":true}`,
		Pubkey: propertyPrivatePubkey, Signature: "3045022100abcd", TTL: 60, Timestamp: now + 1, Private: true,
	})
}

func TestPrivateEnvelopePropertyReadRouteMatrix(t *testing.T) {
	rows := []struct {
		name         string
		path         string
		marker       string
		operatorSees bool
	}{
		{"data", "/data?topic=" + propertyPrivateTopic, propertyPrivateSecret, true},
		{"topics", "/topics", propertyPrivateTopic, true},
		{"topic", "/topics/" + propertyPrivateTopic, propertyPrivateTopic, true},
		{"identity", "/identity/" + propertyPrivatePubkey, propertyPrivateSecret, true},
		{"stats", "/stats", propertyPrivateTopic, true},
		{"mesh status", "/mesh/status", propertyPrivateTopic, false},
		{"mesh nodes", "/mesh/nodes", propertyPrivateTopic, false},
	}
	for _, row := range rows {
		for _, credential := range []string{"direct payment", "operator"} {
			t.Run(row.name+"/"+credential, func(t *testing.T) {
				usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
					return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
				})
				srv := testServerWithPaymentGate(t, 100)
				srv.paymentGate.arcClient = usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
					return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
				})
				storePropertyPrivate(srv)
				headers := map[string]string{}
				if credential == "operator" {
					headers["Authorization"] = "Bearer test-token"
				} else {
					headers[HeaderBSVPayment] = signedEFPaying(t, paidOut{testPayeeScript(t), 100})
				}
				w := getWithHeaders(srv, row.path, headers)
				body := w.Body.String()
				visible := strings.Contains(body, row.marker)
				wantVisible := credential == "operator" && row.operatorSees
				if visible != wantVisible {
					t.Fatalf("private visibility = %v, want %v: %d %s", visible, wantVisible, w.Code, body)
				}
			})
		}
	}
}

func privateSSEBody(t *testing.T, srv *Server, topic string, headers map[string]string, operator bool) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/data/subscribe?topic="+topic, nil).WithContext(ctx)
	req.Host = "localhost"
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(w, req)
		close(done)
	}()
	waitForSSESubscription(t, srv, topic)
	start := srv.sseHub.seqID.Load()
	srv.NotifyEnvelope(&envelope.Envelope{Type: "data", Topic: topic, Payload: propertyPrivateSecret, Private: true})
	srv.NotifyEnvelope(&envelope.Envelope{Type: "data", Topic: topic, Payload: "public-sentinel-x"})
	wantDelta := int64(1)
	if operator {
		wantDelta = 2
	}
	deadline := time.Now().Add(2 * time.Second)
	for srv.sseHub.seqID.Load()-start < wantDelta && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	cancel()
	<-done
	if srv.sseHub.seqID.Load()-start < wantDelta {
		t.Fatalf("stream did not process its sentinel")
	}
	return w.Body.String()
}

func TestPrivateEnvelopePropertySSECredentialMatrix(t *testing.T) {
	for _, kind := range []string{"proof", "direct", "brc121", "app token", "operator"} {
		t.Run(kind, func(t *testing.T) {
			var srv *Server
			headers := map[string]string{}
			topic := "example:private-sse-x"
			if kind == "app token" {
				srv = testServer(t)
				key, _ := ec.NewPrivateKey()
				seedEnvelopeAt(t, srv.envelopeStore, topic, `{"public":true}`, time.Now().Unix(), tokenModel(key))
				srv.tokenGate = NewTokenGate(NewTopicMonetizationResolver(srv.envelopeStore), true)
				rebuildRoutes(srv)
				headers["X-App-Token"] = mintAppToken(key, topic)
			} else {
				usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
					return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
				})
				var f *brc121Fix
				var brc map[string]string
				var direct string
				var raw []byte
				srv, f, brc, direct, raw = replayPropertyServer(t)
				switch kind {
				case "proof":
					gate := f.pg.brc121
					f.pg.brc121 = nil
					challenge := getChallenge(t, srv, http.MethodGet, "/data/subscribe?topic="+topic)
					f.pg.brc121 = gate
					headers[HeaderX402Proof] = proofCarrying(t, challenge, raw)
				case "direct":
					headers[HeaderBSVPayment] = direct
				case "brc121":
					headers = brc
				case "operator":
					headers["Authorization"] = "Bearer test-token"
				}
			}
			body := privateSSEBody(t, srv, topic, headers, kind == "operator")
			if strings.Contains(body, propertyPrivateSecret) != (kind == "operator") {
				t.Fatalf("private SSE body for %s: %s", kind, body)
			}
			if !strings.Contains(body, "public-sentinel-x") {
				t.Fatalf("stream made no progress: %s", body)
			}
		})
	}
}

func TestPrivateEnvelopePropertyWriteCredentialsDoNotPersist(t *testing.T) {
	rows := []struct {
		name  string
		setup func(*testing.T) *Server
	}{
		{"signed envelope", func(t *testing.T) *Server {
			srv := testServer(t)
			key, _ := ec.NewPrivateKey()
			env := &envelope.Envelope{Type: "data", Topic: "example:public-write-x", Payload: `{"ok":true}`, TTL: 60, Timestamp: time.Now().Unix()}
			env.Sign(key)
			body, _ := json.Marshal(env)
			if w := serveRouteCase(srv, pricedRouteCase{method: http.MethodPost, path: "/data", body: body}, nil); w.Code != http.StatusOK {
				t.Fatalf("signed publish = %d %s", w.Code, w.Body.String())
			}
			return srv
		}},
		{"tip update", func(t *testing.T) *Server {
			f := newTipFixture(t, "test-token", 100)
			next := f.move(f.w, f.origin, 0, f.inscribed("next"))
			if w := post(f.srv, ordtracktest.AtomicBEEF(t, next), nil); w.Code != http.StatusOK {
				t.Fatalf("tip update = %d %s", w.Code, w.Body.String())
			}
			f.srv.paymentGate = nil
			rebuildRoutes(f.srv)
			return f.srv
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			srv := row.setup(t)
			storePropertyPrivate(srv)
			w := getWithHeaders(srv, "/data?topic="+propertyPrivateTopic, nil)
			if strings.Contains(w.Body.String(), propertyPrivateSecret) {
				t.Fatalf("write credential persisted into later read: %s", w.Body.String())
			}
		})
	}
}
