package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// issuanceServer is testServer behind a payment gate built from cfg, as
// cmd/anvil/main.go and NewServer build it. With wallet set the gate mints
// through a counting provider under an ample budget, so a test sees which
// requests issue a challenge rather than the budget; without it there is no
// nonce provider, as on a node without identity.wif and a wallet. Topic
// probe:priced is published with a passthrough price, probe:free without one.
func issuanceServer(t *testing.T, cfg PaymentGateConfig, wallet bool) (*Server, *countingProvider) {
	t.Helper()
	srv := testServer(t)
	prov := &countingProvider{}
	if wallet {
		cfg.NonceProvider = prov
		cfg.mintBudget = newMintBudget(1000, 60, time.Now)
	}
	cfg.Resolver = NewTopicMonetizationResolver(srv.envelopeStore)
	srv.paymentGate = NewPaymentGate(cfg)
	srv.mux = http.NewServeMux()
	srv.routes()
	for topic, mon := range map[string]*envelope.Monetization{
		"probe:priced": {Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 1},
		"probe:free":   nil,
	} {
		env := &envelope.Envelope{Type: "data", Topic: topic, Payload: `{"probe":true}`, Durable: true, Timestamp: time.Now().Unix(), Monetization: mon}
		env.Sign(mustKey(t))
		body, err := env.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/data", bytes.NewReader(body))
		req.Header.Set("X-Anvil-Auth", "test-token")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("publish %s: %d %s", topic, w.Code, w.Body.String())
		}
	}
	return srv, prov
}

// TestX402ChallengeIssuance records which unauthenticated requests issue a
// 402 challenge, each of which takes a nonce, under the default config and
// live-style configs.
func TestX402ChallengeIssuance(t *testing.T) {
	appModels := PaymentGateConfig{AllowPassthrough: true, AllowSplit: true, MaxAppPriceSats: 10000} // config.go defaults
	charging := appModels
	charging.PriceSats, charging.PayeeScriptHex = 5, testPayeeScript(t)
	freeStatusAndData := charging
	freeStatusAndData.EndpointPrices = map[string]int{"/status": 0, "/data": 0}
	pricedData := appModels
	pricedData.PayeeScriptHex, pricedData.EndpointPrices = testPayeeScript(t), map[string]int{"/data": 3}

	type row struct {
		method, target string
		challenged     bool
	}
	for _, tc := range []struct {
		name   string
		cfg    PaymentGateConfig
		wallet bool
		rows   []row
	}{
		// probe:priced's app passthrough price applies only on its own
		// content route, GET /data (isAppContentRoute, content_route.go).
		// /status and /headers/tip are node routes that don't serve
		// probe:priced's content at all; /content/abc is always-free
		// infrastructure (priceForPath); POST /data is a write. Before this
		// rule (cold review BL2(a), RISK 3), a topic's own app price
		// replaced the node's toll — free, here — on every one of these
		// just because ?topic= named it, challenging routes whose response
		// has nothing to do with that topic, and letting a topic's own
		// price (or a token credential) waive what should be the node's
		// unconditional toll on a write.
		{"default config: free node with a wallet", appModels, true, []row{
			{"GET", "/data", false},
			{"GET", "/data?topic=probe:free", false},
			{"GET", "/data?topic=probe:priced", true},
			{"GET", "/status?topic=probe:priced", false},
			{"GET", "/headers/tip?topic=probe:priced", false},
			{"GET", "/content/abc?topic=probe:priced", false},
			{"POST", "/data?topic=probe:priced", false},
			{"POST", "/broadcast?topic=probe:priced", false},
			{"GET", "/.well-known/x402?topic=probe:priced", false},
			{"GET", "/getPresentHeight?topic=probe:priced", false},
		}},
		{"charging node, payment_satoshis = 5", charging, true, []row{
			{"GET", "/status", true},
			{"GET", "/data", true},
			{"GET", "/headers/tip", true},
			{"POST", "/broadcast", true},
			{"GET", "/content/abc", false},
			{"GET", "/.well-known/x402", false},
			{"GET", "/getPresentHeight", false},
		}},
		{"charging node, /status and /data priced 0", freeStatusAndData, true, []row{
			{"GET", "/status", false},
			{"GET", "/data", false},
			{"GET", "/data?topic=probe:priced", true},
			{"GET", "/headers/tip", true},
		}},
		{"free node, endpoint_prices /data = 3", pricedData, true, []row{
			{"GET", "/data", true},
			{"GET", "/status", false},
			{"POST", "/broadcast", false},
		}},
		{"no identity.wif or wallet", appModels, false, []row{
			{"GET", "/data?topic=probe:priced", false},
			{"GET", "/status", false},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, prov := issuanceServer(t, tc.cfg, tc.wallet)
			for _, r := range tc.rows {
				before := prov.mints.Load()
				req := httptest.NewRequest(r.method, r.target, strings.NewReader("{}"))
				req.Host = "localhost"
				w := httptest.NewRecorder()
				srv.Handler().ServeHTTP(w, req)
				minted := prov.mints.Load() - before
				if got := w.Code == http.StatusPaymentRequired; got != r.challenged || minted != map[bool]int64{true: 1}[r.challenged] {
					t.Errorf("%s %s: status %d, %d nonces minted; want challenged %v", r.method, r.target, w.Code, minted, r.challenged)
				}
			}
		})
	}
}

// pendingGate is a charging gate whose nonces are counted and whose cap on
// pending challenges is limit.
func pendingGate(t *testing.T, limit int) (*PaymentGate, *countingProvider) {
	t.Helper()
	prov := &countingProvider{}
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 5, PayeeScriptHex: testPayeeScript(t), NonceProvider: prov,
		mintBudget: newMintBudget(1000, 60, time.Now)})
	pg.maxPending = limit
	return pg, prov
}

// A full pendingChallenges answers 503 with Retry-After before a nonce is
// taken, and expired challenges are dropped to make room.
func TestPaymentGate_PendingCapRefusesBeforeMinting(t *testing.T) {
	pg, prov := pendingGate(t, 3)
	for i := 0; i < 3; i++ {
		gateChallenge(t, pg, "/status?n="+strconv.Itoa(i))
	}
	w := serveGate(pg, http.MethodGet, "/status?n=3", "", "")
	retry, _ := strconv.Atoi(w.Header().Get("Retry-After"))
	if w.Code != http.StatusServiceUnavailable || retry < 1 || retry > 61 {
		t.Fatalf("challenge past the cap: got %d Retry-After %q, want 503 within the 60s TTL", w.Code, w.Header().Get("Retry-After"))
	}
	if n := prov.mints.Load(); n != 3 {
		t.Fatalf("%d nonces minted, want 3: a refused challenge must not take one", n)
	}

	pg.mu.Lock()
	for _, p := range pg.pendingChallenges {
		p.challenge.ExpiresAt = time.Now().Add(-10 * time.Second).Unix()
	}
	pg.mu.Unlock()
	gateChallenge(t, pg, "/status?n=4")
	pg.mu.Lock()
	pending, reserved := len(pg.pendingChallenges), pg.reservedPending
	pg.mu.Unlock()
	if pending != 1 || reserved != 0 || prov.mints.Load() != 4 {
		t.Fatalf("after the sweep: %d pending, %d reserved, %d minted; want 1, 0, 4", pending, reserved, prov.mints.Load())
	}
}

// The cap holds for concurrent challenges, and every place given out is
// given back.
func TestPaymentGate_PendingCapHoldsUnderConcurrency(t *testing.T) {
	const limit, callers = 16, 200
	pg, prov := pendingGate(t, limit)
	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := serveGate(pg, http.MethodGet, "/status?n="+strconv.Itoa(i), "", "")
			mu.Lock()
			codes[w.Code]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	pg.mu.Lock()
	pending, reserved := len(pg.pendingChallenges), pg.reservedPending
	pg.mu.Unlock()
	if codes[http.StatusPaymentRequired] != limit || codes[http.StatusServiceUnavailable] != callers-limit ||
		pending != limit || reserved != 0 || prov.mints.Load() != limit {
		t.Fatalf("codes %v, %d pending, %d reserved, %d minted; want %d challenges, %d 503s, %d pending, 0 reserved",
			codes, pending, reserved, prov.mints.Load(), limit, callers-limit, limit)
	}
}

// A filled place counts once against the cap, from the moment it is filled
// to after its release.
func TestPendingPlace_FillCountsOnce(t *testing.T) {
	pg, _ := pendingGate(t, 2)
	counted := func() int {
		pg.mu.Lock()
		defer pg.mu.Unlock()
		return len(pg.pendingChallenges) + pg.reservedPending
	}
	place, _, ok := pg.reservePending()
	if !ok {
		t.Fatal("an empty map refused a place")
	}
	place.fill("challenge", &pendingChallenge{challenge: &X402Challenge{ExpiresAt: time.Now().Add(time.Minute).Unix()}})
	if n := counted(); n != 1 {
		t.Fatalf("a filled place counts %d times against the cap before its release, want 1", n)
	}
	place.release()
	place.release()
	if n := counted(); n != 1 {
		t.Fatalf("a filled place counts %d times against the cap after its release, want 1", n)
	}
	unused, _, ok := pg.reservePending()
	if !ok {
		t.Fatal("a cap of 2 with one challenge pending refused a place")
	}
	unused.release()
	if n := counted(); n != 1 {
		t.Fatalf("a place given back unfilled still counts: %d, want 1", n)
	}
}

// A challenge that would keep more than maxChallengeFootprint bytes is
// refused before it takes a nonce, whether the size is in the request or in
// a topic's payee script.
func TestPaymentGate_OversizedChallengeMintsNothing(t *testing.T) {
	pg, prov := pendingGate(t, maxPendingChallenges)
	long := strings.Repeat("a", maxChallengeFootprint)
	if w := serveGate(pg, http.MethodGet, "/status?q="+long, "", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("long query: got %d, want 400", w.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Host = long
	w := httptest.NewRecorder()
	pg.Middleware(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("long Host: got %d, want 400", w.Code)
	}
	w = httptest.NewRecorder()
	pg.issueChallengeForPayees(w, httptest.NewRequest(http.MethodGet, "/data?topic=x", nil),
		[]Payee{{Role: "content", LockingScriptHex: strings.Repeat("6a", maxChallengeFootprint/2), AmountSats: 1}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("long payee script: got %d, want 400", w.Code)
	}
	if n := prov.mints.Load(); n != 0 {
		t.Fatalf("oversized challenges minted %d nonces", n)
	}
	gateChallenge(t, pg, "/status?q=ordinary")
}
