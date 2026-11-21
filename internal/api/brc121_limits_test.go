package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/libsv/go-p2p/wire"
)

func waitForBRC121Shares(t *testing.T, shares *brc121Shares, key string, held, waiting int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h, w := shares.counts(key); h == held && w == waiting {
			return
		}
		runtime.Gosched()
	}
	h, w := shares.counts(key)
	t.Fatalf("shares are %d held and %d waiting, want %d and %d", h, w, held, waiting)
}

func TestBRC121ThirtySeventhPaymentRefusedWithoutOffer(t *testing.T) {
	shares := newBRC121Shares()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key := "hashed-by-rate-limiter"
	var release []func()
	for i := 0; i < brc121ClientShare; i++ {
		leave, ok := shares.take(ctx, key)
		if !ok {
			t.Fatal("could not take an initial share")
		}
		release = append(release, leave)
	}
	done := make(chan bool, brc121ClientWait)
	for i := 0; i < brc121ClientWait; i++ {
		go func() {
			leave, ok := shares.take(ctx, key)
			if leave != nil {
				leave()
			}
			done <- ok
		}()
	}
	waitForBRC121Shares(t, shares, key, brc121ClientShare, brc121ClientWait)
	if leave, ok := shares.take(ctx, key); ok || leave != nil {
		t.Fatal("the thirty-seventh payment entered the wait queue")
	}
	cancel()
	for _, leave := range release {
		leave()
	}
	for i := 0; i < brc121ClientWait; i++ {
		<-done
	}

	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{}})
	pg.brc121 = &brc121Gate{server: "server", now: time.Now, shares: newBRC121Shares()}
	req := httptest.NewRequest(http.MethodGet, brc121Path, nil)
	req.RemoteAddr = "10.0.0.1:1"
	req.Header.Set(headerBRC121Beef, "present")
	req.Header.Set(headerBRC121Time, strconv.FormatInt(time.Now().UnixMilli(), 10))
	client := pg.clientKeyFor(req)
	pg.brc121.shares.clients[client] = &brc121ShareState{held: brc121ClientShare, waiting: brc121ClientWait, changed: make(chan struct{})}
	w := httptest.NewRecorder()
	pg.Middleware(func(http.ResponseWriter, *http.Request) {})(w, req)
	if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != codeBRC121Busy {
		t.Fatalf("want the thirty-seventh request refused 503, got %d %s", w.Code, w.Body.String())
	}
	assertNoBRC121Offer(t, w)
}

type failedBRC121Nonce struct{}

func (failedBRC121Nonce) MintNonce() (*NonceUTXO, error) { return nil, errors.New("mint failed") }

func TestBRC121OfferOnlyAfterChallengeSucceeds(t *testing.T) {
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: failedBRC121Nonce{}})
	pg.brc121 = &brc121Gate{server: "server"}
	req := httptest.NewRequest(http.MethodGet, brc121Path, nil)
	w := httptest.NewRecorder()
	pg.Middleware(func(http.ResponseWriter, *http.Request) {})(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want mint failure 500, got %d", w.Code)
	}
	assertNoBRC121Offer(t, w)
	if pg.brc121.counts.offered != 0 {
		t.Fatalf("counted %d offers without a 402", pg.brc121.counts.offered)
	}
}

func TestBRC121StaleHeadersSuppressOffer(t *testing.T) {
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{},
		HeadersFresh: func(time.Time) bool { return false }})
	pg.brc121 = &brc121Gate{server: "server"}
	req := httptest.NewRequest(http.MethodGet, brc121Path, nil)
	w := httptest.NewRecorder()
	pg.Middleware(func(http.ResponseWriter, *http.Request) {})(w, req)
	if w.Code != http.StatusPaymentRequired || w.Header().Get(HeaderX402Challenge) == "" {
		t.Fatalf("want the ordinary 402 challenge, got %d", w.Code)
	}
	assertNoBRC121Offer(t, w)
}

func TestBRC121DisabledModelFallbackNotOffered(t *testing.T) {
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{}})
	pg.brc121 = &brc121Gate{server: "server"}
	req := httptest.NewRequest(http.MethodGet, brc121Path, nil)
	payees := []Payee{*pg.nodePayee(req.URL.Path)}
	if got := pg.brc121Offer(req, payees, false, true); got != 0 {
		t.Fatalf("disabled-model fallback offered %d sats", got)
	}
	if got := pg.brc121Offer(req, payees, false, false); got != 100 {
		t.Fatalf("ordinary node challenge offered %d sats, want 100", got)
	}
}

func TestServerBRC121OfferUsesHeaderStalenessRule(t *testing.T) {
	payer := newBRC121Payer()
	hs := brc121HeaderStore(t, payer.source)
	pg := newServerPaymentGate(ServerConfig{HeaderStore: hs, HeaderStaleAfterSecs: 1800,
		PaymentSatoshis: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{}}, nil)
	if pg.headersFresh == nil {
		t.Fatal("server payment gate has no header freshness check")
	}
	raw, err := hs.HeaderAtHeight(hs.Tip())
	if err != nil {
		t.Fatal(err)
	}
	var h wire.BlockHeader
	if err := h.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if !pg.headersFresh(h.Timestamp.Add(1800*time.Second)) || pg.headersFresh(h.Timestamp.Add(1801*time.Second)) {
		t.Fatal("header staleness boundary is not the configured 1800 seconds")
	}
}
