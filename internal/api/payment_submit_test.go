package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/txrelay"
)

// holdingARC is a slow mock ARC: it reports each submit it receives on
// arrived, and answers none until release is called, or until the submit's
// client goes away.
func holdingARC(t *testing.T) (arc *txrelay.ARCClient, arrived <-chan struct{}, release func()) {
	t.Helper()
	got := make(chan struct{}, 4*maxDirectPaymentSubmits)
	hold := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body) // read to its end, so the server sees the client go
		got <- struct{}{}
		select {
		case <-hold:
			_ = json.NewEncoder(w).Encode(txrelay.ARCResponse{TxID: "mock", Status: "SEEN_ON_NETWORK"})
		case <-r.Context().Done():
		}
	}))
	var once sync.Once
	release = func() { once.Do(func() { close(hold) }) }
	t.Cleanup(srv.Close)
	t.Cleanup(release) // runs first, so no handler is left holding the server open
	return txrelay.NewARCClient(srv.URL, ""), got, release
}

// TestDirectPaymentSubmitsAreCappedNodeWide: with maxDirectPaymentSubmits
// direct payments held at ARC, one more is answered 503 with
// ERR_DIRECT_PAYMENT_BUSY and a Retry-After, and never reaches ARC. Once the
// held submits end, the same refused transaction pays.
func TestDirectPaymentSubmitsAreCappedNodeWide(t *testing.T) {
	arc, arrived, release := holdingARC(t)
	srv := testServerWithPaymentGate(t, 100)
	srv.paymentGate.arcClient = arc
	payee := testPayeeScript(t)

	held := make(chan *httptest.ResponseRecorder, maxDirectPaymentSubmits)
	for i := 0; i < maxDirectPaymentSubmits; i++ {
		ef := signedEFPaying(t, paidOut{payee, 100})
		go func() { held <- serveDirectPayment(srv, "/stats", ef) }()
	}
	for i := 0; i < maxDirectPaymentSubmits; i++ {
		<-arrived
	}

	extraEF := signedEFPaying(t, paidOut{payee, 100})
	extra := make(chan *httptest.ResponseRecorder, 1)
	go func() { extra <- serveDirectPayment(srv, "/stats", extraEF) }()
	select {
	case <-arrived:
		t.Fatalf("a direct payment past the %d in flight reached ARC", maxDirectPaymentSubmits)
	case w := <-extra:
		var body codedError
		if w.Code != http.StatusServiceUnavailable || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Code != codeDirectPaymentBusy {
			t.Fatalf("past the cap: got %d %s, want 503 with code %s", w.Code, w.Body.String(), codeDirectPaymentBusy)
		}
		if got := w.Header().Get("Retry-After"); got != "1" {
			t.Fatalf("past the cap: Retry-After %q, want 1", got)
		}
	}

	release()
	for i := 0; i < maxDirectPaymentSubmits; i++ {
		if w := <-held; w.Code != http.StatusOK {
			t.Fatalf("a held direct payment: got %d %s, want 200", w.Code, w.Body.String())
		}
	}
	if w := serveDirectPayment(srv, "/stats", extraEF); w.Code != http.StatusOK {
		t.Fatalf("the refused transaction sent again: got %d %s, want 200", w.Code, w.Body.String())
	}
}

// TestDirectPaymentSubmitEndsAtItsBound: an ARC that never answers holds a
// direct payment only until directPaymentSubmitTimeout, whose stated value is
// at most 10 seconds.
func TestDirectPaymentSubmitEndsAtItsBound(t *testing.T) {
	if directPaymentSubmitTimeout > 10*time.Second {
		t.Fatalf("the direct-payment submit bound is %v, want at most 10s", directPaymentSubmitTimeout)
	}
	prev := directPaymentSubmitTimeout
	directPaymentSubmitTimeout = 100 * time.Millisecond
	t.Cleanup(func() { directPaymentSubmitTimeout = prev })

	arc, arrived, _ := holdingARC(t)
	payee := testPayeeScript(t)
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: payee, NonceProvider: &DevNonceProvider{}, ARCClient: arc})
	payees := []Payee{{Role: "infrastructure", LockingScriptHex: payee, AmountSats: 100}}
	ef := signedEFPaying(t, paidOut{payee, 100})

	done := make(chan error, 1)
	go func() {
		_, err := pg.verifyDirectPayment(context.Background(), ef, payees)
		done <- err
	}()
	<-arrived
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("an unanswered submit: got %v, want it ended by its deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an unanswered submit outlived its bound")
	}
}

// TestDirectPaymentSubmitEndsWithItsRequest: a direct payment's ARC submit
// carries the request's context, so it ends when the request does, well
// before its own bound.
func TestDirectPaymentSubmitEndsWithItsRequest(t *testing.T) {
	arc, arrived, _ := holdingARC(t)
	srv := testServerWithPaymentGate(t, 100)
	srv.paymentGate.arcClient = arc
	ef := signedEFPaying(t, paidOut{testPayeeScript(t), 100})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/stats", nil).WithContext(ctx)
	req.Host = "localhost"
	req.Header.Set(HeaderBSVPayment, ef)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(w, req)
		close(done)
	}()
	<-arrived
	cancel()
	select {
	case <-done:
		if w.Code == http.StatusOK || !strings.Contains(w.Body.String(), context.Canceled.Error()) {
			t.Fatalf("a request that ended during its submit: got %d %s, want a refusal for the ended request", w.Code, w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the submit outlived its request")
	}
}
