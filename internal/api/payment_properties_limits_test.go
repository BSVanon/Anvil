package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
)

// All unauthenticated payment work has a hard admission limit. This test
// fills each limit concurrently, then exercises success, refusal, ambiguity,
// cancellation and timeout exits and proves the admission is returned.
func TestPaymentPropertyConcurrencyLimitsReleaseOnEveryExit(t *testing.T) {
	t.Run("proof attempts", func(t *testing.T) {
		pg := testGate(t, 1)
		pending := &pendingChallenge{challenge: &X402Challenge{ExpiresAt: time.Now().Add(time.Minute).Unix()}}
		pg.pendingChallenges["proof"] = pending
		const callers = 32
		start, release := make(chan struct{}), make(chan struct{})
		var attempted, done sync.WaitGroup
		var admitted atomic.Int32
		attempted.Add(callers)
		done.Add(callers)
		for i := 0; i < callers; i++ {
			go func() {
				defer done.Done()
				<-start
				err := pg.reserveProofAttempt("proof", pending)
				if err == nil {
					admitted.Add(1)
				}
				attempted.Done()
				if err == nil {
					<-release
					pg.endProofAttempt("proof", pending, false, true)
				}
			}()
		}
		close(start)
		attempted.Wait()
		if admitted.Load() != maxProofAttempts {
			t.Fatalf("admitted %d proofs, want %d", admitted.Load(), maxProofAttempts)
		}
		close(release)
		done.Wait()
		if pending.attempts != 0 {
			t.Fatalf("ambiguous exits retained %d attempts", pending.attempts)
		}

		for i := 0; i < maxProofAttempts; i++ {
			if err := pg.reserveProofAttempt("proof", pending); err != nil {
				t.Fatalf("attempt %d after release: %v", i, err)
			}
		}
		if err := pg.reserveProofAttempt("proof", pending); err == nil {
			t.Fatal("proof cap admitted one extra attempt")
		}
		pg.endProofAttempt("proof", pending, true, false)
		if _, ok := pg.pendingChallenges["proof"]; ok {
			t.Fatal("successful proof retained its challenge")
		}

		terminal := &pendingChallenge{challenge: pending.challenge, attempts: maxProofAttempts - 1}
		pg.pendingChallenges["terminal"] = terminal
		if err := pg.reserveProofAttempt("terminal", terminal); err != nil {
			t.Fatal(err)
		}
		pg.endProofAttempt("terminal", terminal, false, false)
		if _, ok := pg.pendingChallenges["terminal"]; ok {
			t.Fatal("last failed proof retained its challenge")
		}
	})

	t.Run("direct submit slots", func(t *testing.T) {
		old := directPaymentSubmitSlots
		directPaymentSubmitSlots = make(chan struct{}, 2)
		t.Cleanup(func() { directPaymentSubmitSlots = old })
		entered, unblock := make(chan struct{}, 2), make(chan struct{})
		var fail atomic.Bool
		arc := usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
			if fail.Load() {
				return nil, errors.New("ARC reply lost")
			}
			entered <- struct{}{}
			<-unblock
			return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
		})
		pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{}, ARCClient: arc})
		payees := []Payee{{Role: "infrastructure", LockingScriptHex: testPayeeScript(t), AmountSats: 100}}
		const callers = 10
		payments := make([]string, callers)
		for i := range payments {
			payments[i] = signedEFPaying(t, paidOut{testPayeeScript(t), uint64(100 + i)})
		}
		results := make(chan error, callers)
		for _, payment := range payments {
			go func() {
				_, err := pg.verifyDirectPayment(context.Background(), payment, payees)
				results <- err
			}()
		}
		<-entered
		<-entered
		if len(directPaymentSubmitSlots) != 2 {
			t.Fatalf("held %d direct slots, want 2", len(directPaymentSubmitSlots))
		}
		busy := 0
		for i := 0; i < callers-2; i++ {
			err := <-results
			if errors.Is(err, errDirectPaymentSubmitsBusy) {
				busy++
			} else {
				t.Fatalf("direct submit: %v", err)
			}
		}
		close(unblock)
		accepted := 0
		for i := 0; i < 2; i++ {
			if err := <-results; err != nil {
				t.Fatalf("admitted direct submit: %v", err)
			}
			accepted++
		}
		if accepted != 2 || busy != callers-2 || len(directPaymentSubmitSlots) != 0 {
			t.Fatalf("accepted %d, busy %d, slots held %d", accepted, busy, len(directPaymentSubmitSlots))
		}

		if _, err := pg.verifyDirectPayment(context.Background(), "bad", payees); err == nil || len(directPaymentSubmitSlots) != 0 {
			t.Fatalf("malformed exit retained a slot: %v", err)
		}
		fail.Store(true)
		retry := signedEFPaying(t, paidOut{testPayeeScript(t), 100})
		if _, err := pg.verifyDirectPayment(context.Background(), retry, payees); err == nil || len(directPaymentSubmitSlots) != 0 {
			t.Fatalf("ARC failure retained a slot: %v", err)
		}
		fail.Store(false)
		if _, err := pg.verifyDirectPayment(context.Background(), retry, payees); err != nil || len(directPaymentSubmitSlots) != 0 {
			t.Fatalf("success retained a slot: %v", err)
		}
	})

	t.Run("payment body slots", func(t *testing.T) {
		oldShares, oldReads, oldLimits := paymentBodyShares, paymentBodyReads, paymentBodyLimits
		paymentBodyShares = newBodyShares(2)
		paymentBodyReads = bodyread.NewPermits(2)
		paymentBodyLimits.Max, paymentBodyLimits.Grace, paymentBodyLimits.Timeout = 8, 20*time.Millisecond, time.Second
		t.Cleanup(func() {
			paymentBodyShares, paymentBodyReads, paymentBodyLimits = oldShares, oldReads, oldLimits
		})
		pg := testGate(t, 1)
		writers := make([]*io.PipeWriter, 2)
		results := make(chan error, 2)
		for i := range writers {
			reader, writer := io.Pipe()
			writers[i] = writer
			req := httptest.NewRequest(http.MethodPost, "/data", reader)
			req.RemoteAddr = "192.0.2.1:1"
			go func() {
				_, err := pg.readPaymentBodyUntil(httptest.NewRecorder(), req, time.Now().Add(time.Second))
				results <- err
			}()
		}
		eventually(t, time.Second, func() bool {
			return paymentBodyShares.holding("192.0.2.1") == 2 && paymentBodyReads.InUse() == 2
		})
		same := httptest.NewRequest(http.MethodPost, "/data", strings.NewReader("x"))
		same.RemoteAddr = "192.0.2.1:2"
		if _, err := pg.readPaymentBodyUntil(httptest.NewRecorder(), same, time.Now().Add(time.Second)); !errors.Is(err, errPaymentBodyShare) {
			t.Fatalf("per-client body cap: %v", err)
		}
		wait, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		_, err := paymentBodyReads.Acquire(wait)
		cancel()
		if !errors.Is(err, bodyread.ErrNoPermit) {
			t.Fatalf("global body cap: %v", err)
		}
		for _, writer := range writers {
			_ = writer.Close()
		}
		for range writers {
			if err := <-results; err != nil {
				t.Fatalf("released body: %v", err)
			}
		}
		if paymentBodyShares.clients() != 0 || paymentBodyReads.InUse() != 0 {
			t.Fatal("completed body reads retained capacity")
		}

		for _, tc := range []struct {
			name string
			req  *http.Request
		}{
			{"success", httptest.NewRequest(http.MethodPost, "/data", strings.NewReader("ok"))},
			{"oversize", httptest.NewRequest(http.MethodPost, "/data", strings.NewReader("123456789"))},
		} {
			tc.req.RemoteAddr = "192.0.2.3:1"
			_, _ = pg.readPaymentBodyUntil(httptest.NewRecorder(), tc.req, time.Now().Add(time.Second))
			if paymentBodyShares.clients() != 0 || paymentBodyReads.InUse() != 0 {
				t.Fatalf("%s exit retained body capacity", tc.name)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		canceled := httptest.NewRequest(http.MethodPost, "/data", strings.NewReader("x")).WithContext(ctx)
		canceled.RemoteAddr = "192.0.2.4:1"
		_, _ = pg.readPaymentBodyUntil(httptest.NewRecorder(), canceled, time.Now().Add(time.Second))
		if paymentBodyShares.clients() != 0 || paymentBodyReads.InUse() != 0 {
			t.Fatal("canceled body retained capacity")
		}
	})

	t.Run("nonce mint slots", func(t *testing.T) {
		oldSlots, oldTimeout := nonceMintSlots, nonceMintTimeout
		nonceMintSlots = make(chan struct{}, 2)
		nonceMintTimeout = 30 * time.Millisecond
		t.Cleanup(func() { nonceMintSlots, nonceMintTimeout = oldSlots, oldTimeout })
		provider := &blockingMintProvider{started: make(chan struct{}, 8), release: make(chan struct{})}
		budgeted := &budgetedNonceProvider{inner: provider, budget: newMintBudget(8, 60, time.Now)}
		const callers = 8
		results := make(chan error, callers)
		for i := 0; i < callers; i++ {
			go func() {
				_, err := budgeted.MintNonce(context.Background())
				results <- err
			}()
		}
		<-provider.started
		<-provider.started
		busy := 0
		for i := 0; i < callers-2; i++ {
			err := <-results
			var capacity *mintCapacityError
			if !errors.As(err, &capacity) {
				t.Fatalf("mint: %v", err)
			}
			busy++
		}
		close(provider.release)
		accepted := 0
		for i := 0; i < 2; i++ {
			if err := <-results; err != nil {
				t.Fatalf("admitted mint: %v", err)
			}
			accepted++
		}
		provider.mu.Lock()
		peak := provider.peak
		provider.mu.Unlock()
		if accepted != 2 || busy != callers-2 || peak != 2 || len(nonceMintSlots) != 0 {
			t.Fatalf("accepted %d, busy %d, peak %d, held %d", accepted, busy, peak, len(nonceMintSlots))
		}

		failed := &budgetedNonceProvider{inner: &fakeOpaqueFailureNonceProvider{}, budget: newMintBudget(1, 60, time.Now)}
		if _, err := failed.MintNonce(context.Background()); err == nil || len(nonceMintSlots) != 0 {
			t.Fatalf("wallet failure retained a mint slot: %v", err)
		}
		timed := &blockingMintProvider{started: make(chan struct{}, 1), release: make(chan struct{})}
		if _, err := (&budgetedNonceProvider{inner: timed, budget: newMintBudget(1, 60, time.Now)}).MintNonce(context.Background()); err == nil || len(nonceMintSlots) != 0 {
			t.Fatalf("timeout retained a mint slot: %v", err)
		}
	})
}
