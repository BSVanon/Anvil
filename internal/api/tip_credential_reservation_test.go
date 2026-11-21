package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
)

type delayedTipCredential struct {
	TipCredential
	delayFor string
	delay    time.Duration
}

func (d *delayedTipCredential) VerifyTipUpdate(ctx context.Context, n *beefnorm.BEEF, origin, tip string) (func(bool) bool, error) {
	complete, err := d.TipCredential.VerifyTipUpdate(ctx, n, origin, tip)
	if err == nil && n != nil && n.Subject != nil && n.Subject.String() == d.delayFor {
		time.Sleep(d.delay)
	}
	return complete, err
}

func TestConcurrentTipSpendsAuthorizeOnlyTheReservedTransaction(t *testing.T) {
	f := newTipFixture(t, "test-token", 100)
	fundA, fundB := f.fund(10_000), f.fund(10_000)
	racerA := f.w.Spend(t, []ordtracktest.In{{Tx: f.origin, Vout: 0}, {Tx: fundA}}, f.inscribed("racer-a"), ordtracktest.Out{Sats: 9_999})
	racerB := f.w.Spend(t, []ordtracktest.In{{Tx: f.origin, Vout: 0}, {Tx: fundB}}, f.inscribed("racer-b"), ordtracktest.Out{Sats: 9_999})
	f.store.Add(racerA, racerB)
	f.srv.SetTipCredential(&delayedTipCredential{
		TipCredential: f.cred, delayFor: racerA.TxID().String(), delay: 150 * time.Millisecond,
	}, f.tr.Stats)

	beefA, beefB := ordtracktest.AtomicBEEF(t, racerA), ordtracktest.AtomicBEEF(t, racerB)
	hdrA := map[string]string{"X-Forwarded-For": "203.0.113.1"}
	hdrB := map[string]string{"X-Forwarded-For": "203.0.113.2"}
	var wg sync.WaitGroup
	var recA, recB *httptest.ResponseRecorder
	wg.Add(2)
	go func() {
		defer wg.Done()
		recA = post(f.srv, beefA, hdrA)
	}()
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond)
		recB = post(f.srv, beefB, hdrB)
	}()
	wg.Wait()

	if recA.Code != http.StatusOK {
		t.Fatalf("reserved spend: %d %s", recA.Code, recA.Body.String())
	}
	sameReply(t, "concurrent spend", recB, post(f.plain, beefB, hdrB))
	if !f.srv.broadcaster.Mempool().Has(racerA.TxID().String()) || f.srv.broadcaster.Mempool().Has(racerB.TxID().String()) {
		t.Fatalf("mempool has reserved=%v concurrent=%v", f.srv.broadcaster.Mempool().Has(racerA.TxID().String()), f.srv.broadcaster.Mempool().Has(racerB.TxID().String()))
	}
	if f.tip() != op(racerA, 0) {
		t.Fatalf("tip %s, want %s", f.tip(), op(racerA, 0))
	}
}
