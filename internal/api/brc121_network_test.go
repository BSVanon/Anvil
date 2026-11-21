package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/spv"
)

// journaled is how many payments f's journal keeps.
func (f *brc121Fix) journaled() int {
	n, _ := f.pg.brc121.journal.stats(f.now)
	return n
}

// shortSubmits makes the ARC submit bound d for one test.
func shortSubmits(t *testing.T, d time.Duration) {
	t.Helper()
	old := directPaymentSubmitTimeout
	directPaymentSubmitTimeout = d
	t.Cleanup(func() { directPaymentSubmitTimeout = old })
}

// TestBRC121ARCRefusalNotJournaled: a payment ARC refuses outright, by
// status or by HTTP code, is answered 402 and is neither recorded nor kept.
func TestBRC121ARCRefusalNotJournaled(t *testing.T) {
	for _, a := range []struct {
		status string
		code   int
	}{{"REJECTED", 0}, {"", 465}, {"", 462}} {
		f := newBRC121Fix(t, 100)
		f.arc.answer(a.status, a.code)
		w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
		if w.Code != http.StatusPaymentRequired || codeOf(t, w) != codeBRC121NotAccepted {
			t.Fatalf("%+v: want 402 %s, got %d %s", a, codeBRC121NotAccepted, w.Code, w.Body.String())
		}
		if internalizes, _ := f.wallet.recorded(); internalizes != 0 || f.journaled() != 0 {
			t.Fatalf("%+v: a refused payment was recorded (%d) or kept (%d)", a, internalizes, f.journaled())
		}
	}
}

// TestBRC121ARCTimeoutJournaled: a payment ARC does not answer within the
// submit bound is answered 503 and kept in the journal, unrecorded.
func TestBRC121ARCTimeoutJournaled(t *testing.T) {
	shortSubmits(t, 100*time.Millisecond)
	f := newBRC121Fix(t, 100)
	hold := make(chan struct{})
	defer close(hold)
	f.arc.mu.Lock()
	f.arc.hold = hold
	f.arc.mu.Unlock()
	w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
	if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != codeBRC121PaymentKept {
		t.Fatalf("want 503 %s, got %d %s", codeBRC121PaymentKept, w.Code, w.Body.String())
	}
	assertNoBRC121Offer(t, w)
	if internalizes, _ := f.wallet.recorded(); internalizes != 0 || f.journaled() != 1 {
		t.Fatalf("want the payment kept unrecorded, got %d internalizes and %d kept", internalizes, f.journaled())
	}
}

// TestBRC121InternalizeErrorJournaled: a payment the network accepted but the
// wallet failed to record is answered 503 and kept.
func TestBRC121InternalizeErrorJournaled(t *testing.T) {
	f := newBRC121Fix(t, 100)
	f.wallet.internalizeErr = errors.New("storage unavailable")
	w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
	if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != codeBRC121PaymentKept || f.journaled() != 1 {
		t.Fatalf("want 503 %s and the payment kept, got %d %s and %d kept", codeBRC121PaymentKept, w.Code, w.Body.String(), f.journaled())
	}
	assertNoBRC121Offer(t, w)
}

// TestBRC121SubmitsBusy503: with every ARC submit slot taken, a payment is
// answered 503 with a Retry-After, and kept: its payer has broadcast it.
func TestBRC121SubmitsBusy503(t *testing.T) {
	f := newBRC121Fix(t, 100)
	for i := 0; i < maxDirectPaymentSubmits; i++ {
		directPaymentSubmitSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < maxDirectPaymentSubmits; i++ {
			<-directPaymentSubmitSlots
		}
	}()
	w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
	if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != codeBRC121PaymentKept || w.Header().Get("Retry-After") == "" {
		t.Fatalf("want 503 %s with Retry-After, got %d %s", codeBRC121PaymentKept, w.Code, w.Body.String())
	}
	assertNoBRC121Offer(t, w)
	if f.arc.calls.Load() != 0 || f.journaled() != 1 {
		t.Fatalf("want no ARC call and the payment kept, got %d calls and %d kept", f.arc.calls.Load(), f.journaled())
	}
}

// TestBRC121NotOfferedOrTakenWithoutWalletOrARC: a gate with no node wallet,
// or no ARC client, makes no offer and ignores the BRC-121 headers: the
// request gets the plain x402 challenge and nothing is recorded.
func TestBRC121NotOfferedOrTakenWithoutWalletOrARC(t *testing.T) {
	payer := newBRC121Payer()
	hs := brc121HeaderStore(t, payer.source)
	for _, noARC := range []bool{false, true} {
		wallet := newFakeBRC121Wallet()
		_, client := newBRC121Stub()
		cfg := PaymentGateConfig{PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{}, ARCClient: client}
		if noARC {
			cfg.ARCClient = nil
		}
		pg := NewPaymentGate(cfg)
		var bw brc121Wallet = wallet
		if !noARC {
			bw = nil
		}
		if err := pg.startBRC121(bw, spv.NewValidator(hs), t.TempDir(), slog.Default()); err != nil {
			t.Fatal(err)
		}
		if pg.brc121 != nil {
			t.Fatalf("no ARC %v: BRC-121 must be off", noARC)
		}
		f := &brc121Fix{pg: pg, wallet: wallet, payer: payer, now: time.Now()}
		w := f.serve(brc121Path, "10.0.0.1:1", payer.pay(t, wallet.root.PubKey(), 100, time.Now(), brc121Pay{}))
		if w.Code != http.StatusPaymentRequired || w.Header().Get(HeaderX402Challenge) == "" {
			t.Fatalf("no ARC %v: want the plain x402 challenge, got %d %s", noARC, w.Code, w.Body.String())
		}
		if w.Header().Get(headerBRC121Sats) != "" || w.Header().Get(headerBRC121Server) != "" {
			t.Fatalf("no ARC %v: BRC-121 was offered", noARC)
		}
		if internalizes, _ := wallet.recorded(); internalizes != 0 {
			t.Fatalf("no ARC %v: a payment was recorded", noARC)
		}
		reason, _ := pg.brc121Status()["reason"].(string)
		if want := map[bool]string{false: "no node wallet", true: "no ARC client"}[noARC]; reason != want {
			t.Fatalf("no ARC %v: status reason %q, want %q", noARC, reason, want)
		}
	}
}

// TestBRC121SamePaymentTwiceRefused: the same payment presented again is
// refused by the replay record, before ARC.
func TestBRC121SamePaymentTwiceRefused(t *testing.T) {
	f := newBRC121Fix(t, 100)
	h := f.payment(t, 100, brc121Pay{})
	if w := f.serve(brc121Path, "10.0.0.1:1", h); w.Code != http.StatusOK {
		t.Fatalf("first presentation: want 200, got %d %s", w.Code, w.Body.String())
	}
	w := f.serve(brc121Path, "10.0.0.1:1", h)
	if w.Code != http.StatusPaymentRequired || codeOf(t, w) != codeBRC121Replayed || f.arc.calls.Load() != 1 {
		t.Fatalf("second presentation: want 402 %s with no new ARC call, got %d %s (%d calls)", codeBRC121Replayed, w.Code, w.Body.String(), f.arc.calls.Load())
	}
}

// TestBRC121WalletRecordRefusesReplayAfterRestart: with a fresh replay record,
// as after a restart, the wallet's own record of the payment refuses it,
// before ARC and before the wallet would merge it.
func TestBRC121WalletRecordRefusesReplayAfterRestart(t *testing.T) {
	f := newBRC121Fix(t, 100)
	h := f.payment(t, 100, brc121Pay{})
	if w := f.serve(brc121Path, "10.0.0.1:1", h); w.Code != http.StatusOK {
		t.Fatalf("first presentation: want 200, got %d", w.Code)
	}
	f.pg.replays = newPaymentReplaySet(time.Hour, 16, time.Now)
	w := f.serve(brc121Path, "10.0.0.1:1", h)
	if w.Code != http.StatusPaymentRequired || codeOf(t, w) != codeBRC121Replayed {
		t.Fatalf("after a restart: want 402 %s, got %d %s", codeBRC121Replayed, w.Code, w.Body.String())
	}
	if f.arc.calls.Load() != 1 || f.wallet.merges != 0 {
		t.Fatalf("the replay reached ARC (%d calls) or the wallet (%d merges)", f.arc.calls.Load(), f.wallet.merges)
	}
}

// TestBRC121ConcurrentIdenticalPaymentsServedOnce: the same payment sent n
// times at once is served exactly once. ARC holds its answer until every
// other request has been refused, or until all n reach it, which only
// happens when nothing claims the transaction.
func TestBRC121ConcurrentIdenticalPaymentsServedOnce(t *testing.T) {
	const n = 8
	f := newBRC121Fix(t, 100)
	hold := make(chan struct{})
	f.arc.mu.Lock()
	f.arc.hold = hold
	f.arc.mu.Unlock()
	h := f.payment(t, 100, brc121Pay{})
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			codes <- f.serve(brc121Path, addr, h).Code
		}(fmt.Sprintf("10.0.1.%d:1", i))
	}
	var got []int
	for len(got) < n-1 && f.arc.calls.Load() < n {
		select {
		case c := <-codes:
			got = append(got, c)
		case <-time.After(5 * time.Millisecond):
		}
	}
	close(hold)
	wg.Wait()
	close(codes)
	for c := range codes {
		got = append(got, c)
	}
	served := 0
	for _, c := range got {
		if c == http.StatusOK {
			served++
		}
	}
	if served != 1 {
		t.Fatalf("want exactly one of %d identical payments served, got %d (codes %v)", n, served, got)
	}
}

// TestBRC121ClientShare: a fifth payment waits until one of the client's four
// validations finishes, then is served.
func TestBRC121ClientShare(t *testing.T) {
	f := newBRC121Fix(t, 100)
	f.wallet.blockSender = f.payer.identity.PubKey()
	f.wallet.started = make(chan struct{}, 2*brc121ClientShare)
	f.wallet.release = make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < brc121ClientShare; i++ {
		h := f.payment(t, 100, brc121Pay{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.serve(brc121Path, "10.0.0.1:1", h)
		}()
	}
	for i := 0; i < brc121ClientShare; i++ {
		<-f.wallet.started
	}
	fifth := make(chan *httptest.ResponseRecorder, 1)
	h5 := f.payment(t, 100, brc121Pay{})
	go func() { fifth <- f.serve(brc121Path, "10.0.0.1:1", h5) }()
	waitForBRC121Shares(t, f.pg.brc121.shares, rateLimitKey("10.0.0.1"), 4, 1)
	close(f.wallet.release)
	wg.Wait()
	if w := <-fifth; w.Code != http.StatusOK {
		t.Fatalf("fifth payment: want 200 after a share frees, got %d %s", w.Code, w.Body.String())
	}
}

// TestBRC121JournalSweepRecordsKeptPayment: a payment kept after an ARC
// timeout is recorded by the sweep, with the node's own wallet, once ARC
// accepts it: the output is then listed spendable and the entry is gone.
func TestBRC121JournalSweepRecordsKeptPayment(t *testing.T) {
	shortSubmits(t, 100*time.Millisecond)
	n := newRealBRC121Node(t)
	hold := make(chan struct{})
	n.arc.mu.Lock()
	n.arc.hold = hold
	n.arc.mu.Unlock()
	h := n.payer.pay(t, n.server, 100, time.Now(), brc121Pay{})
	if w := n.serve(h); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 on an ARC timeout, got %d %s", w.Code, w.Body.String())
	}
	p := &brc121Payment{}
	if err := p.readBRC121BEEF(h[headerBRC121Beef], 100); err != nil {
		t.Fatal(err)
	}
	if !n.pg.brc121.journal.has(p.txid.String()) || len(n.spendable(t, p.txid.String())) != 0 {
		t.Fatal("want the payment kept and not yet in the wallet")
	}
	n.arc.mu.Lock()
	n.arc.hold = nil
	n.arc.mu.Unlock()
	close(hold)
	n.pg.brc121.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	n.pg.sweepBRC121(context.Background())
	if n.pg.brc121.journal.has(p.txid.String()) {
		t.Fatal("the sweep left the recorded payment in the journal")
	}
	outs := n.spendable(t, p.txid.String())
	if len(outs) != 1 || !outs[0].Spendable || outs[0].Satoshis != 100 {
		t.Fatalf("want the swept payment listed spendable, got %+v", outs)
	}
	if n.pg.brc121.counts.claimed != 1 {
		t.Fatalf("want one claim counted, got %d", n.pg.brc121.counts.claimed)
	}
}

// TestBRC121SweepDropsRefusedPayment: a kept payment ARC then refuses
// outright is dropped by the sweep, unrecorded.
func TestBRC121SweepDropsRefusedPayment(t *testing.T) {
	f := newBRC121Fix(t, 100)
	f.wallet.internalizeErr = errors.New("storage unavailable")
	f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
	if f.journaled() != 1 {
		t.Fatal("want the payment kept")
	}
	f.wallet.internalizeErr = nil
	f.arc.answer("REJECTED", 0)
	f.now = f.now.Add(2 * time.Minute)
	f.pg.sweepBRC121(context.Background())
	if internalizes, held := f.wallet.recorded(); f.journaled() != 0 || held != 0 || internalizes != 1 {
		t.Fatalf("want the refused payment dropped unrecorded, got %d kept, %d held, %d internalizes", f.journaled(), held, internalizes)
	}
}

// TestBRC121SweepKeepsTransientAndExpires: an entry ARC still gives no
// answer for stays; one past brc121JournalTTL is dropped and counted.
func TestBRC121SweepKeepsTransientAndExpires(t *testing.T) {
	f := newBRC121Fix(t, 100)
	f.wallet.internalizeErr = errors.New("storage unavailable")
	f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
	f.arc.answer("", 503)
	f.now = f.now.Add(2 * time.Minute)
	f.pg.sweepBRC121(context.Background())
	if f.journaled() != 1 {
		t.Fatal("a transient ARC answer must keep the entry")
	}
	f.now = f.now.Add(brc121JournalTTL)
	f.pg.sweepBRC121(context.Background())
	if f.journaled() != 0 || f.pg.brc121.counts.dropped != 1 {
		t.Fatalf("want the expired entry dropped and counted, got %d kept, %d dropped", f.journaled(), f.pg.brc121.counts.dropped)
	}
}

// TestBRC121JournalSurvivesReopen: a kept payment is read back after the
// journal is closed and opened again.
func TestBRC121JournalSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	j, err := openBRC121Journal(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := &brc121Entry{TxID: "ab", Vout: 1, Nonce: "AAECAwQFBgc=", Time: "1", Sender: "02aa", Satoshis: 100, BEEF: []byte{1, 2}, Kept: 7}
	if _, err := j.add(e); err != nil {
		t.Fatal(err)
	}
	_ = j.close()
	j, err = openBRC121Journal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	got, err := j.get("ab")
	if err != nil || !j.has("ab") || got.Satoshis != 100 || got.Nonce != e.Nonce || got.Kept != 7 {
		t.Fatalf("want the entry back after reopening, got %+v (%v)", got, err)
	}
}

// TestBRC121JournalCap: with maxBRC121JournalEntries kept, the next payment
// is not kept, and is counted.
func TestBRC121JournalCap(t *testing.T) {
	f := newBRC121Fix(t, 100)
	j := f.pg.brc121.journal
	for i := 0; i < maxBRC121JournalEntries; i++ {
		j.kept[string(rune(0x10000+i))] = f.now.Unix()
	}
	f.wallet.internalizeErr = errors.New("storage unavailable")
	w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
	if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != codeBRC121PaymentUnrecorded {
		t.Fatalf("want 503 %s, got %d %s", codeBRC121PaymentUnrecorded, w.Code, w.Body.String())
	}
	assertNoBRC121Offer(t, w)
	if f.journaled() != maxBRC121JournalEntries || f.pg.brc121.counts.full != 1 {
		t.Fatalf("want entry %d refused and counted, got %d kept, %d refused", maxBRC121JournalEntries+1, f.journaled(), f.pg.brc121.counts.full)
	}
}
