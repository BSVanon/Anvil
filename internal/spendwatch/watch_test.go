package spendwatch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

const (
	txA = "aa00000000000000000000000000000000000000000000000000000000000000"
	txB = "bb00000000000000000000000000000000000000000000000000000000000000"
	txC = "cc00000000000000000000000000000000000000000000000000000000000000"
)

// fakeWoC records request times and answers each with reply(path).
type fakeWoC struct {
	mu    sync.Mutex
	times []time.Time
	paths []string
	reply func(path string, n int) (int, string, http.Header)
	srv   *httptest.Server
}

func newFakeWoC(t *testing.T, reply func(path string, n int) (int, string, http.Header)) *fakeWoC {
	f := &fakeWoC{reply: reply}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.times = append(f.times, time.Now())
		f.paths = append(f.paths, r.URL.Path)
		n := len(f.times)
		f.mu.Unlock()
		code, body, hdr := f.reply(r.URL.Path, n)
		for k, v := range hdr {
			w.Header()[k] = v
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeWoC) requests() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.times...)
}

func unspentReply(string, int) (int, string, http.Header) {
	return http.StatusNotFound, "Not Found", nil
}

func spendingTx(t *testing.T, prevTxid string, vout uint32) *transaction.Transaction {
	t.Helper()
	h, err := chainhash.NewHashFromHex(prevTxid)
	if err != nil {
		t.Fatal(err)
	}
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{SourceTXID: h, SourceTxOutIndex: vout, SequenceNumber: 0xffffffff})
	return tx
}

type spendLog struct {
	mu   sync.Mutex
	hits []string
}

func (l *spendLog) add(outpoint, txid string) {
	l.mu.Lock()
	l.hits = append(l.hits, outpoint+">"+txid)
	l.mu.Unlock()
}

func (l *spendLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.hits...)
}

func TestObserveAndHintReachOnlyWatchingOwners(t *testing.T) {
	w := New(Config{})
	var a, b spendLog
	w.OnSpent("a", a.add)
	w.OnSpent("b", b.add)
	if err := w.Watch(txA+"_1", "a"); err != nil {
		t.Fatal(err)
	}

	tx := spendingTx(t, txA, 1)
	w.Observe(tx)
	w.Observe(spendingTx(t, txA, 0)) // another output of the same tx: not watched
	w.Hint(txA+".1", strings.ToUpper(txC))
	w.Hint(txB+"_0", txC) // not watched

	want := []string{txA + "_1>" + tx.TxID().String(), txA + "_1>" + txC}
	if got := a.all(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("owner a got %v, want %v", got, want)
	}
	if got := b.all(); len(got) != 0 {
		t.Fatalf("owner b watches nothing, got %v", got)
	}

	w.Unwatch(txA+"_1", "a")
	w.Observe(tx)
	if got := a.all(); len(got) != 2 {
		t.Fatalf("an unwatched outpoint still dispatched: %v", got)
	}
}

func TestWatchCap(t *testing.T) {
	w := New(Config{MaxWatched: 2})
	if err := w.Watch(txA+"_0", "a"); err != nil {
		t.Fatal(err)
	}
	if err := w.Watch(txA+"_0", "b"); err != nil {
		t.Fatalf("a second owner of a watched outpoint must not count: %v", err)
	}
	if err := w.Watch(txB+"_0", "a"); err != nil {
		t.Fatal(err)
	}
	if err := w.Watch(txC+"_0", "a"); err != ErrFull {
		t.Fatalf("third outpoint: got %v, want ErrFull", err)
	}
	if err := w.Watch("nothex_0", "a"); err == nil {
		t.Fatal("an invalid outpoint must be refused")
	}
}

func TestCheckCachesAnswers(t *testing.T) {
	f := newFakeWoC(t, func(path string, n int) (int, string, http.Header) {
		switch {
		case strings.Contains(path, txA):
			return http.StatusNotFound, "Not Found", nil
		case strings.Contains(path, txB):
			return http.StatusOK, `{"txid":"` + txC + `","vin":0,"status":"confirmed"}`, nil
		default:
			return http.StatusOK, `{"txid":"` + txC + `","vin":0,"status":"unconfirmed"}`, nil
		}
	})
	w := New(Config{WoCBase: f.srv.URL, RequestGap: time.Millisecond})
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if spent, _, err := w.Check(ctx, txA+"_0"); err != nil || spent {
			t.Fatalf("unspent: got %v %v", spent, err)
		}
		if spent, by, err := w.Check(ctx, txB+"_0"); err != nil || !spent || by != txC {
			t.Fatalf("spent: got %v %q %v", spent, by, err)
		}
	}
	if n := len(f.requests()); n != 2 {
		t.Fatalf("cached answers must not be looked up again: %d requests", n)
	}
	f.mu.Lock()
	first := f.paths[0]
	f.mu.Unlock()
	if first != "/tx/"+txA+"/0/spent" {
		t.Fatalf("request path %q", first)
	}

	// An unspent answer and an unconfirmed spend expire; a confirmed spend
	// does not.
	w.mu.Lock()
	if !w.cache[txB+"_0"].expires.IsZero() {
		t.Error("a confirmed spend must be cached for good")
	}
	c := w.cache[txA+"_0"]
	if c.expires.IsZero() || c.expires.After(time.Now().Add(unspentTTL)) {
		t.Errorf("unspent answer expiry %v, want within %v", c.expires, unspentTTL)
	}
	c.expires = time.Now().Add(-time.Second)
	w.cache[txA+"_0"] = c
	w.mu.Unlock()
	if _, _, err := w.Check(ctx, txA+"_0"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.Check(ctx, txC+"_0"); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	unconfirmed := w.cache[txC+"_0"].expires
	w.mu.Unlock()
	if unconfirmed.IsZero() {
		t.Error("a spend not yet confirmed must expire like an unspent answer")
	}
	if n := len(f.requests()); n != 4 {
		t.Fatalf("an expired answer must be looked up again: %d requests", n)
	}
}

func runWatcher(t *testing.T, w *Watcher) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func TestPollRateCapHolds(t *testing.T) {
	f := newFakeWoC(t, unspentReply)
	gap := 40 * time.Millisecond
	w := New(Config{WoCBase: f.srv.URL, RequestGap: gap, PollInterval: time.Millisecond})
	for i := 0; i < 30; i++ {
		txid := strings.Repeat("0", 62) + string("0123456789abcdef"[i%16]) + string("0123456789abcdef"[i/16])
		if err := w.Watch(txid+"_0", "a"); err != nil {
			t.Fatal(err)
		}
	}
	runWatcher(t, w)
	time.Sleep(10 * gap)

	times := f.requests()
	if len(times) < 3 {
		t.Fatalf("only %d polls ran", len(times))
	}
	if len(times) > 11 {
		t.Fatalf("%d polls in %v breaks a %v gap", len(times), 10*gap, gap)
	}
	for i := 1; i < len(times); i++ {
		if d := times[i].Sub(times[i-1]); d < gap-5*time.Millisecond {
			t.Fatalf("polls %d and %d only %v apart, want at least %v", i-1, i, d, gap)
		}
	}
	if polls, _ := w.Stats(); polls < int64(len(times))-1 {
		t.Fatalf("Stats counted %d polls for %d requests", polls, len(times))
	}
}

func TestPoll429BacksOff(t *testing.T) {
	var limited atomic.Bool
	f := newFakeWoC(t, func(path string, n int) (int, string, http.Header) {
		if n == 1 {
			limited.Store(true)
			return http.StatusTooManyRequests, "slow down", nil
		}
		return http.StatusNotFound, "Not Found", nil
	})
	backoff := 250 * time.Millisecond
	w := New(Config{WoCBase: f.srv.URL, RequestGap: 5 * time.Millisecond, BackoffBase: backoff, PollInterval: time.Millisecond})
	if err := w.Watch(txA+"_0", "a"); err != nil {
		t.Fatal(err)
	}
	if err := w.Watch(txB+"_0", "a"); err != nil {
		t.Fatal(err)
	}
	runWatcher(t, w)
	deadline := time.Now().Add(2 * time.Second)
	for len(f.requests()) < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	times := f.requests()
	if len(times) < 3 {
		t.Fatalf("polling did not resume after a 429: %d requests", len(times))
	}
	if d := times[1].Sub(times[0]); d < backoff-10*time.Millisecond {
		t.Fatalf("next request %v after a 429, want at least %v", d, backoff)
	}
	if d := times[2].Sub(times[1]); d >= backoff {
		t.Fatalf("a success must reset the backoff: next gap %v", d)
	}
	if _, errs := w.Stats(); errs < 1 {
		t.Fatal("a 429 must count as a poll error")
	}
	if retryAfter("7") != 7*time.Second || retryAfter("soon") != 0 {
		t.Fatal("Retry-After seconds misread")
	}
}

func TestUnwatchStopsPolls(t *testing.T) {
	f := newFakeWoC(t, unspentReply)
	w := New(Config{WoCBase: f.srv.URL, RequestGap: time.Millisecond, PollInterval: 20 * time.Millisecond})
	var spends spendLog
	w.OnSpent("a", spends.add)
	if err := w.Watch(txA+"_0", "a"); err != nil {
		t.Fatal(err)
	}
	runWatcher(t, w)
	deadline := time.Now().Add(2 * time.Second)
	for len(f.requests()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(f.requests()) < 2 {
		t.Fatal("watched outpoint was not polled")
	}
	w.Unwatch(txA+"_0", "a")
	time.Sleep(30 * time.Millisecond) // let an in-flight poll finish
	before := len(f.requests())
	time.Sleep(150 * time.Millisecond)
	if after := len(f.requests()); after != before {
		t.Fatalf("polls continued after Unwatch: %d then %d", before, after)
	}
}

func TestPollReportsSpend(t *testing.T) {
	f := newFakeWoC(t, func(string, int) (int, string, http.Header) {
		return http.StatusOK, `{"txid":"` + txC + `","vin":2,"status":"confirmed"}`, nil
	})
	w := New(Config{WoCBase: f.srv.URL, RequestGap: time.Millisecond, PollInterval: 10 * time.Millisecond})
	var spends spendLog
	w.OnSpent("a", spends.add)
	if err := w.Watch(txA+"_3", "a"); err != nil {
		t.Fatal(err)
	}
	runWatcher(t, w)
	deadline := time.Now().Add(2 * time.Second)
	for len(spends.all()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := spends.all(); len(got) == 0 || got[0] != txA+"_3>"+txC {
		t.Fatalf("poll spend not reported: %v", got)
	}
}
