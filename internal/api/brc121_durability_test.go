package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/spv"
)

func TestBRC121WalletReadFailureKeptWithoutOffer(t *testing.T) {
	f := newBRC121Fix(t, 100)
	f.wallet.listErr = errors.New("storage unavailable")
	w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
	if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != codeBRC121PaymentKept || w.Header().Get("Retry-After") == "" {
		t.Fatalf("want 503 %s with Retry-After, got %d %s", codeBRC121PaymentKept, w.Code, w.Body.String())
	}
	assertNoBRC121Offer(t, w)
	if !strings.Contains(w.Body.String(), "do not pay again; retry the same request shortly") || f.journaled() != 1 || f.arc.calls.Load() != 0 {
		t.Fatalf("response was not truthful or durable: %s, kept=%d, ARC=%d", w.Body.String(), f.journaled(), f.arc.calls.Load())
	}
}

func TestBRC121InFlightDuplicateKeptWithoutOffer(t *testing.T) {
	f := newBRC121Fix(t, 100)
	hold := make(chan struct{})
	f.arc.mu.Lock()
	f.arc.hold = hold
	f.arc.mu.Unlock()
	h := f.payment(t, 100, brc121Pay{})
	first := make(chan int, 1)
	go func() { first <- f.serve(brc121Path, "10.0.0.1:1", h).Code }()
	waitAtomicCalls(t, &f.arc.calls, 1)
	w := f.serve(brc121Path, "10.0.0.2:1", h)
	if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != codeBRC121PaymentKept {
		t.Fatalf("want 503 %s, got %d %s", codeBRC121PaymentKept, w.Code, w.Body.String())
	}
	assertNoBRC121Offer(t, w)
	close(hold)
	if code := <-first; code != http.StatusOK {
		t.Fatalf("first request got %d", code)
	}
}

func TestBRC121JournalPrecedesAcceptedNetworkResult(t *testing.T) {
	f := newBRC121Fix(t, 100)
	f.pg.brc121.beforeRecord = func() error { return errors.New("recording deliberately interrupted") }
	h := f.payment(t, 100, brc121Pay{})
	w := f.serve(brc121Path, "10.0.0.1:1", h)
	if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != codeBRC121PaymentKept {
		t.Fatalf("want a kept response, got %d %s", w.Code, w.Body.String())
	}
	p := &brc121Payment{}
	if err := p.readBRC121BEEF(h[headerBRC121Beef], 100); err != nil || !f.pg.brc121.journal.has(p.txid.String()) {
		t.Fatalf("accepted payment was not already journaled: %v", err)
	}
	f.pg.brc121.beforeRecord = nil
	f.now = f.now.Add(2 * time.Minute)
	f.pg.sweepBRC121(context.Background())
	if f.pg.brc121.journal.has(p.txid.String()) {
		t.Fatal("the sweep did not remove the recorded payment")
	}
	if _, held := f.wallet.recorded(); held != 1 {
		t.Fatalf("the sweep recorded %d payments, want 1", held)
	}
}

func TestBRC121RejectsTrailingAtomicBEEFBytes(t *testing.T) {
	for _, suffix := range [][]byte{{0}, {0xde, 0xad, 0xbe, 0xef}} {
		f := newBRC121Fix(t, 100)
		h := f.payment(t, 100, brc121Pay{})
		raw, err := base64.StdEncoding.DecodeString(h[headerBRC121Beef])
		if err != nil {
			t.Fatal(err)
		}
		h[headerBRC121Beef] = base64.StdEncoding.EncodeToString(append(raw, suffix...))
		w := f.serve(brc121Path, "10.0.0.1:1", h)
		if w.Code != http.StatusPaymentRequired || codeOf(t, w) != codeBRC121BadBEEF || f.arc.calls.Load() != 0 {
			t.Fatalf("suffix %x: want 402 %s before ARC, got %d %s", suffix, codeBRC121BadBEEF, w.Code, w.Body.String())
		}
	}
}

func TestBRC121PerClientJournalCap(t *testing.T) {
	f := newBRC121Fix(t, 100)
	key := sha256.Sum256([]byte(rateLimitKey("10.0.0.1")))
	f.pg.brc121.live.counts = map[[32]byte]int{key: maxBRC121ClientJournalEntries}
	f.pg.brc121.live.owners = make(map[string][32]byte)
	w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
	if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != codeBRC121PaymentUnrecorded {
		t.Fatalf("want 503 %s, got %d %s", codeBRC121PaymentUnrecorded, w.Code, w.Body.String())
	}
	assertNoBRC121Offer(t, w)
	if !strings.Contains(w.Body.String(), "do not pay again; retry the same request shortly") {
		t.Fatalf("response omitted the retry warning: %s", w.Body.String())
	}
	if f.journaled() != 0 || f.arc.calls.Load() != 0 {
		t.Fatalf("over-cap payment was kept (%d) or submitted (%d)", f.journaled(), f.arc.calls.Load())
	}
}

func TestBRC121JournalWriteFailureUnrecorded(t *testing.T) {
	f := newBRC121Fix(t, 100)
	if err := f.pg.brc121.journal.close(); err != nil {
		t.Fatal(err)
	}
	w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
	if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != codeBRC121PaymentUnrecorded {
		t.Fatalf("want 503 %s, got %d %s", codeBRC121PaymentUnrecorded, w.Code, w.Body.String())
	}
	assertNoBRC121Offer(t, w)
	if f.arc.calls.Load() != 0 {
		t.Fatalf("journal write failure reached ARC %d times", f.arc.calls.Load())
	}
}

func TestBRC121SetupReportsActualError(t *testing.T) {
	payer := newBRC121Payer()
	hs := brc121HeaderStore(t, payer.source)
	_, client := newBRC121Stub()
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{}, ARCClient: client})
	err := pg.startBRC121(brokenDeriveWallet{newFakeBRC121Wallet()}, spv.NewValidator(hs), t.TempDir(), slog.Default())
	if err == nil {
		t.Fatal("setup unexpectedly succeeded")
	}
	reason, _ := pg.brc121Status()["reason"].(string)
	if reason != err.Error() || reason == "the node wallet could not be set up for BRC-121" {
		t.Fatalf("setup reason %q does not report %v", reason, err)
	}
}

func waitAtomicCalls(t *testing.T, calls interface{ Load() int32 }, want int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < want && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if calls.Load() < want {
		t.Fatalf("got %d ARC calls, want %d", calls.Load(), want)
	}
}
