package netguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

// tricklingHost answers every lookup with a declared peerhygiene-capped
// length and then trickles the body at about rate bytes per second, until
// the client goes away. It reports each request's arrival on arrived.
func tricklingHost(t *testing.T, rate int, arrived chan<- struct{}) string {
	t.Helper()
	const chunk = 2 << 10
	interval := time.Duration(chunk) * time.Second / time.Duration(rate)
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.FormatInt(peerhygiene.MaxLookupResponseBytes, 10))
		w.WriteHeader(http.StatusOK)
		piece := []byte(strings.Repeat(" ", chunk))
		for {
			if _, err := w.Write(piece); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			if arrived != nil {
				select {
				case arrived <- struct{}{}:
				default:
				}
				arrived = nil
			}
			select {
			case <-r.Context().Done():
				return
			case <-stop:
				return
			case <-time.After(interval):
			}
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(stop) }) // runs first, so srv.Close does not wait on the handlers
	return srv.URL
}

// TestGuard_SlowHostsCannotStarveAnHonestAnswer: twelve hosts answer a stock
// go-sdk LookupResolver query at once, each declaring a 2 MiB reply and
// trickling it at twice bodyread.MinReadRate, so the rate floor never cuts
// them off; one honest host answers 300 ms later. Reading before taking a
// slot, the slow hosts hold read permits, of which there are 32, and no
// decoding slot, so the honest answer is decoded and reaches the merged
// answer within the query's 3 s. Taking the slot first, the slow hosts hold
// all four slots until the query ends and the honest answer never gets one.
func TestGuard_SlowHostsCannotStarveAnHonestAnswer(t *testing.T) {
	const slow = 12
	arrived := make(chan struct{}, slow)
	var hosts []string
	for range slow {
		hosts = append(hosts, tricklingHost(t, 2*bodyread.MinReadRate, arrived))
	}
	tx, beef := spendingTx(t, []byte("honest"))
	honestBody := jsonOutputList(t, beef, 0)
	honest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond) // after every slow host has sent its headers
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(honestBody)
	}))
	t.Cleanup(honest.Close)
	hosts = append(hosts, honest.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	answer, err := lookup.NewLookupResolver(&lookup.LookupResolver{SLAPTrackers: hosts}).Query(ctx, slapQuestion)
	took := time.Since(start)
	if err != nil {
		t.Fatalf("the honest answer must be used despite %d slow hosts: %v", slow, err)
	}
	if len(answer.Outputs) != 1 || mergedKeys(t, answer)[tx.TxID().String()+".0"] != true {
		t.Fatalf("the merged answer lacks the honest output: %+v", answer.Outputs)
	}
	if took > 5*time.Second {
		t.Fatalf("the query took %v, past its 3s window", took)
	}
	if got := len(arrived); got != slow {
		t.Fatalf("only %d of %d slow hosts began their replies", got, slow)
	}
	waitFor(t, "read permits to come back", func() bool { return heldPermits() == 0 })
}

// TestGuard_ReadPermitsBoundReadsInProgress: forty lookup replies that send
// their headers and stall are read under at most bodyread.LookupPermits
// permits at once, and none takes a decoding slot; the rest wait for a
// permit. When the lookups' context ends, every permit comes back.
func TestGuard_ReadPermitsBoundReadsInProgress(t *testing.T) {
	const lookups = bodyread.LookupPermits + 8
	url := tricklingHost(t, 1, nil) // one 2 KiB piece, then nothing for 2 s
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range lookups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp, err := http.DefaultClient.Do(lookupRequest(t, ctx, url)); err == nil {
				_ = resp.Body.Close()
			}
		}()
	}
	waitFor(t, "every permit to be taken", func() bool { return heldPermits() == bodyread.LookupPermits })
	for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if n := heldPermits(); n > bodyread.LookupPermits {
			t.Fatalf("%d read permits are taken, over the %d there are", n, bodyread.LookupPermits)
		}
	}
	if n := heldSlots(t); n != 0 {
		t.Fatalf("%d decoding slots are held by replies still being read, want 0", n)
	}
	cancel()
	wg.Wait()
	waitFor(t, "read permits to come back", func() bool { return heldPermits() == 0 })
}

// TestGuard_HoldsTheReadPermitUntilASlotIsTaken: a reply read in full keeps
// its read permit while it waits for a decoding slot, so bodies read ahead of
// their slot stay counted, and gives it back once it has the slot.
func TestGuard_HoldsTheReadPermitUntilASlotIsTaken(t *testing.T) {
	url, _ := serveAnswer(t, "application/json", []byte(`{"type":"freeform","result":"ok"}`), false)
	all := takeSlots(t, peerhygiene.LookupSlots, true)
	done := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(lookupRequest(t, context.Background(), url))
		if err == nil {
			_ = resp.Body.Close()
		}
		done <- err
	}()
	waitFor(t, "the reply to take a read permit", func() bool { return heldPermits() == 1 })
	time.Sleep(100 * time.Millisecond) // long enough to read 33 bytes from loopback
	if n := heldPermits(); n != 1 {
		t.Fatalf("waiting for a slot, the reply holds %d read permits, want 1", n)
	}
	all[0]()
	if err := <-done; err != nil {
		t.Fatalf("the lookup must complete once a slot frees: %v", err)
	}
	releases(all[1:]).all()
	if n := heldPermits(); n != 0 {
		t.Fatalf("after the lookup, %d read permits are held, want 0", n)
	}
}

// TestGuard_CutsOffALookupBelowTheMinimumRate: a reply that keeps trickling,
// slower than the guard's minimum rate once its grace has passed, is cut off
// long before the read timeout, and the error counts against the host: it is
// not ErrNoLookupSlot.
func TestGuard_CutsOffALookupBelowTheMinimumRate(t *testing.T) {
	url := tricklingHost(t, 4<<10, nil) // 4 KiB/s
	g := &guard{base: http.DefaultTransport, maxBytes: MaxResponseBytes, maxLookupBytes: peerhygiene.MaxLookupResponseBytes,
		readTimeout: 20 * time.Second, minRate: 64 << 10, grace: 200 * time.Millisecond}
	start := time.Now()
	resp, err := (&http.Client{Transport: g}).Do(lookupRequest(t, context.Background(), url))
	took := time.Since(start)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the guard must cut off the trickle")
	}
	if !strings.Contains(err.Error(), "netguard: lookup answer arrived below 65536 bytes/s after 200ms") {
		t.Fatalf("want the minimum-rate cutoff, got: %v", err)
	}
	if errors.Is(err, peerhygiene.ErrNoLookupSlot) {
		t.Fatal("a host too slow to answer must count against it")
	}
	if took > 3*time.Second {
		t.Fatalf("the cutoff took %v, want about the 200ms grace", took)
	}
	waitFor(t, "read permits to come back", func() bool { return heldPermits() == 0 })
}

// TestGuard_GivesUpWhenNoReadPermitFrees: while every read permit is taken, a
// reply waits for one only as long as its request's context lasts, and the
// error wraps ErrNoLookupSlot, so hygiene does not count it against the host.
func TestGuard_GivesUpWhenNoReadPermitFrees(t *testing.T) {
	url, _ := serveAnswer(t, "application/json", []byte(`{"type":"freeform","result":"ok"}`), false)
	var all releases
	for range bodyread.LookupPermits {
		release, err := bodyread.Lookups.Acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, release)
	}
	defer all.all()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	resp, err := http.DefaultClient.Do(lookupRequest(t, ctx, url))
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the reply must not be read without a permit")
	}
	if !errors.Is(err, peerhygiene.ErrNoLookupSlot) || !errors.Is(err, bodyread.ErrNoPermit) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want ErrNoLookupSlot and ErrNoPermit wrapping the deadline, got: %v", err)
	}
}

// waitFor polls cond for up to 5 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}
