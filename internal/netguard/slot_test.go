package netguard

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
)

// heldSlots counts the decoding slots in use, by taking every free one and
// giving them all back.
func heldSlots(t *testing.T) int {
	t.Helper()
	release := takeSlots(t, peerhygiene.LookupSlots, false)
	defer release.all()
	return peerhygiene.LookupSlots - len(release)
}

type releases []func()

func (r releases) all() {
	for _, release := range r {
		release()
	}
}

// takeSlots takes up to n free decoding slots, waiting briefly for each. With
// must set, it fails the test unless it gets all n.
func takeSlots(t *testing.T, n int, must bool) releases {
	t.Helper()
	var got releases
	for range n {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		release, err := peerhygiene.AcquireLookupSlot(ctx)
		cancel()
		if err != nil {
			if must {
				got.all()
				t.Fatalf("only %d of %d decoding slots are free", len(got), n)
			}
			break
		}
		got = append(got, release)
	}
	return got
}

func lookupRequest(t *testing.T, ctx context.Context, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/lookup", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

// TestGuard_HoldsTheSlotUntilTheBodyIsClosed: an accepted reply holds its
// decoding slot until the caller closes the body, so the caller's own
// decoding runs under it. Closing again frees nothing more: here a slot held
// elsewhere stays held.
func TestGuard_HoldsTheSlotUntilTheBodyIsClosed(t *testing.T) {
	url, _ := serveAnswer(t, "application/json", []byte(`{"type":"freeform","result":"ok"}`), false)
	elsewhere := takeSlots(t, 1, true)
	defer elsewhere.all()

	resp, err := http.DefaultClient.Do(lookupRequest(t, context.Background(), url))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if n := heldSlots(t); n != 2 {
		t.Fatalf("with the body open, %d slots are held, want 2", n)
	}
	_ = resp.Body.Close()
	_ = resp.Body.Close()
	if n := heldSlots(t); n != 1 {
		t.Fatalf("after the body is closed twice, %d slots are held, want the 1 held elsewhere", n)
	}
}

// TestGuard_ReturnsTheSlotOfARefusedReply: whatever stops the guard handing a
// reply on returns its slot: a reply the validator refuses, a declared or a
// streamed length over the cap, or a body cut off part way.
func TestGuard_ReturnsTheSlotOfARefusedReply(t *testing.T) {
	cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0123456789"))
		w.(http.Flusher).Flush()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(cut.Close)
	over := freeformOfSize(int(peerhygiene.MaxLookupResponseBytes) + 1)
	for name, url := range map[string]string{
		"refused by the validator": first(serveAnswer(t, octetStream, countBomb, false)),
		"declared over the cap":    first(serveAnswer(t, "application/json", over, false)),
		"streamed over the cap":    first(serveAnswer(t, "application/json", over, true)),
		"cut off part way":         cut.URL,
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := http.DefaultClient.Do(lookupRequest(t, context.Background(), url))
			if err == nil {
				_ = resp.Body.Close()
				t.Fatal("the guard must refuse the reply")
			}
			if n := heldSlots(t); n != 0 {
				t.Fatalf("after the refusal (%v), %d slots are held, want 0", err, n)
			}
		})
	}
}

func first(url string, _ any) string { return url }

// TestGuard_GivesUpWhenNoSlotFrees: while every slot is held, a reply waits
// for one only as long as its request's context lasts, then fails with
// ErrNoLookupSlot, which hygiene does not count against the host.
func TestGuard_GivesUpWhenNoSlotFrees(t *testing.T) {
	url, _ := serveAnswer(t, "application/json", []byte(`{"type":"freeform","result":"ok"}`), false)
	all := takeSlots(t, peerhygiene.LookupSlots, true)
	defer all.all()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	resp, err := http.DefaultClient.Do(lookupRequest(t, ctx, url))
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the reply must not be handed on without a slot")
	}
	if !errors.Is(err, peerhygiene.ErrNoLookupSlot) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want ErrNoLookupSlot wrapping the deadline, got: %v", err)
	}
}

// TestGuard_ReturnsTheSlotOfABodyNeverClosed: a caller that drops an
// accepted reply's body without closing it does not keep the slot for good;
// it comes back once the garbage collector finds the body unreachable.
func TestGuard_ReturnsTheSlotOfABodyNeverClosed(t *testing.T) {
	url, _ := serveAnswer(t, "application/json", []byte(`{"type":"freeform","result":"ok"}`), false)
	func() {
		if _, err := http.DefaultClient.Do(lookupRequest(t, context.Background(), url)); err != nil {
			t.Fatalf("lookup: %v", err)
		}
	}()
	for deadline := time.Now().Add(10 * time.Second); heldSlots(t) != 0; {
		if time.Now().After(deadline) {
			t.Fatal("the slot of a body never closed did not come back")
		}
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
}

// TestGuard_ReadTimeoutReturnsTheSlot: a peer that sends its headers and
// then trickles, or stalls, cannot keep a slot past the guard's read timeout.
func TestGuard_ReadTimeoutReturnsTheSlot(t *testing.T) {
	stall := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0123456789"))
		w.(http.Flusher).Flush()
		<-stall
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(stall) }) // runs first, so srv.Close does not wait on the handler

	g := &guard{base: http.DefaultTransport, maxBytes: MaxResponseBytes,
		maxLookupBytes: peerhygiene.MaxLookupResponseBytes, readTimeout: 50 * time.Millisecond}
	resp, err := (&http.Client{Transport: g}).Do(lookupRequest(t, context.Background(), srv.URL))
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the guard must give up on the stalled reply")
	}
	if !strings.Contains(err.Error(), "netguard: lookup answer not read within 50ms") {
		t.Fatalf("want the read timeout, got: %v", err)
	}
	if n := heldSlots(t); n != 0 {
		t.Fatalf("after the read timeout, %d slots are held, want 0", n)
	}
}

// stalledBody is a reply body whose Read waits until Close. It counts its
// Close calls without synchronizing them, as a body need not.
type stalledBody struct {
	closes int
	closed chan struct{}
}

func (b *stalledBody) Read([]byte) (int, error) {
	<-b.closed
	return 0, errors.New("read on a closed body")
}

func (b *stalledBody) Close() error {
	if b.closes++; b.closes == 1 {
		close(b.closed)
	}
	return nil
}

// TestGuard_ClosesAStalledBodyOnce: the read timeout closes a stalled reply's
// body to cut the read short, and the guard does not close it again.
func TestGuard_ClosesAStalledBodyOnce(t *testing.T) {
	body := &stalledBody{closed: make(chan struct{})}
	resp := &http.Response{StatusCode: http.StatusOK, Body: body, ContentLength: -1, Header: http.Header{}}
	g := &guard{base: fakeTransport{resp: resp}, maxBytes: MaxResponseBytes,
		maxLookupBytes: peerhygiene.MaxLookupResponseBytes, readTimeout: 20 * time.Millisecond}
	_, err := g.RoundTrip(newRequest(t, http.MethodPost, "http://h/lookup"))
	if err == nil || !strings.Contains(err.Error(), "netguard: lookup answer not read within 20ms") {
		t.Fatalf("want the read timeout, got: %v", err)
	}
	if body.closes != 1 {
		t.Fatalf("the body was closed %d times, want once", body.closes)
	}
	if n := heldSlots(t); n != 0 {
		t.Fatalf("after the read timeout, %d slots are held, want 0", n)
	}
}

// TestGuard_BoundedFacilitatorTakesOneSlotPerExchange: peerhygiene's
// BoundedFacilitator on http.DefaultClient decodes under the slot the guard
// took for the exchange instead of waiting for a second one. Twice as many
// lookups as slots, answered all at once, all complete; taking a second slot
// would leave every slot held by a lookup waiting for another.
func TestGuard_BoundedFacilitatorTakesOneSlotPerExchange(t *testing.T) {
	const lookups = 2 * peerhygiene.LookupSlots
	var mu sync.Mutex
	arrived, all := 0, make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		if arrived++; arrived == lookups {
			close(all)
		}
		mu.Unlock()
		select { // answer once every lookup is waiting
		case <-all:
		case <-time.After(2 * time.Second):
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"freeform","result":"ok"}`))
	}))
	t.Cleanup(srv.Close)
	url := srv.URL
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errs := make(chan error, lookups)
	for range lookups {
		go func() {
			_, err := (&peerhygiene.BoundedFacilitator{Client: http.DefaultClient}).Lookup(ctx, url, slapQuestion)
			errs <- err
		}()
	}
	for range lookups {
		if err := <-errs; err != nil {
			t.Fatalf("lookup: %v", err)
		}
	}
	if n := heldSlots(t); n != 0 {
		t.Fatalf("after the lookups, %d slots are held, want 0", n)
	}
}
