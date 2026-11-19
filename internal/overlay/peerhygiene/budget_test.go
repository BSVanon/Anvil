package peerhygiene

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestAcquireLookupSlot_WaitsAndReleasesOnce: no more than LookupSlots slots
// are held at once, a further taker waits only as long as its context, and a
// release returns its slot the first time only.
func TestAcquireLookupSlot_WaitsAndReleasesOnce(t *testing.T) {
	var held []func()
	defer func() {
		for _, release := range held {
			release()
		}
	}()
	for range LookupSlots {
		release, err := AcquireLookupSlot(context.Background())
		if err != nil {
			t.Fatalf("a free slot: %v", err)
		}
		held = append(held, release)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := AcquireLookupSlot(ctx); !errors.Is(err, ErrNoLookupSlot) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("with every slot held, want ErrNoLookupSlot wrapping the deadline, got: %v", err)
	}
	held[0]()
	held[0]()
	if n := len(lookupSlots); n != LookupSlots-1 {
		t.Fatalf("after one slot is released twice, %d are held, want %d", n, LookupSlots-1)
	}
	release, err := AcquireLookupSlot(context.Background())
	if err != nil {
		t.Fatalf("the released slot: %v", err)
	}
	held[0] = release
}

// gatedTransport answers every request with a 200 JSON reply whose body
// blocks on its first read until gate is closed, so a test can look at the
// slots while the reply is being read. With claim set it takes a slot and
// marks the claim, holding the slot until the body is closed, as the netguard
// transport does.
type gatedTransport struct {
	body    string
	claim   bool
	gate    chan struct{}
	reading chan struct{} // closed at the body's first read
	once    sync.Once
}

func newGatedTransport(claim bool) *gatedTransport {
	return &gatedTransport{body: `{"type":"freeform","result":"ok"}`, claim: claim,
		gate: make(chan struct{}), reading: make(chan struct{})}
}

func (g *gatedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := &gatedBody{g: g}
	if g.claim {
		release, err := AcquireLookupSlot(req.Context())
		if err != nil {
			return nil, err
		}
		MarkLookupSlotHeld(req.Context())
		body.release = release
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: body, ContentLength: -1, Request: req}, nil
}

type gatedBody struct {
	g       *gatedTransport
	sent    bool
	release func()
}

func (b *gatedBody) Read(p []byte) (int, error) {
	b.g.once.Do(func() { close(b.g.reading) })
	<-b.g.gate
	if b.sent {
		return 0, io.EOF
	}
	b.sent = true
	return copy(p, b.g.body), nil
}

func (b *gatedBody) Close() error {
	if b.release != nil {
		b.release()
	}
	return nil
}

// TestBoundedFacilitator_DecodesUnderOneSlot: the facilitator reads and
// decodes a reply under one slot, its own, or, through a transport that
// already took one for the exchange (the netguard transport on
// http.DefaultClient), under that one alone, and returns it once done.
func TestBoundedFacilitator_DecodesUnderOneSlot(t *testing.T) {
	for _, claim := range []bool{false, true} {
		tr := newGatedTransport(claim)
		done := make(chan error, 1)
		go func() {
			_, err := (&BoundedFacilitator{Client: &http.Client{Transport: tr}}).Lookup(context.Background(), "https://peer.example", testQuestion)
			done <- err
		}()
		select {
		case <-tr.reading:
		case err := <-done:
			t.Fatalf("transport slot %v: the lookup returned before reading: %v", claim, err)
		}
		if n := len(lookupSlots); n != 1 {
			t.Errorf("transport slot %v: while the reply is read, %d slots are held, want 1", claim, n)
		}
		close(tr.gate)
		if err := <-done; err != nil {
			t.Fatalf("transport slot %v: lookup: %v", claim, err)
		}
		if n := len(lookupSlots); n != 0 {
			t.Errorf("transport slot %v: after the lookup, %d slots are held, want 0", claim, n)
		}
	}
}

// TestBoundedFacilitator_GivesUpWhenNoSlotFrees: while every slot is held, a
// lookup waits only as long as its context, fails with ErrNoLookupSlot, and
// hygiene counts none of it against the host.
func TestBoundedFacilitator_GivesUpWhenNoSlotFrees(t *testing.T) {
	var held []func()
	for range LookupSlots {
		release, err := AcquireLookupSlot(context.Background())
		if err != nil {
			t.Fatalf("a free slot: %v", err)
		}
		held = append(held, release)
	}
	defer func() {
		for _, release := range held {
			release()
		}
	}()
	tr := newGatedTransport(false)
	close(tr.gate)
	f := NewFacilitator(&BoundedFacilitator{Client: &http.Client{Transport: tr}}, nil)
	for i := 0; i < defaultFailuresBeforeBackoff+1; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := f.Lookup(ctx, "https://busy.example", testQuestion)
		cancel()
		if !errors.Is(err, ErrNoLookupSlot) {
			t.Fatalf("lookup %d: want ErrNoLookupSlot, got: %v", i, err)
		}
	}
	if f.tracker.inBackoff("https://busy.example") || len(f.tracker.hosts) != 0 {
		t.Fatal("waiting for a busy slot must not count against the host")
	}
}
