package headers

import (
	"sync"
	"testing"
	"time"
)

// --- broadcaster[T] unit tests, in isolation from the Store that owns it ---
//
// feed.go's own doc comment states the contract this file pins directly:
// subscribe/unsubscribe/publish behave as a simple fan-out set, and publish
// is non-blocking so a slow or absent subscriber can never stall the
// caller — which in production runs while Store.mu is held
// (AddHeaders/ReorgTo, store.go). This was previously only exercised
// indirectly through internal/api's SSE tests.

// TestBroadcasterSubscribePublish proves a published value reaches a
// subscribed channel.
func TestBroadcasterSubscribePublish(t *testing.T) {
	b := newBroadcaster[int]()
	ch := make(chan int, 1)
	unsub := b.subscribe(ch)
	defer unsub()

	b.publish(42)

	select {
	case v := <-ch:
		if v != 42 {
			t.Fatalf("got %d, want 42", v)
		}
	default:
		t.Fatal("expected a published value on the subscribed channel")
	}
}

// TestBroadcasterUnsubscribeStopsDelivery proves unsubscribe actually
// removes the channel from the fan-out set: a publish after unsubscribe
// must not be delivered.
func TestBroadcasterUnsubscribeStopsDelivery(t *testing.T) {
	b := newBroadcaster[int]()
	ch := make(chan int, 1)
	unsub := b.subscribe(ch)
	unsub()

	b.publish(1)

	select {
	case v := <-ch:
		t.Fatalf("unsubscribed channel received %d, want nothing", v)
	default:
	}
}

// TestBroadcasterPublishAfterUnsubscribe drives publish-after-unsubscribe
// end to end: the removed subscriber gets nothing, a second, still-live
// subscriber is unaffected by the first one's removal.
func TestBroadcasterPublishAfterUnsubscribe(t *testing.T) {
	b := newBroadcaster[string]()
	gone := make(chan string, 1)
	stay := make(chan string, 1)
	unsubGone := b.subscribe(gone)
	unsubStay := b.subscribe(stay)
	defer unsubStay()

	unsubGone()
	b.publish("hello")

	select {
	case v := <-stay:
		if v != "hello" {
			t.Fatalf("got %q, want hello", v)
		}
	default:
		t.Fatal("expected the still-subscribed channel to receive the value")
	}
	select {
	case v := <-gone:
		t.Fatalf("unsubscribed channel received %q, want nothing", v)
	default:
	}
}

// TestBroadcasterFullBufferNeverBlocksPublish is the core non-blocking
// guarantee AddHeaders/ReorgTo depend on: a slow subscriber whose buffered
// channel is already full must be skipped, never block the publisher.
func TestBroadcasterFullBufferNeverBlocksPublish(t *testing.T) {
	b := newBroadcaster[int]()
	full := make(chan int, 1)
	full <- 999 // pre-fill its only slot; a blocking send would now hang forever
	unsub := b.subscribe(full)
	defer unsub()

	done := make(chan struct{})
	go func() {
		b.publish(1)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publish blocked on a full subscriber buffer")
	}

	// The pre-filled value is still the only thing in the channel — the
	// new publish was dropped, not queued behind it.
	if got := <-full; got != 999 {
		t.Fatalf("full channel's buffered value = %d, want 999 (publish must have been skipped, not queued)", got)
	}
	select {
	case v := <-full:
		t.Fatalf("channel had a second value %d queued; the publish should have been dropped", v)
	default:
	}
}

// TestBroadcasterConcurrentSubscribeAndPublish drives one goroutine
// publishing while another concurrently subscribes and unsubscribes a
// stream of short-lived channels — the -race detector (this package's
// tests always run with -race per the project's gates) is the primary
// assertion; a delivery-count check on the long-lived subscribers is a
// secondary correctness signal.
func TestBroadcasterConcurrentSubscribeAndPublish(t *testing.T) {
	b := newBroadcaster[int]()
	const subscribers = 20
	const publishes = 200

	longLived := make([]chan int, subscribers)
	unsubs := make([]func(), subscribers)
	for i := range longLived {
		longLived[i] = make(chan int, publishes)
		unsubs[i] = b.subscribe(longLived[i])
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < publishes; i++ {
			b.publish(i)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < publishes; i++ {
			ch := make(chan int, 1)
			unsub := b.subscribe(ch)
			unsub()
		}
	}()
	wg.Wait()

	for i, ch := range longLived {
		unsubs[i]()
		if got := len(ch); got != publishes {
			t.Fatalf("subscriber %d received %d values, want %d (buffer sized to never drop in this test)", i, got, publishes)
		}
	}
}
