package api

import (
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// TestMessageHubFanout verifies new messages are delivered to all subscribers
// matching the recipient+messageBox key, and not to unrelated subscribers.
// Wallets rely on this to receive real-time notifications of messages.
func TestMessageHubFanout(t *testing.T) {
	hub := newMessageHub()

	chA := make(chan *messaging.Message, 4)
	chB := make(chan *messaging.Message, 4)
	chOther := make(chan *messaging.Message, 4)

	unsubA := hub.subscribe("recipient-1", "avos.offer", chA)
	unsubB := hub.subscribe("recipient-1", "avos.offer", chB)
	unsubOther := hub.subscribe("recipient-2", "avos.offer", chOther)
	defer unsubA()
	defer unsubB()
	defer unsubOther()

	hub.notify(&messaging.Message{
		Recipient:  "recipient-1",
		MessageBox: "avos.offer",
		Body:       "hello",
	})

	select {
	case msg := <-chA:
		if msg.Body != "hello" {
			t.Errorf("chA: expected body=hello, got %q", msg.Body)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("chA: subscriber A did not receive message")
	}

	select {
	case msg := <-chB:
		if msg.Body != "hello" {
			t.Errorf("chB: expected body=hello, got %q", msg.Body)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("chB: subscriber B did not receive message")
	}

	select {
	case msg := <-chOther:
		t.Errorf("chOther: should NOT receive message for different recipient, got body=%q", msg.Body)
	case <-time.After(50 * time.Millisecond):
		// expected — different recipient key, no delivery
	}
}

// TestMessageHubNotifyDropsSlowClient verifies the non-blocking drop behavior:
// a subscriber whose channel is full gets skipped, and delivery to other
// subscribers continues. Prevents one stuck client from blocking the whole
// fanout.
func TestMessageHubNotifyDropsSlowClient(t *testing.T) {
	hub := newMessageHub()

	// Unbuffered channel — will block on any send
	slowCh := make(chan *messaging.Message)
	fastCh := make(chan *messaging.Message, 4)

	hub.subscribe("r", "box", slowCh)
	hub.subscribe("r", "box", fastCh)

	// Notify must not block even though slowCh has no reader
	done := make(chan struct{})
	go func() {
		hub.notify(&messaging.Message{Recipient: "r", MessageBox: "box", Body: "delivered"})
		close(done)
	}()

	select {
	case <-done:
		// expected — notify returned despite slow client
	case <-time.After(200 * time.Millisecond):
		t.Fatal("notify blocked on slow client — drop-on-congestion broken")
	}

	// fastCh should have received it
	select {
	case <-fastCh:
		// expected
	case <-time.After(100 * time.Millisecond):
		t.Error("fastCh: did not receive message despite slow client being dropped")
	}
}

// TestMessageHubUnsubscribe verifies that unsubscribing stops delivery to
// that channel.
func TestMessageHubUnsubscribe(t *testing.T) {
	hub := newMessageHub()
	ch := make(chan *messaging.Message, 4)
	unsub := hub.subscribe("r", "box", ch)

	unsub() // stop receiving

	hub.notify(&messaging.Message{Recipient: "r", MessageBox: "box", Body: "should-not-arrive"})

	select {
	case msg := <-ch:
		t.Errorf("received message after unsubscribe: %q", msg.Body)
	case <-time.After(50 * time.Millisecond):
		// expected — unsubscribed, no delivery
	}
}

// TestMessageHubNextIDIsMonotonic verifies event IDs are monotonically
// increasing, as required by SSE Last-Event-ID semantics.
func TestMessageHubNextIDIsMonotonic(t *testing.T) {
	hub := newMessageHub()
	first := hub.nextID()
	second := hub.nextID()
	third := hub.nextID()
	if !(first < second && second < third) {
		t.Errorf("event IDs must be monotonically increasing; got %d, %d, %d", first, second, third)
	}
}
