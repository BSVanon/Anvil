package messaging

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNotificationsFollowPersistedArrivalOrderAcrossConcurrentWrites(t *testing.T) {
	s := testStore(t, Options{})
	sender, recipient, origin := testIdentity(t), testIdentity(t), testIdentity(t)
	const total = 24
	notified := make(chan string, total)
	s.SetOnStoredMessage(func(msg *StoredMessage) {
		notified <- msg.MessageID
	})
	start := make(chan struct{})
	errs := make(chan error, total)
	var writers sync.WaitGroup
	for i := 0; i < total; i++ {
		writers.Add(1)
		go func(i int) {
			defer writers.Done()
			<-start
			body := fmt.Sprintf("body-%02d", i)
			if i%2 == 0 {
				_, err := s.Send(&Message{Sender: sender, Recipient: recipient, MessageBox: "box", Body: body}, origin)
				errs <- err
				return
			}
			_, err := s.Deliver(&Message{
				MessageID: fmt.Sprintf("legacy-%02d", i), Sender: sender, Recipient: recipient,
				MessageBox: "box", Body: body,
			}, "sender")
			errs <- err
		}(i)
	}
	close(start)
	writers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	stored, err := s.List(recipient, "box")
	if err != nil || len(stored) != total {
		t.Fatalf("stored = %d, %v", len(stored), err)
	}
	for i, persisted := range stored {
		select {
		case got := <-notified:
			if got != persisted.MessageID {
				t.Fatalf("notification[%d] = %q, persisted ID = %q", i, got, persisted.MessageID)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for notification %d", i)
		}
	}
}

func TestNotificationCallbackCanWriteToSameStore(t *testing.T) {
	s := testStore(t, Options{})
	sender, recipient, origin := testIdentity(t), testIdentity(t), testIdentity(t)
	done := make(chan error, 1)
	s.SetOnStoredMessage(func(msg *StoredMessage) {
		if msg.Body != "first" {
			return
		}
		if deleted, err := s.Acknowledge(recipient, []string{msg.MessageID}); err != nil || deleted != 1 {
			done <- fmt.Errorf("acknowledge from callback = %d, %v", deleted, err)
			return
		}
		_, err := s.Send(&Message{Sender: sender, Recipient: recipient, MessageBox: "box", Body: "second"}, origin)
		done <- err
	})
	sendTest(t, s, sender, recipient, origin, "box", "first")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("callback write deadlocked")
	}
	msgs, err := s.List(recipient, "box")
	if err != nil || len(msgs) != 1 || msgs[0].Body != "second" {
		t.Fatalf("messages after callback writes = %+v, %v", msgs, err)
	}
}

func TestNotificationDispatcherRecoversFromCallbackPanic(t *testing.T) {
	s := testStore(t, Options{})
	sender, recipient, origin := testIdentity(t), testIdentity(t), testIdentity(t)
	delivered := make(chan string, 1)
	s.SetOnStoredMessage(func(msg *StoredMessage) {
		if msg.Body == "panic" {
			panic("test callback panic")
		}
		delivered <- msg.Body
	})
	sendTest(t, s, sender, recipient, origin, "box", "panic")
	sendTest(t, s, sender, recipient, origin, "box", "after")
	select {
	case got := <-delivered:
		if got != "after" {
			t.Fatalf("notification after panic = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("callback panic stopped the dispatcher")
	}
}

func TestCloseReturnsWhenNotificationCallbackDoesNotDrain(t *testing.T) {
	s, err := NewStore(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	previousTimeout := notificationDrainTimeout
	notificationDrainTimeout = 50 * time.Millisecond
	t.Cleanup(func() { notificationDrainTimeout = previousTimeout })
	entered := make(chan struct{})
	release := make(chan struct{})
	s.SetOnStoredMessage(func(*StoredMessage) {
		close(entered)
		<-release
	})
	sendTest(t, s, testIdentity(t), testIdentity(t), testIdentity(t), "box", "pending")
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("callback did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not honor the notification drain timeout")
	}
	close(release)
	select {
	case <-s.notifier.done:
	case <-time.After(time.Second):
		t.Fatal("notification dispatcher did not exit after callback release")
	}
}

func TestNotificationQueueByteBudgetDropsExcessButKeepsMessages(t *testing.T) {
	previous := notificationQueueMaxBytes
	notificationQueueMaxBytes = 10
	t.Cleanup(func() { notificationQueueMaxBytes = previous })
	s := testStore(t, Options{})
	release := make(chan struct{})
	var mu sync.Mutex
	var got []string
	s.SetOnStoredMessage(func(m *StoredMessage) {
		<-release
		mu.Lock()
		got = append(got, m.Body)
		mu.Unlock()
	})
	sender, recipient, origin := testIdentity(t), testIdentity(t), testIdentity(t)
	// Queued bytes are released only after a callback returns, so with the
	// first callback blocked, 4+4 bytes fit the 10-byte budget and the third
	// notification is dropped.
	for _, body := range []string{"aaaa", "bbbb", "cccc"} {
		sendTest(t, s, sender, recipient, origin, "box", body)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[0] != "aaaa" || got[1] != "bbbb" {
		t.Fatalf("delivered notifications = %v, want [aaaa bbbb]", got)
	}
	if listed, err := s.List(recipient, "box"); err != nil || len(listed) != 3 {
		t.Fatalf("stored messages = %d, %v; a dropped notification must not drop the message", len(listed), err)
	}
}
