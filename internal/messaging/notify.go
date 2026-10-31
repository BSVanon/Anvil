package messaging

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

const notificationQueueCapacity = 4096

var (
	notificationDrainTimeout = 5 * time.Second
	// notificationQueueMaxBytes bounds the message bodies held by queued notifications.
	notificationQueueMaxBytes int64 = 64 << 20
)

type storedNotification struct {
	record   StoredMessage
	storedFn func(*StoredMessage)
	legacyFn func(*Message)
}

type notificationDispatcher struct {
	callbackMu sync.RWMutex
	onMessage  func(*Message)
	onStored   func(*StoredMessage)

	queue       chan storedNotification
	done        chan struct{}
	queuedBytes atomic.Int64

	dropped         uint64
	droppedSinceLog uint64
	lastDropLog     time.Time
}

func (s *Store) startNotificationDispatcher() {
	s.notifier = &notificationDispatcher{
		queue: make(chan storedNotification, notificationQueueCapacity),
		done:  make(chan struct{}),
	}
	s.closeDone = make(chan struct{})
	go s.dispatchNotifications()
}

// SetOnMessage is retained for the existing API constructor.
func (s *Store) SetOnMessage(fn func(*Message)) {
	s.notifier.callbackMu.Lock()
	s.notifier.onMessage = fn
	s.notifier.onStored = nil
	s.notifier.callbackMu.Unlock()
}

// SetOnStoredMessage preserves sender attestation in notifications.
func (s *Store) SetOnStoredMessage(fn func(*StoredMessage)) {
	s.notifier.callbackMu.Lock()
	s.notifier.onStored = fn
	s.notifier.onMessage = nil
	s.notifier.callbackMu.Unlock()
}

func (s *Store) insertAndNotify(record *StoredMessage) (bool, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.db.Get(indexKey(record.Recipient, record.MessageID), nil); err == nil {
		return false, nil
	} else if !errors.Is(err, leveldb.ErrNotFound) {
		return false, fmt.Errorf("read message index: %w", err)
	}
	if err := s.insertLocked(record, true); err != nil {
		return false, err
	}
	s.enqueueNotificationLocked(record)
	return true, nil
}

func (s *Store) enqueueNotificationLocked(record *StoredMessage) {
	if s.closed || s.notifier == nil {
		return
	}
	n := s.notifier
	n.callbackMu.RLock()
	storedFn, legacyFn := n.onStored, n.onMessage
	n.callbackMu.RUnlock()
	if storedFn == nil && legacyFn == nil {
		return
	}
	event := storedNotification{record: *record, storedFn: storedFn, legacyFn: legacyFn}
	size := int64(len(record.Body))
	if n.queuedBytes.Add(size) > notificationQueueMaxBytes {
		n.queuedBytes.Add(-size)
		n.noteDropLocked()
		return
	}
	select {
	case n.queue <- event:
	default:
		n.queuedBytes.Add(-size)
		n.noteDropLocked()
	}
}

// noteDropLocked counts a dropped notification; the caller holds writeMu.
func (n *notificationDispatcher) noteDropLocked() {
	n.dropped++
	n.droppedSinceLog++
	now := time.Now()
	if n.lastDropLog.IsZero() || now.Sub(n.lastDropLog) >= time.Minute {
		log.Printf("messagebox notification queue full: dropped %d notifications", n.droppedSinceLog)
		n.droppedSinceLog = 0
		n.lastDropLog = now
	}
}

func (s *Store) dispatchNotifications() {
	defer close(s.notifier.done)
	for event := range s.notifier.queue {
		invokeNotification(event)
		s.notifier.queuedBytes.Add(-int64(len(event.record.Body)))
	}
}

func invokeNotification(event storedNotification) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("messagebox notification callback panic: %v", recovered)
		}
	}()
	if event.storedFn != nil {
		view := event.record
		event.storedFn(&view)
	} else if event.legacyFn != nil {
		msg := event.record.Message
		event.legacyFn(&msg)
	}
}

func (s *Store) Close() error {
	s.writeMu.Lock()
	if s.closed {
		done := s.closeDone
		s.writeMu.Unlock()
		<-done
		s.writeMu.Lock()
		err := s.closeError
		s.writeMu.Unlock()
		return err
	}
	s.closed = true
	close(s.notifier.queue)
	dispatchDone := s.notifier.done
	closeDone := s.closeDone
	s.writeMu.Unlock()

	select {
	case <-dispatchDone:
	case <-time.After(notificationDrainTimeout):
		log.Printf("messagebox notification drain timed out after %s", notificationDrainTimeout)
	}

	s.writeMu.Lock()
	s.closeError = s.db.Close()
	close(closeDone)
	err := s.closeError
	s.writeMu.Unlock()
	return err
}
