package messaging

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/BSVanon/Anvil/internal/store"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

var (
	prefixMsg = []byte("msg:") // msg:<recipient>:<messageId> → Message JSON
)

// Message is a point-to-point message between two identities.
type Message struct {
	MessageID  string `json:"messageId"`
	Sender     string `json:"sender"`     // compressed pubkey hex
	Recipient  string `json:"recipient"`  // compressed pubkey hex
	MessageBox string `json:"messageBox"` // named box (e.g., "inbox", "payment_inbox")
	Body       string `json:"body"`       // opaque content
	Timestamp  int64  `json:"timestamp"`  // unix seconds
}

// Store manages point-to-point messages in LevelDB.
// Messages are keyed by recipient pubkey + auto-incrementing ID.
type Store struct {
	db    *leveldb.DB
	nextID atomic.Int64
	ttl    time.Duration // auto-expire unacknowledged messages (0 = no expiry)
}

// NewStore opens or creates a message store.
func NewStore(path string, ttlSeconds int) (*Store, error) {
	db, err := store.OpenWithRecover(path, nil)
	if err != nil {
		return nil, fmt.Errorf("open message store: %w", err)
	}

	s := &Store{
		db:  db,
		ttl: time.Duration(ttlSeconds) * time.Second,
	}

	// Seed next ID from existing messages.
	s.nextID.Store(s.highWaterMark() + 1)
	return s, nil
}

// Close closes the underlying LevelDB.
func (s *Store) Close() error {
	return s.db.Close()
}

// Send stores a message for the recipient. Returns the assigned message ID.
func (s *Store) Send(msg *Message) (string, error) {
	if msg.Recipient == "" {
		return "", fmt.Errorf("recipient required")
	}
	if msg.MessageBox == "" {
		return "", fmt.Errorf("messageBox required")
	}
	if msg.Body == "" {
		return "", fmt.Errorf("body required")
	}

	id := s.nextID.Add(1)
	msg.MessageID = fmt.Sprintf("%d", id)
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().Unix()
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("marshal message: %w", err)
	}

	key := s.messageKey(msg.Recipient, msg.MessageID)
	if err := s.db.Put(key, data, nil); err != nil {
		return "", fmt.Errorf("store message: %w", err)
	}
	return msg.MessageID, nil
}

// List returns messages for a recipient in a given message box.
// Results are ordered by message ID (ascending = oldest first).
func (s *Store) List(recipient, messageBox string) ([]*Message, error) {
	prefix := append(append([]byte{}, prefixMsg...), []byte(recipient+":")...)

	var results []*Message
	iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()

	for iter.Next() {
		var msg Message
		if err := json.Unmarshal(iter.Value(), &msg); err != nil {
			continue
		}
		if msg.MessageBox != messageBox {
			continue
		}
		results = append(results, &msg)
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("iterate messages: %w", err)
	}
	return results, nil
}

// Acknowledge deletes messages by ID for a given recipient.
// Returns the number of messages deleted.
func (s *Store) Acknowledge(recipient string, messageIDs []string) (int, error) {
	deleted := 0
	for _, id := range messageIDs {
		key := s.messageKey(recipient, id)
		if ok, _ := s.db.Has(key, nil); ok {
			if err := s.db.Delete(key, nil); err != nil {
				return deleted, fmt.Errorf("delete message %s: %w", id, err)
			}
			deleted++
		}
	}
	return deleted, nil
}

// ExpireOld removes messages older than the configured TTL.
// Call periodically. Returns the number expired.
func (s *Store) ExpireOld() int {
	if s.ttl <= 0 {
		return 0
	}
	cutoff := time.Now().Add(-s.ttl).Unix()

	var toDelete [][]byte
	iter := s.db.NewIterator(util.BytesPrefix(prefixMsg), nil)
	for iter.Next() {
		var msg Message
		if err := json.Unmarshal(iter.Value(), &msg); err != nil {
			continue
		}
		if msg.Timestamp < cutoff {
			keyCopy := make([]byte, len(iter.Key()))
			copy(keyCopy, iter.Key())
			toDelete = append(toDelete, keyCopy)
		}
	}
	iter.Release()

	for _, k := range toDelete {
		_ = s.db.Delete(k, nil)
	}
	return len(toDelete)
}

// Count returns the total number of messages stored.
func (s *Store) Count() int {
	count := 0
	iter := s.db.NewIterator(util.BytesPrefix(prefixMsg), nil)
	for iter.Next() {
		count++
	}
	iter.Release()
	return count
}

func (s *Store) messageKey(recipient, messageID string) []byte {
	return append(append([]byte{}, prefixMsg...), []byte(recipient+":"+messageID)...)
}

func (s *Store) highWaterMark() int64 {
	var max int64
	iter := s.db.NewIterator(util.BytesPrefix(prefixMsg), nil)
	defer iter.Release()
	for iter.Next() {
		var msg Message
		if err := json.Unmarshal(iter.Value(), &msg); err != nil {
			continue
		}
		var id int64
		if _, err := fmt.Sscanf(msg.MessageID, "%d", &id); err == nil && id > max {
			max = id
		}
	}
	return max
}
