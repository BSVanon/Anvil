package messaging

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
)

const (
	defaultTTLSeconds       = int64(7 * 24 * 60 * 60)
	defaultMaxPairMessages  = int64(1000)
	defaultMaxPairBytes     = int64(64 << 20)
	defaultMaxStoreMessages = int64(1000000)
	defaultMaxStoreBytes    = int64(2 << 30)
)

type counter struct {
	Count int64 `json:"count"`
	Bytes int64 `json:"bytes"`
}

func normalizeOptions(opts Options) Options {
	if opts.TTLSeconds <= 0 {
		opts.TTLSeconds = defaultTTLSeconds
	}
	if opts.MaxPairMessages <= 0 {
		opts.MaxPairMessages = defaultMaxPairMessages
	}
	if opts.MaxPairBytes <= 0 {
		opts.MaxPairBytes = defaultMaxPairBytes
	}
	if opts.MaxStoreMessages <= 0 {
		opts.MaxStoreMessages = defaultMaxStoreMessages
	}
	if opts.MaxStoreBytes <= 0 {
		opts.MaxStoreBytes = defaultMaxStoreBytes
	}
	if opts.MaxInboxMessages < 0 {
		opts.MaxInboxMessages = 0
	}
	if opts.MaxInboxBytes < 0 {
		opts.MaxInboxBytes = 0
	}
	return opts
}

func readCounter(db *leveldb.DB, key []byte) (counter, error) {
	var value counter
	raw, err := db.Get(key, nil)
	if errors.Is(err, leveldb.ErrNotFound) {
		return value, nil
	}
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, fmt.Errorf("decode quota counter: %w", err)
	}
	return value, nil
}

func putCounter(batch *leveldb.Batch, key []byte, value counter) error {
	if value.Count < 0 {
		value.Count = 0
	}
	if value.Bytes < 0 {
		value.Bytes = 0
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	batch.Put(key, raw)
	return nil
}

func exceeds(current counter, bodyBytes, maxMessages, maxBytes int64) bool {
	return (maxMessages > 0 && current.Count+1 > maxMessages) ||
		(maxBytes > 0 && current.Bytes+bodyBytes > maxBytes)
}

func (s *Store) insert(record *StoredMessage, enforce bool) error {
	inserted, err := s.insertIfAbsent(record, enforce)
	if err != nil {
		return err
	}
	if !inserted {
		return errors.New("message ID already exists")
	}
	return nil
}

func (s *Store) insertIfAbsent(record *StoredMessage, enforce bool) (bool, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	idx := indexKey(record.Recipient, record.MessageID)
	if _, err := s.db.Get(idx, nil); err == nil {
		return false, nil
	} else if !errors.Is(err, leveldb.ErrNotFound) {
		return false, fmt.Errorf("read message index: %w", err)
	}
	return true, s.insertLocked(record, enforce)
}

func (s *Store) insertLocked(record *StoredMessage, enforce bool) error {
	return s.insertLockedWithDeletes(record, enforce, nil)
}

func (s *Store) insertLockedWithDeletes(record *StoredMessage, enforce bool, deleteKeys [][]byte) error {
	if record.ReceivedAt <= 0 {
		record.ReceivedAt = s.now().Unix()
	}
	bodyBytes := int64(len(record.Body))
	pairKey := pairCounterKey(record.Sender, record.Recipient)
	inboxKey := inboxCounterKey(record.Recipient)
	pair, err := readCounter(s.db, pairKey)
	if err != nil {
		return err
	}
	inbox, err := readCounter(s.db, inboxKey)
	if err != nil {
		return err
	}
	node, err := readCounter(s.db, keyNodeCounter)
	if err != nil {
		return err
	}
	if enforce {
		if exceeds(pair, bodyBytes, s.opts.MaxPairMessages, s.opts.MaxPairBytes) {
			return ErrPairQuota
		}
		if exceeds(inbox, bodyBytes, s.opts.MaxInboxMessages, s.opts.MaxInboxBytes) {
			return ErrInboxQuota
		}
		if exceeds(node, bodyBytes, s.opts.MaxStoreMessages, s.opts.MaxStoreBytes) {
			return ErrStoreFull
		}
	}
	data, err := encodeRecord(record)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	seq := s.seq + 1
	primary := primaryKey(record.Recipient, record.MessageBox, seq)
	batch := new(leveldb.Batch)
	batch.Put(primary, data)
	batch.Put(indexKey(record.Recipient, record.MessageID), primary)
	batch.Put(expiryKey(record.ReceivedAt, primary), nil)
	putUint64(batch, keyMetaSeq, seq)
	for _, key := range deleteKeys {
		batch.Delete(key)
	}
	pair.Count++
	pair.Bytes += bodyBytes
	inbox.Count++
	inbox.Bytes += bodyBytes
	node.Count++
	node.Bytes += bodyBytes
	if err := putCounter(batch, pairKey, pair); err != nil {
		return err
	}
	if err := putCounter(batch, inboxKey, inbox); err != nil {
		return err
	}
	if err := putCounter(batch, keyNodeCounter, node); err != nil {
		return err
	}
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("store message: %w", err)
	}
	s.seq = seq
	return nil
}

func (s *Store) deletePrimaryLocked(primary []byte) (bool, error) {
	data, err := s.db.Get(primary, nil)
	if errors.Is(err, leveldb.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	record, err := decodeRecord(data)
	if err != nil {
		return false, fmt.Errorf("decode stored message: %w", err)
	}
	pairKey := pairCounterKey(record.Sender, record.Recipient)
	inboxKey := inboxCounterKey(record.Recipient)
	pair, err := readCounter(s.db, pairKey)
	if err != nil {
		return false, err
	}
	inbox, err := readCounter(s.db, inboxKey)
	if err != nil {
		return false, err
	}
	node, err := readCounter(s.db, keyNodeCounter)
	if err != nil {
		return false, err
	}
	bodyBytes := int64(len(record.Body))
	pair.Count--
	pair.Bytes -= bodyBytes
	inbox.Count--
	inbox.Bytes -= bodyBytes
	node.Count--
	node.Bytes -= bodyBytes
	batch := new(leveldb.Batch)
	batch.Delete(primary)
	batch.Delete(indexKey(record.Recipient, record.MessageID))
	batch.Delete(expiryKey(record.ReceivedAt, primary))
	if pair.Count <= 0 {
		batch.Delete(pairKey)
	} else if err := putCounter(batch, pairKey, pair); err != nil {
		return false, err
	}
	if inbox.Count <= 0 {
		batch.Delete(inboxKey)
	} else if err := putCounter(batch, inboxKey, inbox); err != nil {
		return false, err
	}
	// Keep qn: at zero while deleting empty pair/inbox counters so Count can identify an initialized store.
	if err := putCounter(batch, keyNodeCounter, node); err != nil {
		return false, err
	}
	if err := s.db.Write(batch, nil); err != nil {
		return false, fmt.Errorf("delete message: %w", err)
	}
	return true, nil
}
