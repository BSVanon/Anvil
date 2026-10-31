package messaging

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

var migrationTestHook func(inserted int) error

type v1Record struct {
	key       []byte
	timestamp int64
	messageID string
	recipient string
}

func (s *Store) migrate() error {
	schema, err := s.db.Get(keyMetaSchema, nil)
	if err == nil && bytes.Equal(schema, []byte("2")) {
		return nil
	}
	if err != nil && !errors.Is(err, leveldb.ErrNotFound) {
		return fmt.Errorf("read message schema: %w", err)
	}
	started := time.Now()
	records, undecodable, err := s.readV1Records()
	if err != nil {
		return err
	}
	if len(records) == 0 && undecodable == 0 {
		if err := s.db.Put(keyMetaSchema, []byte("2"), nil); err != nil {
			return fmt.Errorf("write message schema: %w", err)
		}
		return nil
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].timestamp != records[j].timestamp {
			return records[i].timestamp < records[j].timestamp
		}
		a, aErr := strconv.ParseUint(records[i].messageID, 10, 64)
		b, bErr := strconv.ParseUint(records[j].messageID, 10, 64)
		if aErr == nil && bErr == nil {
			return a < b
		}
		return records[i].messageID < records[j].messageID
	})
	now := s.now().Unix()
	inserted := 0
	unservable := 0
	deleteKeys := make([][]byte, 0, len(records))
	for i := range records {
		raw, getErr := s.db.Get(records[i].key, nil)
		if errors.Is(getErr, leveldb.ErrNotFound) {
			continue
		}
		if getErr != nil {
			return fmt.Errorf("read v1 message: %w", getErr)
		}
		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			undecodable++
			continue
		}
		recipient, err := normalizeRecipient(records[i].recipient)
		if err != nil || len(msg.MessageBox) == 0 || len(msg.MessageBox) > MaxMessageBoxBytes {
			unservable++
			continue
		}
		msg.Timestamp = records[i].timestamp
		msg.MessageID = records[i].messageID
		msg.Recipient = recipient
		idx := indexKey(msg.Recipient, msg.MessageID)
		primary, getErr := s.db.Get(idx, nil)
		if getErr == nil {
			ok, hasErr := s.db.Has(primary, nil)
			if hasErr != nil {
				return fmt.Errorf("read migration primary: %w", hasErr)
			}
			if ok {
				deleteKeys = append(deleteKeys, records[i].key)
				continue
			}
		} else if !errors.Is(getErr, leveldb.ErrNotFound) {
			return fmt.Errorf("read migration index: %w", getErr)
		}
		receivedAt := msg.Timestamp
		if receivedAt <= 0 || receivedAt > now {
			receivedAt = now
		}
		record := &StoredMessage{Message: msg, AttestedBy: "unknown", ReceivedAt: receivedAt}
		s.writeMu.Lock()
		err = s.insertLocked(record, false)
		s.writeMu.Unlock()
		if err != nil {
			return fmt.Errorf("migrate message %s: %w", msg.MessageID, err)
		}
		deleteKeys = append(deleteKeys, records[i].key)
		inserted++
		if migrationTestHook != nil {
			if err := migrationTestHook(inserted); err != nil {
				return err
			}
		}
	}
	for start := 0; start < len(deleteKeys); start += 1000 {
		end := start + 1000
		if end > len(deleteKeys) {
			end = len(deleteKeys)
		}
		batch := new(leveldb.Batch)
		for _, key := range deleteKeys[start:end] {
			batch.Delete(key)
		}
		if err := s.db.Write(batch, nil); err != nil {
			return fmt.Errorf("delete migrated v1 messages: %w", err)
		}
	}
	if err := s.db.Put(keyMetaSchema, []byte("2"), nil); err != nil {
		return fmt.Errorf("write message schema: %w", err)
	}
	log.Printf("messagebox store migrated: %d messages in %s (%d undecodable, %d unservable v1 records left in place)",
		len(deleteKeys), time.Since(started).Round(time.Millisecond), undecodable, unservable)
	return nil
}

func (s *Store) readV1Records() ([]v1Record, int, error) {
	records := make([]v1Record, 0)
	undecodable := 0
	iter := s.db.NewIterator(util.BytesPrefix(prefixV1), nil)
	defer iter.Release()
	for iter.Next() {
		var metadata struct {
			Timestamp int64  `json:"timestamp"`
			MessageID string `json:"messageId"`
			Recipient string `json:"recipient"`
		}
		if err := json.Unmarshal(iter.Value(), &metadata); err != nil {
			undecodable++
			continue
		}
		keyTail := string(iter.Key()[len(prefixV1):])
		if split := strings.IndexByte(keyTail, ':'); split >= 0 {
			metadata.Recipient = keyTail[:split]
			metadata.MessageID = keyTail[split+1:]
		}
		records = append(records, v1Record{
			key:       append([]byte(nil), iter.Key()...),
			timestamp: metadata.Timestamp,
			messageID: metadata.MessageID,
			recipient: metadata.Recipient,
		})
	}
	if err := iter.Error(); err != nil {
		return nil, undecodable, fmt.Errorf("iterate v1 messages: %w", err)
	}
	return records, undecodable, nil
}
