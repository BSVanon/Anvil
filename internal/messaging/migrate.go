package messaging

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const migrationIndexBatchSize = 1000

var (
	migrationPass1TestHook func(indexed int) error
	migrationTestHook      func(inserted int) error
)

type migrationCounts struct {
	inserted    int
	undecodable int
	unservable  int
	duplicate   int
}

type v1Metadata struct {
	Timestamp int64  `json:"timestamp"`
	MessageID string `json:"messageId"`
	Recipient string `json:"recipient"`
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
	counts := migrationCounts{}
	if err := s.buildMigrationIndex(&counts); err != nil {
		return err
	}
	if err := s.moveMigrationIndex(&counts); err != nil {
		return err
	}
	remaining, err := s.hasMigrationIndex()
	if err != nil {
		return err
	}
	if remaining {
		return errors.New("migration index was not fully processed")
	}
	if err := s.db.Put(keyMetaSchema, []byte("2"), nil); err != nil {
		return fmt.Errorf("write message schema: %w", err)
	}
	log.Printf("messagebox store migrated: %d messages in %s (%d undecodable, %d unservable, %d duplicate v1 records left in place)",
		counts.inserted, time.Since(started).Round(time.Millisecond), counts.undecodable, counts.unservable, counts.duplicate)
	return nil
}

func (s *Store) buildMigrationIndex(counts *migrationCounts) error {
	iter := s.db.NewIterator(util.BytesPrefix(prefixV1), nil)
	defer iter.Release()
	batch := new(leveldb.Batch)
	batched := 0
	indexed := 0
	flush := func() error {
		if batched == 0 {
			return nil
		}
		if err := s.db.Write(batch, nil); err != nil {
			return fmt.Errorf("write migration index: %w", err)
		}
		indexed += batched
		batch.Reset()
		batched = 0
		if migrationPass1TestHook != nil {
			return migrationPass1TestHook(indexed)
		}
		return nil
	}
	for iter.Next() {
		metadata, err := decodeV1Metadata(iter.Key(), iter.Value())
		if err != nil {
			counts.undecodable++
			continue
		}
		original := append([]byte(nil), iter.Key()...)
		batch.Put(migrationIndexKey(metadata.Timestamp, metadata.MessageID, original), original)
		batched++
		if batched == migrationIndexBatchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterate v1 messages: %w", err)
	}
	return flush()
}

func (s *Store) moveMigrationIndex(counts *migrationCounts) error {
	iter := s.db.NewIterator(util.BytesPrefix(prefixMigration), nil)
	defer iter.Release()
	now := s.now().Unix()
	for iter.Next() {
		migrationKey := append([]byte(nil), iter.Key()...)
		v1Key := append([]byte(nil), iter.Value()...)
		raw, err := s.db.Get(v1Key, nil)
		if errors.Is(err, leveldb.ErrNotFound) {
			if err := s.deleteMigrationKey(migrationKey); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("read v1 message: %w", err)
		}
		metadata, err := decodeV1Metadata(v1Key, raw)
		if err != nil {
			counts.undecodable++
			if err := s.deleteMigrationKey(migrationKey); err != nil {
				return err
			}
			continue
		}
		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			counts.undecodable++
			if err := s.deleteMigrationKey(migrationKey); err != nil {
				return err
			}
			continue
		}
		recipient, err := normalizeRecipient(metadata.Recipient)
		if err != nil || validateMessageBox(msg.MessageBox) != nil {
			counts.unservable++
			if err := s.deleteMigrationKey(migrationKey); err != nil {
				return err
			}
			continue
		}
		msg.Timestamp = metadata.Timestamp
		msg.MessageID = metadata.MessageID
		msg.Recipient = recipient
		if _, err := parseCompressedKey(msg.Sender); err == nil {
			msg.Sender = strings.ToLower(msg.Sender)
		}
		receivedAt := msg.Timestamp
		if receivedAt <= 0 || receivedAt > now {
			receivedAt = now
		}
		record := &StoredMessage{Message: msg, AttestedBy: "unknown", ReceivedAt: receivedAt}

		moved := false
		s.writeMu.Lock()
		_, indexErr := s.db.Get(indexKey(msg.Recipient, msg.MessageID), nil)
		if indexErr == nil {
			counts.duplicate++
			err = s.deleteMigrationKey(migrationKey)
		} else if !errors.Is(indexErr, leveldb.ErrNotFound) {
			err = fmt.Errorf("read migration index: %w", indexErr)
		} else {
			err = s.insertLockedWithDeletes(record, false, [][]byte{v1Key, migrationKey})
			if err == nil {
				counts.inserted++
				moved = true
			}
		}
		s.writeMu.Unlock()
		if err != nil {
			return fmt.Errorf("migrate message %s: %w", msg.MessageID, err)
		}
		if moved && migrationTestHook != nil {
			if err := migrationTestHook(counts.inserted); err != nil {
				return err
			}
		}
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterate migration index: %w", err)
	}
	return nil
}

func decodeV1Metadata(key, raw []byte) (v1Metadata, error) {
	var metadata v1Metadata
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return metadata, err
	}
	keyTail := string(key[len(prefixV1):])
	if split := strings.IndexByte(keyTail, ':'); split >= 0 {
		metadata.Recipient = keyTail[:split]
		metadata.MessageID = keyTail[split+1:]
	}
	return metadata, nil
}

func migrationIndexKey(timestamp int64, messageID string, original []byte) []byte {
	key := make([]byte, 0, len(prefixMigration)+8+1+8+4+len(messageID)+len(original))
	key = append(key, prefixMigration...)
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(timestamp)^(uint64(1)<<63))
	key = append(key, raw[:]...)
	if numeric, ok := decimalUint64(messageID); ok {
		key = append(key, 0)
		binary.BigEndian.PutUint64(raw[:], numeric)
		key = append(key, raw[:]...)
	} else {
		key = append(key, 1)
		key = appendLP(key, messageID)
	}
	return append(key, original...)
}

func decimalUint64(value string) (uint64, bool) {
	if value == "" {
		return 0, false
	}
	for i := range value {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	return n, err == nil
}

func (s *Store) deleteMigrationKey(key []byte) error {
	batch := new(leveldb.Batch)
	batch.Delete(key)
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("delete migration index: %w", err)
	}
	return nil
}

func (s *Store) hasMigrationIndex() (bool, error) {
	iter := s.db.NewIterator(util.BytesPrefix(prefixMigration), nil)
	defer iter.Release()
	remaining := iter.Next()
	if err := iter.Error(); err != nil {
		return false, fmt.Errorf("inspect migration index: %w", err)
	}
	return remaining, nil
}
