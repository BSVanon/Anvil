package messaging

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const (
	maxAckTombstonesPerRecipient = uint64(10_000)
	maxAckTombstonesTotal        = uint64(1_000_000)
)

var ackTombstoneExpiryChunk = 1000

var (
	prefixAckPrimary   = []byte("ak:p:")
	prefixAckRecipient = []byte("ak:r:")
	prefixAckGlobal    = []byte("ak:g:")
	prefixAckCount     = []byte("ak:c:")
	keyAckTotal        = []byte("ak:total")
)

func (s *Store) acknowledgedLocked(recipient, messageID string) (bool, error) {
	primary := ackPrimaryKey(recipient, messageID)
	raw, err := s.db.Get(primary, nil)
	if errors.Is(err, leveldb.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read acknowledgement tombstone: %w", err)
	}
	if len(raw) != 8 {
		return false, s.removeAckTombstoneLocked(primary, 0)
	}
	acknowledgedAt := int64(binary.BigEndian.Uint64(raw))
	if acknowledgedAt > s.now().Unix()-s.opts.TTLSeconds {
		return true, nil
	}
	return false, s.removeAckTombstoneLocked(primary, acknowledgedAt)
}

func (s *Store) putAckTombstonesLocked(recipient string, ids []string) error {
	for _, id := range ids {
		if err := s.putAckTombstoneLocked(recipient, id, s.now().Unix()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) putAckTombstoneLocked(recipient, messageID string, acknowledgedAt int64) error {
	primary := ackPrimaryKey(recipient, messageID)
	raw, err := s.db.Get(primary, nil)
	exists := err == nil
	if err != nil && !errors.Is(err, leveldb.ErrNotFound) {
		return err
	}
	oldAcknowledgedAt := int64(0)
	if exists && len(raw) == 8 {
		oldAcknowledgedAt = int64(binary.BigEndian.Uint64(raw))
	}
	if !exists {
		for {
			count, err := readUint64(s.db, ackCountKey(recipient))
			if err != nil {
				return err
			}
			if count < maxAckTombstonesPerRecipient {
				break
			}
			if err := s.evictOldestAckForRecipientLocked(recipient); err != nil {
				return err
			}
		}
		for {
			total, err := readUint64(s.db, keyAckTotal)
			if err != nil {
				return err
			}
			if total < maxAckTombstonesTotal {
				break
			}
			if err := s.evictOldestAckLocked(); err != nil {
				return err
			}
		}
	}

	batch := new(leveldb.Batch)
	if oldAcknowledgedAt != 0 {
		batch.Delete(ackRecipientKey(recipient, oldAcknowledgedAt, messageID))
		batch.Delete(ackGlobalKey(oldAcknowledgedAt, recipient, messageID))
	}
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(acknowledgedAt))
	batch.Put(primary, stamp[:])
	batch.Put(ackRecipientKey(recipient, acknowledgedAt, messageID), primary)
	batch.Put(ackGlobalKey(acknowledgedAt, recipient, messageID), primary)
	if !exists {
		count, err := readUint64(s.db, ackCountKey(recipient))
		if err != nil {
			return err
		}
		total, err := readUint64(s.db, keyAckTotal)
		if err != nil {
			return err
		}
		putUint64(batch, ackCountKey(recipient), count+1)
		putUint64(batch, keyAckTotal, total+1)
	}
	return s.db.Write(batch, nil)
}

func (s *Store) evictOldestAckForRecipientLocked(recipient string) error {
	iter := s.db.NewIterator(util.BytesPrefix(ackRecipientPrefix(recipient)), nil)
	defer iter.Release()
	if !iter.Next() {
		return errors.New("acknowledgement recipient count is inconsistent")
	}
	primary := append([]byte(nil), iter.Value()...)
	return s.removeAckTombstoneLocked(primary, ackTimestampFromIndex(iter.Key(), len(prefixAckRecipient)+66))
}

func (s *Store) evictOldestAckLocked() error {
	iter := s.db.NewIterator(util.BytesPrefix(prefixAckGlobal), nil)
	defer iter.Release()
	if !iter.Next() {
		return errors.New("acknowledgement total count is inconsistent")
	}
	primary := append([]byte(nil), iter.Value()...)
	return s.removeAckTombstoneLocked(primary, ackTimestampFromIndex(iter.Key(), len(prefixAckGlobal)))
}

func (s *Store) removeAckTombstoneLocked(primary []byte, acknowledgedAt int64) error {
	recipient, messageID, ok := splitAckPrimary(primary)
	if !ok {
		return nil
	}
	if acknowledgedAt == 0 {
		raw, err := s.db.Get(primary, nil)
		if err == nil && len(raw) == 8 {
			acknowledgedAt = int64(binary.BigEndian.Uint64(raw))
		}
	}
	count, err := readUint64(s.db, ackCountKey(recipient))
	if err != nil {
		return err
	}
	total, err := readUint64(s.db, keyAckTotal)
	if err != nil {
		return err
	}
	batch := new(leveldb.Batch)
	batch.Delete(primary)
	batch.Delete(ackRecipientKey(recipient, acknowledgedAt, messageID))
	batch.Delete(ackGlobalKey(acknowledgedAt, recipient, messageID))
	if count <= 1 {
		batch.Delete(ackCountKey(recipient))
	} else {
		putUint64(batch, ackCountKey(recipient), count-1)
	}
	if total <= 1 {
		batch.Delete(keyAckTotal)
	} else {
		putUint64(batch, keyAckTotal, total-1)
	}
	return s.db.Write(batch, nil)
}

func (s *Store) expireAckTombstones() {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	cutoff := s.now().Unix() - s.opts.TTLSeconds
	limit := ackTombstoneExpiryChunk
	if limit < 1 {
		limit = 1
	}
	iter := s.db.NewIterator(util.BytesPrefix(prefixAckGlobal), nil)
	batch := new(leveldb.Batch)
	removedByRecipient := make(map[string]uint64)
	removed := uint64(0)
	for removed < uint64(limit) && iter.Next() {
		acknowledgedAt := ackTimestampFromIndex(iter.Key(), len(prefixAckGlobal))
		if acknowledgedAt > cutoff {
			break
		}
		primary := append([]byte(nil), iter.Value()...)
		recipient, messageID, ok := splitAckPrimary(primary)
		if !ok {
			continue
		}
		batch.Delete(primary)
		batch.Delete(ackRecipientKey(recipient, acknowledgedAt, messageID))
		batch.Delete(append([]byte(nil), iter.Key()...))
		removedByRecipient[recipient]++
		removed++
	}
	iterErr := iter.Error()
	iter.Release()
	if iterErr != nil || removed == 0 {
		return
	}
	for recipient, countRemoved := range removedByRecipient {
		count, err := readUint64(s.db, ackCountKey(recipient))
		if err != nil {
			return
		}
		if count <= countRemoved {
			batch.Delete(ackCountKey(recipient))
		} else {
			putUint64(batch, ackCountKey(recipient), count-countRemoved)
		}
	}
	total, err := readUint64(s.db, keyAckTotal)
	if err != nil {
		return
	}
	if total <= removed {
		batch.Delete(keyAckTotal)
	} else {
		putUint64(batch, keyAckTotal, total-removed)
	}
	_ = s.db.Write(batch, nil)
}

func ackPrimaryKey(recipient, messageID string) []byte {
	key := append(append([]byte(nil), prefixAckPrimary...), recipient...)
	return append(key, messageID...)
}

func ackRecipientPrefix(recipient string) []byte {
	return append(append([]byte(nil), prefixAckRecipient...), recipient...)
}

func ackRecipientKey(recipient string, acknowledgedAt int64, messageID string) []byte {
	key := ackRecipientPrefix(recipient)
	return appendAckTimestampAndID(key, acknowledgedAt, messageID)
}

func ackGlobalKey(acknowledgedAt int64, recipient, messageID string) []byte {
	key := appendAckTimestampAndID(append([]byte(nil), prefixAckGlobal...), acknowledgedAt, recipient)
	return append(key, messageID...)
}

func ackCountKey(recipient string) []byte {
	return append(append([]byte(nil), prefixAckCount...), recipient...)
}

func appendAckTimestampAndID(key []byte, timestamp int64, id string) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(timestamp))
	key = append(key, raw[:]...)
	return append(key, id...)
}

func ackTimestampFromIndex(key []byte, offset int) int64 {
	if len(key) < offset+8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(key[offset : offset+8]))
}

func splitAckPrimary(key []byte) (string, string, bool) {
	offset := len(prefixAckPrimary)
	if len(key) < offset+66 {
		return "", "", false
	}
	return string(key[offset : offset+66]), string(key[offset+66:]), true
}
