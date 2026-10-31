package messaging

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

var (
	prefixPrimary   = []byte("m2:")
	prefixIndex     = []byte("mi:")
	prefixExpiry    = []byte("ex:")
	prefixV1        = []byte("msg:")
	prefixMigration = []byte("mg:")
	prefixPair      = []byte("qp:")
	prefixInbox     = []byte("qr:")
	keyNodeCounter  = []byte("qn:")
	keyMetaSeq      = []byte("meta:seq")
	keyMetaSchema   = []byte("meta:schema")
)

func primaryPrefix(recipient, box string) []byte {
	key := make([]byte, 0, len(prefixPrimary)+len(recipient)+1+len(box))
	key = append(key, prefixPrimary...)
	key = append(key, recipient...)
	key = append(key, byte(len(box)))
	return append(key, box...)
}

func primaryKey(recipient, box string, seq uint64) []byte {
	key := primaryPrefix(recipient, box)
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], seq)
	return append(key, raw[:]...)
}

func indexKey(recipient, messageID string) []byte {
	key := make([]byte, 0, len(prefixIndex)+len(recipient)+len(messageID))
	key = append(key, prefixIndex...)
	key = append(key, recipient...)
	return append(key, messageID...)
}

func expiryKey(receivedAt int64, primary []byte) []byte {
	key := make([]byte, 0, len(prefixExpiry)+8+len(primary))
	key = append(key, prefixExpiry...)
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(receivedAt))
	key = append(key, raw[:]...)
	return append(key, primary...)
}

func expiryPrimary(key []byte) []byte {
	if len(key) < len(prefixExpiry)+8 {
		return nil
	}
	return append([]byte(nil), key[len(prefixExpiry)+8:]...)
}

func pairCounterKey(sender, recipient string) []byte {
	key := append([]byte(nil), prefixPair...)
	key = appendLP(key, sender)
	return append(key, recipient...)
}

func inboxCounterKey(recipient string) []byte {
	return append(append([]byte(nil), prefixInbox...), recipient...)
}

func appendLP(dst []byte, value string) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(len(value)))
	dst = append(dst, raw[:]...)
	return append(dst, value...)
}

func readUint64(db *leveldb.DB, key []byte) (uint64, error) {
	raw, err := db.Get(key, nil)
	if errors.Is(err, leveldb.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if len(raw) != 8 {
		return 0, errors.New("invalid uint64 metadata")
	}
	return binary.BigEndian.Uint64(raw), nil
}

func putUint64(batch *leveldb.Batch, key []byte, value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	batch.Put(key, raw[:])
}

func decodeHex(value string) ([]byte, error) { return hex.DecodeString(value) }

func (s *Store) expiredKeys(cutoff int64, limit int) ([][]byte, [][]byte) {
	keys := make([][]byte, 0)
	primaries := make([][]byte, 0)
	iter := s.db.NewIterator(util.BytesPrefix(prefixExpiry), nil)
	defer iter.Release()
	for iter.Next() {
		key := iter.Key()
		if len(key) < len(prefixExpiry)+8 {
			continue
		}
		receivedAt := int64(binary.BigEndian.Uint64(key[len(prefixExpiry):]))
		if receivedAt > cutoff {
			break
		}
		keys = append(keys, append([]byte(nil), key...))
		primaries = append(primaries, expiryPrimary(key))
		if len(keys) >= limit {
			break
		}
	}
	return keys, primaries
}
