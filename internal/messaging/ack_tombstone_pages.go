package messaging

import "github.com/syndtr/goleveldb/leveldb/util"

// ForEachAcknowledgementPage streams persistent acknowledgement IDs for one
// recipient. It is used by private-home reconnect anti-entropy.
func (s *Store) ForEachAcknowledgementPage(recipient string, size int, fn func([]string) error) error {
	recipient, err := normalizeRecipient(recipient)
	if err != nil {
		return err
	}
	if size < 1 {
		size = 1
	}
	s.expireAckTombstones()
	prefix := ackRecipientPrefix(recipient)
	iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()
	page := make([]string, 0, size)
	messageOffset := len(prefix) + 8
	for iter.Next() {
		if len(iter.Key()) <= messageOffset {
			continue
		}
		page = append(page, string(iter.Key()[messageOffset:]))
		if len(page) == size {
			if err := fn(append([]string(nil), page...)); err != nil {
				return err
			}
			page = page[:0]
		}
	}
	if err := iter.Error(); err != nil {
		return err
	}
	if len(page) > 0 {
		return fn(page)
	}
	return nil
}
