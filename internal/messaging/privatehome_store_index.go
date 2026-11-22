package messaging

import (
	"container/heap"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

var privateHomeExpiryChunk = 1000

type privateHomeExpiry struct {
	at     int64
	member string
	kind   byte
}

type privateHomeExpiryHeap []privateHomeExpiry

func pushPrivateHomeExpiry(h *privateHomeExpiryHeap, entry privateHomeExpiry) {
	heap.Push(h, entry)
}

func (h privateHomeExpiryHeap) Len() int { return len(h) }
func (h privateHomeExpiryHeap) Less(i, j int) bool {
	if h[i].at != h[j].at {
		return h[i].at < h[j].at
	}
	if h[i].member != h[j].member {
		return h[i].member < h[j].member
	}
	return h[i].kind < h[j].kind
}
func (h privateHomeExpiryHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *privateHomeExpiryHeap) Push(value any) {
	*h = append(*h, value.(privateHomeExpiry))
}
func (h *privateHomeExpiryHeap) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}

const (
	privateHomeExpiryRecord     byte = 'r'
	privateHomeExpiryRevocation byte = 'v'
)

func (s *PrivateHomeStore) prepareLocked() error {
	if !s.initialized {
		if err := s.rebuildIndexesLocked(); err != nil {
			return err
		}
	}
	return s.expireLocked()
}

func (s *PrivateHomeStore) rebuildIndexesLocked() error {
	if s.onFullScan != nil {
		s.onFullScan()
	}
	s.claims, s.ordinaryTombstones, s.activeIdentities = 0, 0, 0
	s.primaryRecords, s.revocations = 0, 0
	s.expirations, s.ordinaryExpiries = nil, nil
	batch := new(leveldb.Batch)
	changed := false
	revoked := make(map[string]int64)

	markers := s.messages.db.NewIterator(util.BytesPrefix(privateHomeRevokedPrefix), nil)
	for markers.Next() {
		member := string(markers.Key()[len(privateHomeRevokedPrefix):])
		cutoff, ok := decodePrivateHomeCutoff(markers.Value())
		if !ok {
			batch.Delete(append([]byte(nil), markers.Key()...))
			changed = true
			continue
		}
		revoked[member] = cutoff
		s.revocations++
		s.activeIdentities++
		heap.Push(&s.expirations, privateHomeExpiry{at: cutoff/1000 + s.maxTTL, member: member, kind: privateHomeExpiryRevocation})
	}
	markerErr := markers.Error()
	markers.Release()
	if markerErr != nil {
		return markerErr
	}

	records := s.messages.db.NewIterator(util.BytesPrefix(privateHomeRecordPrefix), nil)
	for records.Next() {
		var record PrivateHomeRecord
		if json.Unmarshal(records.Value(), &record) != nil {
			batch.Delete(append([]byte(nil), records.Key()...))
			member := string(records.Key()[len(privateHomeRecordPrefix):])
			batch.Delete(privateHomeAdmissionKey(member))
			changed = true
			continue
		}
		s.primaryRecords++
		_, hasRevocation := revoked[record.Member]
		if record.Kind == PrivateHomeRelease && record.Signature == "" && !hasRevocation {
			// Migrate trusted cutoffs written by the first private-home store
			// format, which represented them only as unsigned primary records.
			revoked[record.Member] = record.IssuedAt
			hasRevocation = true
			s.revocations++
			s.activeIdentities++
			batch.Put(privateHomeRevocationKey(record.Member), encodePrivateHomeCutoff(record.IssuedAt))
			heap.Push(&s.expirations, privateHomeExpiry{
				at: record.IssuedAt/1000 + s.maxTTL, member: record.Member, kind: privateHomeExpiryRevocation,
			})
			changed = true
		}
		s.accountRecordAdditionLocked(record, hasRevocation)
		s.pushRecordExpiry(record)
	}
	recordErr := records.Error()
	records.Release()
	if recordErr != nil {
		return recordErr
	}
	if changed {
		if err := s.messages.db.Write(batch, nil); err != nil {
			return err
		}
	}
	s.initialized = true
	return nil
}

func (s *PrivateHomeStore) expireLocked() error {
	now := s.now().Unix()
	batch := new(leveldb.Batch)
	changed := false
	deletedRecords := make(map[string]struct{})
	deletedRevocations := make(map[string]struct{})
	processed := 0
	for processed < privateHomeExpiryChunk && s.expirations.Len() > 0 && s.expirations[0].at <= now {
		entry := heap.Pop(&s.expirations).(privateHomeExpiry)
		processed++
		switch entry.kind {
		case privateHomeExpiryRecord:
			if _, deleted := deletedRecords[entry.member]; deleted {
				continue
			}
			record, exists, err := s.recordLocked(entry.member)
			if err != nil {
				return err
			}
			if !exists || s.recordExpiry(record) != entry.at || entry.at > now {
				continue
			}
			_, revoked, err := s.revocationLocked(entry.member)
			if err != nil {
				return err
			}
			if _, deleted := deletedRevocations[entry.member]; deleted {
				revoked = false
			}
			s.accountRecordRemovalLocked(record, true, revoked)
			s.primaryRecords--
			batch.Delete(privateHomeRecordKey(entry.member))
			batch.Delete(privateHomeAdmissionKey(entry.member))
			deletedRecords[entry.member] = struct{}{}
			changed = true
		case privateHomeExpiryRevocation:
			if _, deleted := deletedRevocations[entry.member]; deleted {
				continue
			}
			cutoff, exists, err := s.revocationLocked(entry.member)
			if err != nil {
				return err
			}
			if !exists || cutoff/1000+s.maxTTL != entry.at || entry.at > now {
				continue
			}
			record, current, err := s.recordLocked(entry.member)
			if err != nil {
				return err
			}
			_, recordDeleted := deletedRecords[entry.member]
			if !current || record.Kind != PrivateHomeClaim || recordDeleted {
				s.activeIdentities--
			}
			s.revocations--
			batch.Delete(privateHomeRevocationKey(entry.member))
			deletedRevocations[entry.member] = struct{}{}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := s.messages.db.Write(batch, nil); err != nil {
		s.initialized = false
		return err
	}
	for member := range deletedRecords {
		s.notifyAdmissionRemoved(member)
		s.notifyRecordChanged(member, 0)
	}
	return nil
}

func (s *PrivateHomeStore) accountRecordRemovalLocked(record PrivateHomeRecord, exists, revoked bool) {
	if !exists {
		return
	}
	if record.Kind == PrivateHomeClaim {
		s.claims--
		if !revoked {
			s.activeIdentities--
		}
	} else if record.Signature != "" {
		s.ordinaryTombstones--
	}
}

func (s *PrivateHomeStore) accountRecordAdditionLocked(record PrivateHomeRecord, revoked bool) {
	if record.Kind == PrivateHomeClaim {
		s.claims++
		if !revoked {
			s.activeIdentities++
		}
	} else if record.Signature != "" {
		s.ordinaryTombstones++
	}
}

func (s *PrivateHomeStore) pushRecordExpiry(record PrivateHomeRecord) {
	entry := privateHomeExpiry{at: s.recordExpiry(record), member: record.Member, kind: privateHomeExpiryRecord}
	heap.Push(&s.expirations, entry)
	if record.Kind == PrivateHomeRelease && record.Signature != "" {
		heap.Push(&s.ordinaryExpiries, entry)
	}
}

func (s *PrivateHomeStore) compactExpiryHeapsLocked() error {
	recordLimit := 2*(s.primaryRecords+s.revocations) + 64
	ordinaryLimit := 2*s.ordinaryTombstones + 64
	if s.expirations.Len() <= recordLimit && s.ordinaryExpiries.Len() <= ordinaryLimit {
		return nil
	}
	expirations := make(privateHomeExpiryHeap, 0, s.primaryRecords+s.revocations)
	ordinary := make(privateHomeExpiryHeap, 0, s.ordinaryTombstones)
	markers := s.messages.db.NewIterator(util.BytesPrefix(privateHomeRevokedPrefix), nil)
	for markers.Next() {
		member := string(markers.Key()[len(privateHomeRevokedPrefix):])
		if cutoff, ok := decodePrivateHomeCutoff(markers.Value()); ok {
			expirations = append(expirations, privateHomeExpiry{
				at: cutoff/1000 + s.maxTTL, member: member, kind: privateHomeExpiryRevocation,
			})
		}
	}
	markerErr := markers.Error()
	markers.Release()
	if markerErr != nil {
		return markerErr
	}
	records := s.messages.db.NewIterator(util.BytesPrefix(privateHomeRecordPrefix), nil)
	for records.Next() {
		var record PrivateHomeRecord
		if json.Unmarshal(records.Value(), &record) != nil {
			continue
		}
		entry := privateHomeExpiry{at: s.recordExpiry(record), member: record.Member, kind: privateHomeExpiryRecord}
		expirations = append(expirations, entry)
		if record.Kind == PrivateHomeRelease && record.Signature != "" {
			ordinary = append(ordinary, entry)
		}
	}
	recordErr := records.Error()
	records.Release()
	if recordErr != nil {
		return recordErr
	}
	heap.Init(&expirations)
	heap.Init(&ordinary)
	s.expirations, s.ordinaryExpiries = expirations, ordinary
	return nil
}

func (s *PrivateHomeStore) recordExpiry(record PrivateHomeRecord) int64 {
	if record.Kind == PrivateHomeClaim {
		return record.ExpiresAt
	}
	return record.IssuedAt/1000 + s.maxTTL
}

func (s *PrivateHomeStore) evictOldestOrdinaryLocked(batch *leveldb.Batch, replacingMember string, pending *privateHomeBatchState) error {
	for s.ordinaryExpiries.Len() > 0 {
		entry := heap.Pop(&s.ordinaryExpiries).(privateHomeExpiry)
		if entry.member == replacingMember {
			continue
		}
		if pending != nil {
			if _, protected := pending.protected[entry.member]; protected {
				continue
			}
			if _, deleted := pending.deleted[entry.member]; deleted {
				continue
			}
		}
		record, exists, err := s.recordLocked(entry.member)
		if err != nil {
			return err
		}
		if !exists || record.Kind != PrivateHomeRelease || record.Signature == "" || s.recordExpiry(record) != entry.at {
			continue
		}
		batch.Delete(privateHomeRecordKey(entry.member))
		batch.Delete(privateHomeAdmissionKey(entry.member))
		if pending != nil {
			pending.deleted[entry.member] = struct{}{}
		}
		s.ordinaryTombstones--
		s.primaryRecords--
		return nil
	}
	return ErrPrivateHomeLimit
}

func (s *PrivateHomeStore) revocationLocked(member string) (int64, bool, error) {
	raw, err := s.messages.db.Get(privateHomeRevocationKey(member), nil)
	if errors.Is(err, leveldb.ErrNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	cutoff, ok := decodePrivateHomeCutoff(raw)
	if !ok {
		return 0, false, fmt.Errorf("decode private home revocation")
	}
	return cutoff, true, nil
}

func encodePrivateHomeCutoff(cutoff int64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(cutoff))
	return raw[:]
}

func decodePrivateHomeCutoff(raw []byte) (int64, bool) {
	if len(raw) != 8 {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(raw)), true
}

func privateHomeRecordKey(member string) []byte {
	return append(append([]byte(nil), privateHomeRecordPrefix...), member...)
}

func privateHomeRevocationKey(member string) []byte {
	return append(append([]byte(nil), privateHomeRevokedPrefix...), member...)
}

func privateHomeAdmissionKey(member string) []byte {
	return append(append([]byte(nil), privateHomeAdmissionPrefix...), member...)
}
