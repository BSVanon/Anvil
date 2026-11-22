package messaging

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// PrivateHomeRevocation is a trusted replay cutoff synchronized between
// allowed gateways. It is kept separately from evictable member releases.
type PrivateHomeRevocation struct {
	Member         string
	BeforeIssuedAt int64
}

// CurrentClaims reads a bounded set of claim versions under one writer lock.
// It is used to acknowledge an applied mesh page without reacquiring the lock
// once per record.
func (s *PrivateHomeStore) CurrentClaims(members []string) (map[string]PrivateHomeRecord, error) {
	claims := make(map[string]PrivateHomeRecord, len(members))
	if s == nil || s.messages == nil {
		return claims, nil
	}
	s.messages.writeMu.Lock()
	defer s.messages.writeMu.Unlock()
	if err := s.prepareLocked(); err != nil {
		return nil, err
	}
	for _, member := range members {
		member = strings.ToLower(member)
		if _, seen := claims[member]; seen {
			continue
		}
		record, ok, err := s.recordLocked(member)
		if err != nil {
			return nil, err
		}
		if ok && record.Kind == PrivateHomeClaim {
			claims[member] = record
		}
	}
	return claims, nil
}

// RevokeMember removes a current claim and leaves a trusted replay cutoff.
func (s *PrivateHomeStore) RevokeMember(member string) (int64, bool, error) {
	member = strings.ToLower(member)
	if s == nil || s.messages == nil {
		return 0, false, errors.New("private home store unavailable")
	}
	s.messages.writeMu.Lock()
	defer s.messages.writeMu.Unlock()
	if err := s.prepareLocked(); err != nil {
		return 0, false, err
	}
	record, ok, err := s.recordLocked(member)
	if err != nil || !ok || record.Kind != PrivateHomeClaim {
		return 0, false, err
	}
	changed, err := s.applyRevocationLocked(member, record.IssuedAt)
	return record.IssuedAt, changed, err
}

// ApplyRevocation applies an allowed operator's unsigned cutoff. Trusted
// cutoffs occupy the member's registry slot until every covered claim must be
// expired and are never evicted by signed release pressure.
func (s *PrivateHomeStore) ApplyRevocation(member string, beforeIssuedAt int64) (bool, error) {
	if s == nil || s.messages == nil {
		return false, errors.New("private home store unavailable")
	}
	member = strings.ToLower(member)
	if _, err := strictCompressedKey(member); err != nil || beforeIssuedAt <= 0 ||
		beforeIssuedAt > s.now().Add(privateHomeMaxFuture).UnixMilli() {
		return false, ErrPrivateHomeInvalid
	}
	s.messages.writeMu.Lock()
	defer s.messages.writeMu.Unlock()
	if err := s.prepareLocked(); err != nil {
		return false, err
	}
	return s.applyRevocationLocked(member, beforeIssuedAt)
}

func (s *PrivateHomeStore) applyRevocationLocked(member string, cutoff int64) (bool, error) {
	prior, hadPrior, err := s.revocationLocked(member)
	if err != nil {
		return false, err
	}
	if hadPrior && prior >= cutoff {
		return false, nil
	}
	old, exists, err := s.recordLocked(member)
	if err != nil {
		return false, err
	}
	unionExists := hadPrior || (exists && old.Kind == PrivateHomeClaim)
	if !unionExists && s.activeIdentities >= s.maxMembers {
		return false, ErrPrivateHomeLimit
	}

	batch := new(leveldb.Batch)
	batch.Put(privateHomeRevocationKey(member), encodePrivateHomeCutoff(cutoff))
	heapEntry := privateHomeExpiry{at: cutoff/1000 + s.maxTTL, member: member, kind: privateHomeExpiryRevocation}
	pushPrivateHomeExpiry(&s.expirations, heapEntry)
	if !unionExists {
		s.activeIdentities++
	}
	if exists && old.IssuedAt <= cutoff {
		s.accountRecordRemovalLocked(old, true, true)
		tombstone := PrivateHomeRecord{
			Kind: PrivateHomeRelease, Member: member, Homes: []string{}, IssuedAt: cutoff,
		}
		raw, marshalErr := json.Marshal(tombstone)
		if marshalErr != nil {
			return false, marshalErr
		}
		batch.Put(privateHomeRecordKey(member), raw)
		batch.Delete(privateHomeAdmissionKey(member))
		s.accountRecordAdditionLocked(tombstone, true)
		s.pushRecordExpiry(tombstone)
	}
	if err := s.messages.db.Write(batch, nil); err != nil {
		s.initialized = false
		return false, err
	}
	return true, nil
}

// Records returns current primary records in member order. Synchronization uses
// ForEachRecordPage directly and does not materialize this slice.
func (s *PrivateHomeStore) Records() ([]PrivateHomeRecord, error) {
	var records []PrivateHomeRecord
	err := s.ForEachRecordPage(200, func(page []PrivateHomeRecord) error {
		records = append(records, page...)
		return nil
	})
	return records, err
}

// ForEachRecordPage streams current primary records in key order.
func (s *PrivateHomeStore) ForEachRecordPage(size int, fn func([]PrivateHomeRecord) error) error {
	if s == nil || s.messages == nil {
		return nil
	}
	if size < 1 {
		size = 1
	}
	s.messages.writeMu.Lock()
	if err := s.prepareLocked(); err != nil {
		s.messages.writeMu.Unlock()
		return err
	}
	s.messages.writeMu.Unlock()
	iter := s.messages.db.NewIterator(util.BytesPrefix(privateHomeRecordPrefix), nil)
	defer iter.Release()
	page := make([]PrivateHomeRecord, 0, size)
	for iter.Next() {
		var record PrivateHomeRecord
		if json.Unmarshal(iter.Value(), &record) != nil {
			continue
		}
		page = append(page, record)
		if len(page) == size {
			if err := fn(append([]PrivateHomeRecord(nil), page...)); err != nil {
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

// ForEachRevocationPage streams every trusted cutoff, including one hidden by
// a newer signed claim, so reconnecting peers retain the replay high-water mark.
func (s *PrivateHomeStore) ForEachRevocationPage(size int, fn func([]PrivateHomeRevocation) error) error {
	if s == nil || s.messages == nil {
		return nil
	}
	if size < 1 {
		size = 1
	}
	iter := s.messages.db.NewIterator(util.BytesPrefix(privateHomeRevokedPrefix), nil)
	defer iter.Release()
	page := make([]PrivateHomeRevocation, 0, size)
	for iter.Next() {
		cutoff, ok := decodePrivateHomeCutoff(iter.Value())
		if !ok {
			continue
		}
		page = append(page, PrivateHomeRevocation{
			Member: string(iter.Key()[len(privateHomeRevokedPrefix):]), BeforeIssuedAt: cutoff,
		})
		if len(page) == size {
			if err := fn(append([]PrivateHomeRevocation(nil), page...)); err != nil {
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

// Admissions returns durable local certificate bindings for startup repair.
func (s *PrivateHomeStore) Admissions() ([]PrivateHomeAdmission, error) {
	if s == nil || s.messages == nil {
		return nil, nil
	}
	iter := s.messages.db.NewIterator(util.BytesPrefix(privateHomeAdmissionPrefix), nil)
	defer iter.Release()
	var admissions []PrivateHomeAdmission
	for iter.Next() {
		var admission PrivateHomeAdmission
		if json.Unmarshal(iter.Value(), &admission) == nil {
			admissions = append(admissions, admission)
		}
	}
	return admissions, iter.Error()
}

func (s *PrivateHomeStore) DeleteAdmission(member string) error {
	if s == nil || s.messages == nil {
		return nil
	}
	return s.messages.db.Delete(privateHomeAdmissionKey(strings.ToLower(member)), nil)
}
