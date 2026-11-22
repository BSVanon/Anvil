package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

var (
	privateHomeRecordPrefix    = []byte("ph:r:")
	privateHomeRevokedPrefix   = []byte("ph:v:")
	privateHomeAdmissionPrefix = []byte("ph:a:")
)

// PrivateHomeOptions controls the bounded private-home registry.
type PrivateHomeOptions struct {
	MaxMembers   int
	MaxTTL       int64
	AllowedHomes []string
	Now          func() time.Time
}

// PrivateHomeAdmission durably binds a locally admitted claim to the
// revocation outpoint that authorized it.
type PrivateHomeAdmission struct {
	Member   string `json:"member"`
	IssuedAt int64  `json:"issuedAt"`
	Outpoint string `json:"outpoint"`
}

// PrivateHomeStore persists private claims in the message store database.
// Counters and expiry heaps are rebuilt once per process, then mutations are
// O(log n) apart from signature verification and the caller's batch size.
type PrivateHomeStore struct {
	messages   *Store
	verifier   *PrivateHomeVerifier
	maxMembers int
	maxTTL     int64
	now        func() time.Time

	initialized        bool
	claims             int
	ordinaryTombstones int
	activeIdentities   int
	expirations        privateHomeExpiryHeap
	ordinaryExpiries   privateHomeExpiryHeap
	onFullScan         func()
}

func NewPrivateHomeStore(messages *Store, opts PrivateHomeOptions) *PrivateHomeStore {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if opts.MaxMembers < 1 {
		opts.MaxMembers = 1
	}
	return &PrivateHomeStore{
		messages: messages, verifier: newPrivateHomeVerifier(opts.MaxTTL, opts.AllowedHomes, now),
		maxMembers: opts.MaxMembers, maxTTL: opts.MaxTTL, now: now,
	}
}

// Validate verifies a record without changing persistent state.
func (s *PrivateHomeStore) Validate(ctx context.Context, record PrivateHomeRecord) error {
	if s == nil || s.verifier == nil {
		return errors.New("private home store unavailable")
	}
	return s.verifier.Validate(ctx, record)
}

// Apply verifies and stores a newer signed claim or release.
func (s *PrivateHomeStore) Apply(ctx context.Context, record PrivateHomeRecord) error {
	return s.applyOne(ctx, record, nil, nil)
}

// ApplyAdmitted stores a local claim with the certificate admission that
// authorized it. A release removes any earlier binding.
func (s *PrivateHomeStore) ApplyAdmitted(ctx context.Context, record PrivateHomeRecord, outpoint string) error {
	binding := &PrivateHomeAdmission{Member: record.Member, IssuedAt: record.IssuedAt, Outpoint: outpoint}
	return s.applyOne(ctx, record, binding, nil)
}

// ApplyLocal validates once, checks live gateway compatibility, and persists an
// optional certificate admission binding. A nil outpoint means certgate is off;
// a non-nil pointer to an empty string is an unrevocable admission.
func (s *PrivateHomeStore) ApplyLocal(ctx context.Context, record PrivateHomeRecord, outpoint *string, compatible func([]string) bool) error {
	var binding *PrivateHomeAdmission
	if outpoint != nil {
		binding = &PrivateHomeAdmission{Member: record.Member, IssuedAt: record.IssuedAt, Outpoint: *outpoint}
	}
	return s.applyOne(ctx, record, binding, compatible)
}

func (s *PrivateHomeStore) applyOne(ctx context.Context, record PrivateHomeRecord, binding *PrivateHomeAdmission, compatible func([]string) bool) error {
	if s == nil || s.messages == nil {
		return errors.New("private home store unavailable")
	}
	if err := s.Validate(ctx, record); err != nil {
		return err
	}
	if record.Kind == PrivateHomeClaim && compatible != nil && !compatible(record.Homes) {
		return ErrPrivateHomeIncompatible
	}
	s.messages.writeMu.Lock()
	defer s.messages.writeMu.Unlock()
	if err := s.prepareLocked(); err != nil {
		return err
	}
	batch := new(leveldb.Batch)
	if err := s.applySignedLocked(record, binding, batch); err != nil {
		return err
	}
	if err := s.messages.db.Write(batch, nil); err != nil {
		s.initialized = false
		return fmt.Errorf("store private home record: %w", err)
	}
	return nil
}

// ApplyBatch validates a control page outside the writer lock, then applies it
// with one expiry pass and one LevelDB batch. Results align with records.
func (s *PrivateHomeStore) ApplyBatch(ctx context.Context, records []PrivateHomeRecord) []error {
	results := make([]error, len(records))
	latest := make(map[string]int, len(records))
	for i, record := range records {
		if err := s.Validate(ctx, record); err != nil {
			results[i] = err
			continue
		}
		if previous, ok := latest[record.Member]; ok {
			if records[previous].IssuedAt >= record.IssuedAt {
				results[i] = ErrPrivateHomeStale
				continue
			}
			results[previous] = ErrPrivateHomeStale
		}
		latest[record.Member] = i
	}
	if s == nil || s.messages == nil {
		return fillPrivateHomeErrors(results, errors.New("private home store unavailable"))
	}

	s.messages.writeMu.Lock()
	defer s.messages.writeMu.Unlock()
	if err := s.prepareLocked(); err != nil {
		return fillPrivateHomeErrors(results, err)
	}
	batch := new(leveldb.Batch)
	accepted := 0
	for i, record := range records {
		if results[i] == nil {
			results[i] = s.applySignedLocked(record, nil, batch)
			if results[i] == nil {
				accepted++
			}
		}
	}
	if accepted == 0 {
		return results
	}
	if err := s.messages.db.Write(batch, nil); err != nil {
		s.initialized = false
		return fillPrivateHomeErrors(results, fmt.Errorf("store private home record: %w", err))
	}
	return results
}

func fillPrivateHomeErrors(results []error, err error) []error {
	for i := range results {
		if results[i] == nil {
			results[i] = err
		}
	}
	return results
}

func (s *PrivateHomeStore) applySignedLocked(record PrivateHomeRecord, binding *PrivateHomeAdmission, batch *leveldb.Batch) error {
	old, exists, err := s.recordLocked(record.Member)
	if err != nil {
		return err
	}
	if exists && record.IssuedAt <= old.IssuedAt {
		return ErrPrivateHomeStale
	}
	cutoff, revoked, err := s.revocationLocked(record.Member)
	if err != nil {
		return err
	}
	if revoked && record.IssuedAt <= cutoff {
		return ErrPrivateHomeStale
	}
	if record.Kind == PrivateHomeClaim && (!exists || old.Kind != PrivateHomeClaim) && !revoked && s.activeIdentities >= s.maxMembers {
		return ErrPrivateHomeLimit
	}
	newOrdinary := record.Kind == PrivateHomeRelease && (!exists || old.Kind != PrivateHomeRelease || old.Signature == "")
	for newOrdinary && s.ordinaryTombstones >= s.maxMembers {
		if err := s.evictOldestOrdinaryLocked(batch, record.Member); err != nil {
			return err
		}
	}

	s.accountRecordRemovalLocked(old, exists, revoked)
	batch.Delete(privateHomeRecordKey(record.Member))
	batch.Delete(privateHomeAdmissionKey(record.Member))
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	batch.Put(privateHomeRecordKey(record.Member), raw)
	s.accountRecordAdditionLocked(record, revoked)
	s.pushRecordExpiry(record)
	if record.Kind == PrivateHomeClaim && binding != nil {
		binding.Member, binding.IssuedAt = record.Member, record.IssuedAt
		rawBinding, err := json.Marshal(binding)
		if err != nil {
			return err
		}
		batch.Put(privateHomeAdmissionKey(record.Member), rawBinding)
	}
	return nil
}

// Current returns the member's live claim. Releases and expired claims are absent.
func (s *PrivateHomeStore) Current(member string) (PrivateHomeRecord, bool, error) {
	if s == nil || s.messages == nil || len(member) != 66 {
		return PrivateHomeRecord{}, false, nil
	}
	s.messages.writeMu.Lock()
	defer s.messages.writeMu.Unlock()
	if err := s.prepareLocked(); err != nil {
		return PrivateHomeRecord{}, false, err
	}
	record, ok, err := s.recordLocked(strings.ToLower(member))
	if err != nil || !ok || record.Kind != PrivateHomeClaim {
		return PrivateHomeRecord{}, false, err
	}
	return record, true, nil
}

// Count returns the number of current live claims, excluding releases.
func (s *PrivateHomeStore) Count() int {
	if s == nil || s.messages == nil {
		return 0
	}
	s.messages.writeMu.Lock()
	defer s.messages.writeMu.Unlock()
	if s.prepareLocked() != nil {
		return 0
	}
	return s.claims
}

func (s *PrivateHomeStore) recordLocked(member string) (PrivateHomeRecord, bool, error) {
	raw, err := s.messages.db.Get(privateHomeRecordKey(member), nil)
	if errors.Is(err, leveldb.ErrNotFound) {
		return PrivateHomeRecord{}, false, nil
	}
	if err != nil {
		return PrivateHomeRecord{}, false, fmt.Errorf("read private home record: %w", err)
	}
	var record PrivateHomeRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return PrivateHomeRecord{}, false, fmt.Errorf("decode private home record: %w", err)
	}
	return record, true, nil
}
