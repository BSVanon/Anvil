package envelope

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BSVanon/Anvil/internal/store"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

var (
	prefixDurable = []byte("d:") // d:<topic>:<key> → envelope JSON
)

// Store manages both ephemeral and durable data envelopes.
// Durable envelopes are persisted to LevelDB. Ephemeral envelopes
// are held in memory with TTL-based expiration.
type Store struct {
	db        *leveldb.DB
	ephemeral map[string]*Envelope // key → envelope
	mu        sync.RWMutex

	maxEphemeralTTL  int // max TTL seconds for ephemeral envelopes
	maxDurableSize   int // max payload size in bytes for durable envelopes
	maxDurableStoreB int64 // max total durable store size in bytes (0 = unlimited)
	durableFull      atomic.Bool // set by CheckDurableCapacity, checked on write
}

// NewStore opens or creates an envelope store.
func NewStore(path string, maxEphemeralTTL, maxDurableSize int) (*Store, error) {
	db, err := store.OpenWithRecover(path, nil)
	if err != nil {
		return nil, fmt.Errorf("open envelope store: %w", err)
	}
	return &Store{
		db:              db,
		ephemeral:       make(map[string]*Envelope),
		maxEphemeralTTL: maxEphemeralTTL,
		maxDurableSize:  maxDurableSize,
	}, nil
}

// SetMaxDurableStoreMB sets the maximum durable store size in megabytes.
// When exceeded, new durable writes are rejected. Call CheckDurableCapacity
// periodically to update the full flag.
func (s *Store) SetMaxDurableStoreMB(mb int) {
	if mb > 0 {
		s.maxDurableStoreB = int64(mb) * 1024 * 1024
	}
}

// CheckDurableCapacity estimates durable store size and sets the full flag.
// Call periodically (e.g., every 30 seconds alongside ephemeral sweep).
// Returns (sizeBytes, isFull).
func (s *Store) CheckDurableCapacity() (int64, bool) {
	if s.maxDurableStoreB <= 0 {
		return 0, false
	}
	var size int64
	iter := s.db.NewIterator(util.BytesPrefix(prefixDurable), nil)
	for iter.Next() {
		size += int64(len(iter.Key()) + len(iter.Value()))
	}
	iter.Release()
	full := size >= s.maxDurableStoreB
	s.durableFull.Store(full)
	return size, full
}

// Close closes the underlying LevelDB.
func (s *Store) Close() error {
	return s.db.Close()
}

// Ingest validates and stores an envelope. Rejects unsigned or invalid envelopes.
func (s *Store) Ingest(env *Envelope) error {
	if err := env.Validate(); err != nil {
		return fmt.Errorf("invalid envelope: %w", err)
	}

	env.ReceivedAt = time.Now()

	// Backfill missing timestamp after signature verification passes.
	// Legacy envelopes signed with timestamp=0 verify correctly (digest
	// computed with 0), then get a receive-time timestamp for storage/query.
	if env.Timestamp == 0 {
		env.Timestamp = env.ReceivedAt.Unix()
	}

	if env.Durable {
		return s.storeDurable(env)
	}
	return s.storeEphemeral(env)
}

func (s *Store) storeDurable(env *Envelope) error {
	if s.durableFull.Load() {
		return fmt.Errorf("durable store full: max capacity reached, rejecting new writes")
	}
	if len(env.Payload) > s.maxDurableSize {
		return fmt.Errorf("payload %d bytes exceeds max %d", len(env.Payload), s.maxDurableSize)
	}

	data, err := env.Marshal()
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	key := append(append([]byte{}, prefixDurable...), []byte(env.Topic+":"+env.Key())...)
	return s.db.Put(key, data, nil)
}

func (s *Store) storeEphemeral(env *Envelope) error {
	if env.TTL > s.maxEphemeralTTL {
		return fmt.Errorf("TTL %d exceeds max %d", env.TTL, s.maxEphemeralTTL)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ephemeral[env.Key()] = env
	return nil
}

// Delete removes an envelope by topic and key from both durable and ephemeral
// storage. Returns whether anything was deleted.
func (s *Store) Delete(topic, key string) (bool, error) {
	if topic == "" || key == "" {
		return false, fmt.Errorf("topic and key required")
	}

	deleted := false
	durableKey := append(append([]byte{}, prefixDurable...), []byte(topic+":"+key)...)
	if ok, err := s.db.Has(durableKey, nil); err != nil {
		return false, fmt.Errorf("check durable envelope: %w", err)
	} else if ok {
		if err := s.db.Delete(durableKey, nil); err != nil {
			return false, fmt.Errorf("delete durable envelope: %w", err)
		}
		deleted = true
	}

	s.mu.Lock()
	if _, ok := s.ephemeral[key]; ok {
		delete(s.ephemeral, key)
		deleted = true
	}
	s.mu.Unlock()

	return deleted, nil
}

// DeduplicateDurable removes older durable envelopes that share the same
// topic and publisher pubkey as the given envelope, keeping only the newest.
// Used for topics like anvil:catalog where one entry per publisher should win.
// Returns the number of entries removed.
func (s *Store) DeduplicateDurable(env *Envelope) int {
	prefix := append(append([]byte{}, prefixDurable...), []byte(env.Topic+":")...)
	currentKey := append(append([]byte{}, prefixDurable...), []byte(env.Topic+":"+env.Key())...)

	var toDelete [][]byte
	newerExists := false
	iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
	for iter.Next() {
		k := iter.Key()
		if string(k) == string(currentKey) {
			continue // skip self
		}
		old, err := UnmarshalEnvelope(iter.Value())
		if err != nil {
			continue
		}
		if old.Pubkey != env.Pubkey {
			continue
		}
		if old.Timestamp > env.Timestamp {
			// A newer entry already exists — the incoming envelope is stale.
			newerExists = true
			break
		}
		keyCopy := make([]byte, len(k))
		copy(keyCopy, k)
		toDelete = append(toDelete, keyCopy)
	}
	iter.Release()

	if newerExists {
		// Stale envelope arrived late. Remove it instead of the newer one.
		_ = s.db.Delete(currentKey, nil)
		return 0
	}

	for _, k := range toDelete {
		_ = s.db.Delete(k, nil)
	}
	return len(toDelete)
}

// StoreEphemeralDirect stores an envelope without validation. For testing only.
func (s *Store) StoreEphemeralDirect(env *Envelope) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ephemeral[env.Key()] = env
}

// QueryByTopic returns envelopes matching the given topic.
// Searches both durable (LevelDB) and ephemeral (memory) stores.
// Results are sorted newest-first (by timestamp descending) and
// limited after merging both stores, so limit=1 always returns the
// most recent envelope regardless of storage type.
func (s *Store) QueryByTopic(topic string, limit int) ([]*Envelope, error) {
	var results []*Envelope

	// Query durable store (collect all, sort later)
	prefix := append(append([]byte{}, prefixDurable...), []byte(topic+":")...)
	iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()

	for iter.Next() {
		env, err := UnmarshalEnvelope(iter.Value())
		if err != nil {
			continue
		}
		results = append(results, env)
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("iterate durable: %w", err)
	}

	// Query ephemeral store
	s.mu.RLock()
	for _, env := range s.ephemeral {
		if env.Topic == topic && !env.IsExpired() {
			results = append(results, env)
		}
	}
	s.mu.RUnlock()

	// Sort newest-first by timestamp
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp > results[j].Timestamp
	})

	// Apply limit after merge + sort
	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}

	return results, nil
}

// ExpireEphemeral removes expired ephemeral envelopes. Call periodically.
func (s *Store) ExpireEphemeral() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	expired := 0
	for key, env := range s.ephemeral {
		if env.IsExpired() {
			delete(s.ephemeral, key)
			expired++
		}
	}
	return expired
}

// CountEphemeral returns the number of ephemeral envelopes in memory.
func (s *Store) CountEphemeral() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ephemeral)
}

// CountDurable returns the number of durable envelopes.
func (s *Store) CountDurable() int {
	count := 0
	iter := s.db.NewIterator(util.BytesPrefix(prefixDurable), nil)
	defer iter.Release()
	for iter.Next() {
		count++
	}
	return count
}

// LatestByTopic returns the most recent envelope timestamp (unix) per topic.
func (s *Store) LatestByTopic() map[string]int64 {
	latest := make(map[string]int64)

	iter := s.db.NewIterator(util.BytesPrefix(prefixDurable), nil)
	for iter.Next() {
		env, err := UnmarshalEnvelope(iter.Value())
		if err != nil {
			continue
		}
		if env.Timestamp > latest[env.Topic] {
			latest[env.Topic] = env.Timestamp
		}
	}
	iter.Release()

	s.mu.RLock()
	for _, env := range s.ephemeral {
		if !env.IsExpired() && env.Timestamp > latest[env.Topic] {
			latest[env.Topic] = env.Timestamp
		}
	}
	s.mu.RUnlock()

	return latest
}

// Topics returns a map of topic → envelope count across both ephemeral and durable stores.
func (s *Store) Topics() map[string]int {
	topics := make(map[string]int)

	// Count durable envelopes from LevelDB
	iter := s.db.NewIterator(util.BytesPrefix(prefixDurable), nil)
	for iter.Next() {
		env, err := UnmarshalEnvelope(iter.Value())
		if err != nil {
			continue
		}
		topics[env.Topic]++
	}
	iter.Release()

	// Count ephemeral envelopes
	s.mu.RLock()
	for _, env := range s.ephemeral {
		if !env.IsExpired() {
			topics[env.Topic]++
		}
	}
	s.mu.RUnlock()

	return topics
}
