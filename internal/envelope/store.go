package envelope

import (
	"fmt"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

var (
	prefixDurable   = []byte("d:")   // d:<topic>:<key> → envelope JSON
	prefixEphemeral = []byte("e:")   // in-memory only, not persisted
)

// Store manages both ephemeral and durable data envelopes.
// Durable envelopes are persisted to LevelDB. Ephemeral envelopes
// are held in memory with TTL-based expiration.
type Store struct {
	db        *leveldb.DB
	ephemeral map[string]*Envelope // key → envelope
	mu        sync.RWMutex

	maxEphemeralTTL int // max TTL seconds for ephemeral envelopes
	maxDurableSize  int // max payload size in bytes for durable envelopes
}

// NewStore opens or creates an envelope store.
func NewStore(path string, maxEphemeralTTL, maxDurableSize int) (*Store, error) {
	db, err := leveldb.OpenFile(path, nil)
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

	if env.Durable {
		return s.storeDurable(env)
	}
	return s.storeEphemeral(env)
}

func (s *Store) storeDurable(env *Envelope) error {
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

// StoreEphemeralDirect stores an envelope without validation. For testing only.
func (s *Store) StoreEphemeralDirect(env *Envelope) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ephemeral[env.Key()] = env
}

// QueryByTopic returns envelopes matching the given topic.
// Searches both durable (LevelDB) and ephemeral (memory) stores.
// Results are limited by the limit parameter (0 = no limit).
func (s *Store) QueryByTopic(topic string, limit int) ([]*Envelope, error) {
	var results []*Envelope

	// Query durable store
	prefix := append(append([]byte{}, prefixDurable...), []byte(topic+":")...)
	iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()

	for iter.Next() {
		env, err := UnmarshalEnvelope(iter.Value())
		if err != nil {
			continue
		}
		results = append(results, env)
		if limit > 0 && len(results) >= limit {
			break
		}
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("iterate durable: %w", err)
	}

	// Query ephemeral store
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, env := range s.ephemeral {
		if env.Topic == topic && !env.IsExpired() {
			results = append(results, env)
			if limit > 0 && len(results) >= limit {
				break
			}
		}
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

// Topics returns a map of topic → envelope count for all ephemeral envelopes.
func (s *Store) Topics() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	topics := make(map[string]int)
	for _, env := range s.ephemeral {
		topics[env.Topic]++
	}
	return topics
}
