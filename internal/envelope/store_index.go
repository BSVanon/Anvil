package envelope

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sort"
	"strings"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

var (
	prefixExactAll    = []byte("x1:")
	prefixExactPublic = []byte("u1:")
	prefixPublicPull  = []byte("g1:")
	durableIndexReady = []byte("m:envelope-index-v1")
)

const envelopeIndexMigration = "envelope-durable-indexes"

// PageCursor identifies one envelope in the stable newest-first store order.
// Timestamp alone is not a cursor because many signed envelopes can share it.
type PageCursor struct {
	Timestamp int64  `json:"timestamp"`
	ID        string `json:"id"`
}

func CursorFor(env *Envelope) PageCursor {
	if env == nil {
		return PageCursor{}
	}
	return PageCursor{Timestamp: env.Timestamp, ID: envelopeOrderID(env)}
}

func envelopeOrderID(env *Envelope) string {
	return HashEnvelope(env.Topic, env.Pubkey, env.Payload, env.Timestamp)
}

func envelopeBefore(a, b *Envelope) bool {
	if a.Timestamp != b.Timestamp {
		return a.Timestamp > b.Timestamp
	}
	return envelopeOrderID(a) < envelopeOrderID(b)
}

func durablePrimaryKey(topic, key string) []byte {
	out := append([]byte{}, prefixDurable...)
	return append(out, []byte(topic+":"+key)...)
}

func indexTopicPrefix(kind []byte, topic string) []byte {
	out := append([]byte{}, kind...)
	out = append(out, base64.RawURLEncoding.EncodeToString([]byte(topic))...)
	return append(out, ':')
}

func indexEntryKey(kind []byte, topic string, cursor PageCursor) []byte {
	out := indexTopicPrefix(kind, topic)
	var timestamp [8]byte
	ordered := uint64(cursor.Timestamp) ^ (uint64(1) << 63)
	binary.BigEndian.PutUint64(timestamp[:], ^ordered)
	out = append(out, timestamp[:]...)
	out = append(out, ':')
	return append(out, cursor.ID...)
}

func topicPrefixes(topic string) []string {
	prefixes := make([]string, 0, strings.Count(topic, ":")+1)
	for i := 0; i < len(topic); i++ {
		if topic[i] == ':' && i > 0 {
			prefixes = append(prefixes, topic[:i])
		}
	}
	return append(prefixes, topic)
}

func (s *Store) addIndexPuts(batch *leveldb.Batch, primary []byte, env *Envelope) {
	cursor := CursorFor(env)
	batch.Put(indexEntryKey(prefixExactAll, env.Topic, cursor), primary)
	if env.Private {
		return
	}
	batch.Put(indexEntryKey(prefixExactPublic, env.Topic, cursor), primary)
	for _, prefix := range topicPrefixes(env.Topic) {
		batch.Put(indexEntryKey(prefixPublicPull, prefix, cursor), primary)
	}
}

func (s *Store) addIndexDeletes(batch *leveldb.Batch, env *Envelope) {
	if env == nil {
		return
	}
	cursor := CursorFor(env)
	batch.Delete(indexEntryKey(prefixExactAll, env.Topic, cursor))
	if env.Private {
		return
	}
	batch.Delete(indexEntryKey(prefixExactPublic, env.Topic, cursor))
	for _, prefix := range topicPrefixes(env.Topic) {
		batch.Delete(indexEntryKey(prefixPublicPull, prefix, cursor))
	}
}

func (s *Store) initializeDurableIndexes(migrationStarted func(string) error) error {
	_, markerErr := s.db.Get(durableIndexReady, nil)
	build := errors.Is(markerErr, leveldb.ErrNotFound)
	if markerErr != nil && !build {
		return markerErr
	}

	counts := make(map[string]int)
	publicCounts := make(map[string]int)
	publicLatest := make(map[string]int64)
	batch := new(leveldb.Batch)
	pending := 0
	migrationRecorded := false
	iter := s.db.NewIterator(util.BytesPrefix(prefixDurable), nil)
	for iter.Next() {
		env, err := UnmarshalEnvelope(iter.Value())
		if err != nil {
			continue
		}
		counts[env.Topic]++
		if !env.Private {
			publicCounts[env.Topic]++
			if env.Timestamp > publicLatest[env.Topic] {
				publicLatest[env.Topic] = env.Timestamp
			}
		}
		if build {
			if !migrationRecorded && migrationStarted != nil {
				if err := migrationStarted(envelopeIndexMigration); err != nil {
					iter.Release()
					return err
				}
				migrationRecorded = true
			}
			primary := append([]byte(nil), iter.Key()...)
			s.addIndexPuts(batch, primary, env)
			pending++
			if pending == 1000 {
				if err := s.db.Write(batch, nil); err != nil {
					iter.Release()
					return err
				}
				batch.Reset()
				pending = 0
			}
		}
	}
	err := iter.Error()
	iter.Release()
	if err != nil {
		return err
	}
	if build {
		if pending > 0 {
			if err := s.db.Write(batch, nil); err != nil {
				return err
			}
		}
		if err := s.db.Put(durableIndexReady, []byte{1}, nil); err != nil {
			return err
		}
	}

	s.publicMu.Lock()
	s.durableTopicCounts = counts
	s.publicDurableCounts = publicCounts
	s.publicDurableLatest = publicLatest
	s.publicMu.Unlock()
	return nil
}

func (s *Store) writeDurable(env *Envelope, data []byte) error {
	primary := durablePrimaryKey(env.Topic, env.Key())
	var old *Envelope
	if prior, err := s.db.Get(primary, nil); err == nil {
		old, _ = UnmarshalEnvelope(prior)
	} else if !errors.Is(err, leveldb.ErrNotFound) {
		return err
	}

	batch := new(leveldb.Batch)
	s.addIndexDeletes(batch, old)
	batch.Put(primary, data)
	s.addIndexPuts(batch, primary, env)
	if err := s.db.Write(batch, nil); err != nil {
		return err
	}
	s.replaceDurableSummary(old, env)
	return nil
}

func (s *Store) deleteDurable(primary []byte, env *Envelope) error {
	batch := new(leveldb.Batch)
	batch.Delete(primary)
	s.addIndexDeletes(batch, env)
	if err := s.db.Write(batch, nil); err != nil {
		return err
	}
	s.replaceDurableSummary(env, nil)
	return nil
}

func (s *Store) replaceDurableSummary(old, next *Envelope) {
	s.publicMu.Lock()
	defer s.publicMu.Unlock()
	if old != nil {
		s.durableTopicCounts[old.Topic]--
		if s.durableTopicCounts[old.Topic] <= 0 {
			delete(s.durableTopicCounts, old.Topic)
		}
		if !old.Private {
			s.publicDurableCounts[old.Topic]--
			if s.publicDurableCounts[old.Topic] <= 0 {
				delete(s.publicDurableCounts, old.Topic)
				delete(s.publicDurableLatest, old.Topic)
			} else if s.publicDurableLatest[old.Topic] == old.Timestamp {
				s.publicDurableLatest[old.Topic] = s.latestPublicDurableTimestamp(old.Topic)
			}
		}
	}
	if next != nil {
		s.durableTopicCounts[next.Topic]++
		if !next.Private {
			s.publicDurableCounts[next.Topic]++
			if next.Timestamp > s.publicDurableLatest[next.Topic] {
				s.publicDurableLatest[next.Topic] = next.Timestamp
			}
		}
	}
}

func (s *Store) latestPublicDurableTimestamp(topic string) int64 {
	results, _ := s.queryDurableIndex(prefixExactPublic, topic, 1, PageCursor{}, 0)
	if len(results) == 0 {
		return 0
	}
	return results[0].Timestamp
}

func (s *Store) putEphemeralLocked(env *Envelope) {
	key := env.Key()
	if old, ok := s.ephemeral[key]; ok {
		s.removeEphemeralLocked(key, old)
	}
	s.ephemeral[key] = env
	s.ephemeralByTopic[env.Topic] = insertEnvelope(s.ephemeralByTopic[env.Topic], env)
	if !env.Private {
		s.ephemeralPublicByTopic[env.Topic] = insertEnvelope(s.ephemeralPublicByTopic[env.Topic], env)
		for _, prefix := range topicPrefixes(env.Topic) {
			s.ephemeralPublicByPrefix[prefix] = insertEnvelope(s.ephemeralPublicByPrefix[prefix], env)
		}
	}
}

func (s *Store) removeEphemeralLocked(key string, env *Envelope) {
	delete(s.ephemeral, key)
	s.ephemeralByTopic[env.Topic] = removeEnvelope(s.ephemeralByTopic[env.Topic], env)
	if len(s.ephemeralByTopic[env.Topic]) == 0 {
		delete(s.ephemeralByTopic, env.Topic)
	}
	if env.Private {
		return
	}
	s.ephemeralPublicByTopic[env.Topic] = removeEnvelope(s.ephemeralPublicByTopic[env.Topic], env)
	if len(s.ephemeralPublicByTopic[env.Topic]) == 0 {
		delete(s.ephemeralPublicByTopic, env.Topic)
	}
	for _, prefix := range topicPrefixes(env.Topic) {
		s.ephemeralPublicByPrefix[prefix] = removeEnvelope(s.ephemeralPublicByPrefix[prefix], env)
		if len(s.ephemeralPublicByPrefix[prefix]) == 0 {
			delete(s.ephemeralPublicByPrefix, prefix)
		}
	}
}

func insertEnvelope(list []*Envelope, env *Envelope) []*Envelope {
	i := sort.Search(len(list), func(i int) bool { return !envelopeBefore(list[i], env) })
	list = append(list, nil)
	copy(list[i+1:], list[i:])
	list[i] = env
	return list
}

func removeEnvelope(list []*Envelope, env *Envelope) []*Envelope {
	for i, candidate := range list {
		if candidate == env {
			copy(list[i:], list[i+1:])
			return list[:len(list)-1]
		}
	}
	return list
}
