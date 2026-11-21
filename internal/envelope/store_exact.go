package envelope

import (
	"fmt"
	"sort"

	"github.com/syndtr/goleveldb/leveldb/util"
)

const ExactTopicDefaultLimit = 1000

// QueryExactTopic returns a bounded public-only exact-topic view. Callers that
// intentionally serve an operator-only representation use QueryExactTopicAll.
func (s *Store) QueryExactTopic(topic string, limit int) ([]*Envelope, error) {
	if limit <= 0 || limit > ExactTopicDefaultLimit {
		limit = ExactTopicDefaultLimit
	}
	return s.QueryPublicExactTopic(topic, limit, 0)
}

// QueryExactTopicAll returns public and private envelopes for an operator-only
// read. A zero limit is intentionally unbounded.
func (s *Store) QueryExactTopicAll(topic string, limit int) ([]*Envelope, error) {
	durable, err := s.queryDurableIndex(prefixExactAll, topic, limit, PageCursor{}, 0)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	ephemeral := selectEnvelopes(s.ephemeralByTopic[topic], limit, PageCursor{}, 0)
	s.mu.RUnlock()
	return mergeEnvelopePages(durable, ephemeral, limit), nil
}

// QueryPublicExactTopic returns only public envelopes from one exact topic.
// The durable and in-memory indexes contain no private records, and limit caps
// the number of indexed records visited. newerThan applies the HTTP forward
// timestamp filter before the limit.
func (s *Store) QueryPublicExactTopic(topic string, limit int, newerThan int64) ([]*Envelope, error) {
	durable, err := s.queryDurableIndex(prefixExactPublic, topic, limit, PageCursor{}, newerThan)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	ephemeral := selectEnvelopes(s.ephemeralPublicByTopic[topic], limit, PageCursor{}, newerThan)
	s.mu.RUnlock()
	return mergeEnvelopePages(durable, ephemeral, limit), nil
}

// QueryPublicTopicPrefix returns a bounded public-only mesh page for a topic
// and its colon-delimited subtopics. after is exclusive and stable when many
// envelopes share a timestamp.
func (s *Store) QueryPublicTopicPrefix(topic string, limit int, after PageCursor) ([]*Envelope, error) {
	durable, err := s.queryDurableIndex(prefixPublicPull, topic, limit, after, 0)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	ephemeral := selectEnvelopes(s.ephemeralPublicByPrefix[topic], limit, after, 0)
	s.mu.RUnlock()
	return mergeEnvelopePages(durable, ephemeral, limit), nil
}

func (s *Store) queryDurableIndex(kind []byte, topic string, limit int, after PageCursor, newerThan int64) ([]*Envelope, error) {
	prefix := indexTopicPrefix(kind, topic)
	rng := util.BytesPrefix(prefix)
	if after.ID != "" {
		start := indexEntryKey(kind, topic, after)
		rng.Start = append(start, 0)
	}
	iter := s.db.NewIterator(rng, nil)
	defer iter.Release()

	results := make([]*Envelope, 0, max(limit, 0))
	work := 0
	workLimit := 0
	if limit > 0 {
		workLimit = limit + 32
	}
	for iter.Next() {
		work++
		if workLimit > 0 && work > workLimit {
			break
		}
		data, err := s.db.Get(iter.Value(), nil)
		if err != nil {
			continue
		}
		env, err := UnmarshalEnvelope(data)
		if err != nil {
			continue
		}
		if newerThan > 0 && env.Timestamp <= newerThan {
			break
		}
		results = append(results, env)
		if limit > 0 && len(results) == limit {
			break
		}
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("iterate durable index: %w", err)
	}
	return results, nil
}

func selectEnvelopes(list []*Envelope, limit int, after PageCursor, newerThan int64) []*Envelope {
	capacity := len(list)
	if limit > 0 && capacity > limit {
		capacity = limit
	}
	results := make([]*Envelope, 0, capacity)
	for _, env := range list {
		if env.IsExpired() {
			continue
		}
		if after.ID != "" {
			id := envelopeOrderID(env)
			if env.Timestamp > after.Timestamp || (env.Timestamp == after.Timestamp && id <= after.ID) {
				continue
			}
		}
		if newerThan > 0 && env.Timestamp <= newerThan {
			break
		}
		results = append(results, env)
		if limit > 0 && len(results) == limit {
			break
		}
	}
	return results
}

func mergeEnvelopePages(a, b []*Envelope, limit int) []*Envelope {
	results := append(append(make([]*Envelope, 0, len(a)+len(b)), a...), b...)
	sort.Slice(results, func(i, j int) bool { return envelopeBefore(results[i], results[j]) })
	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}
	return results
}
