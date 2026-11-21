package envelope

// PublicCountEphemeral returns the number of non-private, non-expired
// ephemeral envelopes — the same filter PublicTopicSummary applies. Safe to
// show to any caller: paired with PublicCountDurable, the two always sum to
// exactly the total envelope count across PublicTopics, so an unauthenticated
// caller or a payer can never back out the private count by subtracting a
// public topic total from an unfiltered CountEphemeral/CountDurable.
func (s *Store) PublicCountEphemeral() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, envs := range s.ephemeralPublicByTopic {
		for _, env := range envs {
			if !env.IsExpired() {
				n++
			}
		}
	}
	return n
}

// PublicCountDurable returns the number of non-private durable envelopes.
// See PublicCountEphemeral.
func (s *Store) PublicCountDurable() int {
	s.publicMu.RLock()
	defer s.publicMu.RUnlock()
	total := 0
	for _, count := range s.publicDurableCounts {
		total += count
	}
	return total
}

// PublicTopics returns a map of topic → envelope count, counting only
// NON-private envelopes. Unlike Topics, this is safe to hand to any
// unauthenticated caller or to broadcast to mesh peers (e.g. the
// mesh:heartbeat payload, /mesh/nodes, /.well-known/anvil) — a topic with
// zero public envelopes does not appear at all, so a private-only topic's
// name never leaks through it.
func (s *Store) PublicTopics() map[string]int {
	counts, _ := s.PublicTopicSummary()
	return counts
}

// PrivateOnlyTopics returns the set of topic names that have at least one
// envelope stored on this node but no PUBLIC envelope at all. These are the
// only topic names that must never reach a peer or an unauthenticated
// caller. A topic absent from this set is safe to pass through unchanged by
// a caller filtering some other list (e.g. gossip demand) against it:
// either the topic is genuinely public, or this node currently holds
// nothing for it at all (expired, or known only via a peer's remote
// demand) — neither case is a reason to drop it.
func (s *Store) PrivateOnlyTopics() map[string]struct{} {
	hasPublic := make(map[string]bool)
	hasAny := make(map[string]bool)

	s.publicMu.RLock()
	for topic, count := range s.durableTopicCounts {
		if count > 0 {
			hasAny[topic] = true
		}
	}
	for topic, count := range s.publicDurableCounts {
		if count > 0 {
			hasPublic[topic] = true
		}
	}
	s.publicMu.RUnlock()

	s.mu.RLock()
	for topic, envs := range s.ephemeralByTopic {
		for _, env := range envs {
			if env.IsExpired() {
				continue
			}
			hasAny[topic] = true
			if !env.Private {
				hasPublic[topic] = true
			}
		}
	}
	s.mu.RUnlock()

	privateOnly := make(map[string]struct{})
	for topic := range hasAny {
		if !hasPublic[topic] {
			privateOnly[topic] = struct{}{}
		}
	}
	return privateOnly
}

// PublicTopicSummary returns, per topic, the count and newest timestamp of
// NON-private envelopes only, in a single pass. Used to build discovery
// responses (/topics) for unauthenticated callers so private envelopes never
// leak via existence, count, or last_updated — even under a topic whose latest
// envelope is public (a mixed topic). Topics with zero public envelopes do not
// appear in the maps at all.
func (s *Store) PublicTopicSummary() (counts map[string]int, latest map[string]int64) {
	s.publicMu.RLock()
	counts = make(map[string]int, len(s.publicDurableCounts))
	latest = make(map[string]int64, len(s.publicDurableLatest))
	for topic, count := range s.publicDurableCounts {
		counts[topic] = count
	}
	for topic, timestamp := range s.publicDurableLatest {
		latest[topic] = timestamp
	}
	s.publicMu.RUnlock()

	s.mu.RLock()
	for topic, envs := range s.ephemeralPublicByTopic {
		for _, env := range envs {
			if env.IsExpired() {
				continue
			}
			counts[topic]++
			if env.Timestamp > latest[topic] {
				latest[topic] = env.Timestamp
			}
		}
	}
	s.mu.RUnlock()

	return counts, latest
}
