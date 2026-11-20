package envelope

// QueryExactTopic returns the envelopes whose own Topic is exactly topic,
// newest-first, at most limit of them when limit is above 0.
//
// QueryByTopic's durable scan reads every key under "d:<topic>:", so it also
// returns envelopes on sub-topics such as "<topic>:x". That prefix match is
// what the mesh's catch-up subscription wants (internal/gossip, which
// documents topic prefixes for peers), and what a read a client makes, or an
// access decision, must not get: each of those is about one topic. The
// ephemeral side of QueryByTopic was always exact.
func (s *Store) QueryExactTopic(topic string, limit int) ([]*Envelope, error) {
	all, err := s.QueryByTopic(topic, 0)
	if err != nil {
		return nil, err
	}
	exact := all[:0]
	for _, env := range all {
		if env.Topic == topic {
			exact = append(exact, env)
		}
	}
	if limit > 0 && len(exact) > limit {
		exact = exact[:limit]
	}
	return exact, nil
}
