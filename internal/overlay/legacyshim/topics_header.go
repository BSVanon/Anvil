package legacyshim

import "fmt"

// maxDistinctTopics caps how many distinct topics one /overlay/submit may
// name — the same bound and the same reason as the canonical route's
// v3engine.maxDistinctTopics: the engine admits a transaction once per entry
// in the topics list it is given, with no deduplication of its own, and this
// node hosts on the order of a dozen topic managers today, so a request
// naming far more than that pays for N times the admission work of an honest
// one. 64 is generous slack over today's topic count.
const maxDistinctTopics = 64

// dedupTopics returns topics with exact duplicates removed, keeping each
// name's first position, and an error if more than maxDistinctTopics
// distinct names remain.
func dedupTopics(topics []string) ([]string, error) {
	if len(topics) == 0 {
		return topics, nil
	}
	seen := make(map[string]struct{}, len(topics))
	out := make([]string, 0, len(topics))
	for _, t := range topics {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) > maxDistinctTopics {
		return nil, fmt.Errorf("more than %d distinct topics (%d named)", maxDistinctTopics, len(out))
	}
	return out, nil
}
