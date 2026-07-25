// Package health tracks the overlay node's own lookup-notify error rate so the
// node can flag its own failures — a lookup that cannot index an admitted output
// (e.g. the V1-BEEF parse bug an external dev had to report twice) — via /status
// and `anvil doctor`, instead of the error only ever landing in the logs where
// nobody looks until an outsider complains.
package health

import (
	"sync"
	"time"
)

// rollingWindow is the "recent" horizon reported alongside since-start totals.
const rollingWindow = time.Hour

// Registry accumulates lookup-notify failures keyed by overlay topic. Safe for
// concurrent use.
type Registry struct {
	mu     sync.Mutex
	topics map[string]*topicStat
}

type topicStat struct {
	total     int64
	recent    []int64 // unix-nano timestamps within the rolling window
	lastErr   string
	lastErrAt int64 // unix seconds
}

// New returns an empty registry.
func New() *Registry { return &Registry{topics: make(map[string]*topicStat)} }

// Default is the process-wide registry the running node records into and /status
// reports from. Tests construct their own via New().
var Default = New()

// RecordLookupError records one lookup-notify (OutputAdmittedByTopic) failure
// for a topic. A nil error or nil receiver is a no-op.
func (r *Registry) RecordLookupError(topic string, err error) {
	if r == nil || err == nil {
		return
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.topics[topic]
	if st == nil {
		st = &topicStat{}
		r.topics[topic] = st
	}
	st.total++
	st.lastErr = err.Error()
	st.lastErrAt = now.Unix()
	st.recent = append(pruneOld(st.recent, now), now.UnixNano())
}

// pruneOld drops timestamps older than the rolling window. Input is assumed
// ascending (append-only), so a single leading trim suffices.
func pruneOld(ts []int64, now time.Time) []int64 {
	cutoff := now.Add(-rollingWindow).UnixNano()
	i := 0
	for i < len(ts) && ts[i] < cutoff {
		i++
	}
	return ts[i:]
}

// TopicHealth is the per-topic view exposed to /status + doctor.
type TopicHealth struct {
	Recent1h    int64  `json:"recent_1h"`
	Total       int64  `json:"total"`
	LastError   string `json:"last_error,omitempty"`
	LastErrorAt int64  `json:"last_error_at,omitempty"` // unix seconds
}

// Snapshot is the whole-registry view. Empty (all zero, nil map) when the node
// has had no lookup-notify errors — the healthy steady state.
type Snapshot struct {
	ByTopic     map[string]TopicHealth `json:"lookup_errors_by_topic,omitempty"`
	RecentTotal int64                  `json:"lookup_errors_recent_1h"`
	Total       int64                  `json:"lookup_errors_total"`
}

// Snapshot returns the current counters, pruning the rolling window as it reads.
func (r *Registry) Snapshot() Snapshot {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := Snapshot{}
	if len(r.topics) == 0 {
		return out
	}
	out.ByTopic = make(map[string]TopicHealth, len(r.topics))
	for topic, st := range r.topics {
		st.recent = pruneOld(st.recent, now)
		recent := int64(len(st.recent))
		out.ByTopic[topic] = TopicHealth{
			Recent1h:    recent,
			Total:       st.total,
			LastError:   st.lastErr,
			LastErrorAt: st.lastErrAt,
		}
		out.RecentTotal += recent
		out.Total += st.total
	}
	return out
}

// Reset clears all counters (tests).
func (r *Registry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.topics = make(map[string]*topicStat)
}
