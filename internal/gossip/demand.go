package gossip

// IncrDemand increments the local demand counter for a topic.
// Called by SSE hub on subscribe and API handlers on query.
func (m *Manager) IncrDemand(topic string) {
	m.demandMu.Lock()
	if m.demandMap == nil {
		m.demandMap = make(map[string]int)
	}
	m.demandMap[topic]++
	m.demandMu.Unlock()
}

// TopicDemand returns the current demand count for a topic.
func (m *Manager) TopicDemand(topic string) int {
	m.demandMu.RLock()
	defer m.demandMu.RUnlock()
	return m.demandMap[topic]
}

// DemandMap returns a copy of the current demand map for heartbeat publication.
func (m *Manager) DemandMap() map[string]int {
	m.demandMu.RLock()
	defer m.demandMu.RUnlock()
	cp := make(map[string]int, len(m.demandMap))
	for k, v := range m.demandMap {
		cp[k] = v
	}
	return cp
}

// MergeDemand merges a remote demand map using max() semantics.
// Called when processing heartbeat envelopes from peers.
func (m *Manager) MergeDemand(remote map[string]int) {
	m.demandMu.Lock()
	defer m.demandMu.Unlock()
	if m.demandMap == nil {
		m.demandMap = make(map[string]int)
	}
	for topic, count := range remote {
		if count > m.demandMap[topic] {
			m.demandMap[topic] = count
		}
	}
}

// DecayDemand halves all demand counters. Call periodically (e.g., every
// 5 minutes) so demand naturally drops when queries/subscriptions stop.
// Removes entries that decay to zero.
func (m *Manager) DecayDemand() {
	m.demandMu.Lock()
	defer m.demandMu.Unlock()
	for topic, count := range m.demandMap {
		halved := count / 2
		if halved <= 0 {
			delete(m.demandMap, topic)
		} else {
			m.demandMap[topic] = halved
		}
	}
}
