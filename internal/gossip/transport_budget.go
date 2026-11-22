package gossip

import "sync"

type managerTransportState struct {
	warnings transportWarningLimiter
	budget   transportQueueBudget
}

type transportQueueBudget struct {
	mu          sync.Mutex
	maxBytes    int
	queuedBytes int
	transports  map[*ServerWSTransport]int
}

func (m *Manager) attachTransport(transport *ServerWSTransport) {
	transport.attachQueueBudget(&m.transports.budget)
}

func (s *ServerWSTransport) attachQueueBudget(budget *transportQueueBudget) {
	s.writeMu.Lock()
	if s.closed || s.queueBudget != nil {
		s.writeMu.Unlock()
		return
	}
	s.queueBudget = budget
	budget.mu.Lock()
	if budget.transports == nil {
		budget.transports = make(map[*ServerWSTransport]int)
	}
	budget.transports[s] = s.queuedBytes
	budget.queuedBytes += s.queuedBytes
	budget.mu.Unlock()
	s.writeMu.Unlock()

	for {
		budget.mu.Lock()
		if budget.queuedBytes <= budget.limitLocked() {
			budget.mu.Unlock()
			return
		}
		victim := budget.largestLocked(s, 0)
		budget.mu.Unlock()
		if victim == nil {
			return
		}
		victim.evictForNodeQueue(s, 0)
	}
}

// Queue accounting always takes writeMu before budget.mu; budget.mu is never
// held while acquiring a transport lock.
func (s *ServerWSTransport) reserveNodeBytesLocked(size int) *ServerWSTransport {
	budget := s.queueBudget
	if budget == nil {
		return nil
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.queuedBytes+size <= budget.limitLocked() {
		budget.queuedBytes += size
		budget.transports[s] += size
		return nil
	}
	return budget.largestLocked(s, size)
}

func (s *ServerWSTransport) releaseNodeBytesLocked(size int) {
	budget := s.queueBudget
	if budget == nil {
		return
	}
	budget.mu.Lock()
	queued := budget.transports[s]
	if size > queued {
		size = queued
	}
	budget.transports[s] = queued - size
	budget.queuedBytes -= size
	budget.mu.Unlock()
}

func (s *ServerWSTransport) releaseAllNodeBytesLocked() {
	budget := s.queueBudget
	if budget == nil {
		return
	}
	budget.mu.Lock()
	budget.queuedBytes -= budget.transports[s]
	delete(budget.transports, s)
	budget.mu.Unlock()
}

func (b *transportQueueBudget) limitLocked() int {
	if b.maxBytes > 0 {
		return b.maxBytes
	}
	return transportNodeQueueBytes
}

func (b *transportQueueBudget) largestLocked(preferred *ServerWSTransport, preferredExtra int) *ServerWSTransport {
	victim := preferred
	preferredQueued := b.transports[preferred]
	largest := preferredQueued
	// Preserve the one-frame idle admission rule: an idle writer may displace
	// an existing backlog, but a queue that already owns node budget cannot
	// leapfrog a larger queue by excluding the frame that caused overflow.
	if preferredQueued > 0 {
		largest += preferredExtra
	}
	for transport, queued := range b.transports {
		if transport == preferred {
			continue
		}
		if queued > largest {
			victim = transport
			largest = queued
		}
	}
	return victim
}

// evictForNodeQueue rechecks pressure after locking the selected victim. The
// attempted bytes count toward the preferred transport while choosing the
// largest queue, but are not added to the budget unless a later reserve wins.
func (s *ServerWSTransport) evictForNodeQueue(preferred *ServerWSTransport, attemptedBytes int) bool {
	s.writeMu.Lock()
	if s.closed || s.queueBudget == nil {
		s.writeMu.Unlock()
		return false
	}
	budget := s.queueBudget
	budget.mu.Lock()
	_, preferredAttached := budget.transports[preferred]
	if !preferredAttached || budget.queuedBytes+attemptedBytes <= budget.limitLocked() ||
		budget.largestLocked(preferred, attemptedBytes) != s {
		budget.mu.Unlock()
		s.writeMu.Unlock()
		return false
	}
	s.closed = true
	s.closeReason = transportCloseNodeQueueFull
	s.writeQueue = nil
	s.queuedBytes = 0
	budget.queuedBytes -= budget.transports[s]
	delete(budget.transports, s)
	s.writeCond.Broadcast()
	budget.mu.Unlock()
	s.writeMu.Unlock()
	s.finishClose()
	return true
}

func (b *transportQueueBudget) total() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.queuedBytes
}
