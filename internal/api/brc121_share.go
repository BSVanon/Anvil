package api

import (
	"context"
	"sync"
	"time"
)

const (
	brc121ClientShare = 4
	brc121ClientWait  = 32
	brc121ShareWait   = 15 * time.Second
)

// brc121Shares gives a client a short chance to use a validation place while
// bounding both the work in progress and the goroutines waiting for it.
type brc121Shares struct {
	mu      sync.Mutex
	clients map[string]*brc121ShareState
}

type brc121ShareState struct {
	held, waiting int
	changed       chan struct{}
}

func newBRC121Shares() *brc121Shares {
	return &brc121Shares{clients: make(map[string]*brc121ShareState)}
}

func (s *brc121Shares) take(ctx context.Context, key string) (func(), bool) {
	s.mu.Lock()
	state := s.clients[key]
	if state == nil {
		state = &brc121ShareState{changed: make(chan struct{})}
		s.clients[key] = state
	}
	if state.held < brc121ClientShare {
		state.held++
		s.mu.Unlock()
		return s.release(key, state), true
	}
	if state.waiting >= brc121ClientWait {
		s.mu.Unlock()
		return nil, false
	}
	state.waiting++
	s.mu.Unlock()

	timer := time.NewTimer(brc121ShareWait)
	defer timer.Stop()
	for {
		s.mu.Lock()
		if state.held < brc121ClientShare {
			state.waiting--
			state.held++
			s.mu.Unlock()
			return s.release(key, state), true
		}
		changed := state.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-timer.C:
			s.stopWaiting(key, state)
			return nil, false
		case <-ctx.Done():
			s.stopWaiting(key, state)
			return nil, false
		}
	}
}

func (s *brc121Shares) release(key string, state *brc121ShareState) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			state.held--
			close(state.changed)
			state.changed = make(chan struct{})
			if state.held == 0 && state.waiting == 0 {
				delete(s.clients, key)
			}
			s.mu.Unlock()
		})
	}
}

func (s *brc121Shares) stopWaiting(key string, state *brc121ShareState) {
	s.mu.Lock()
	state.waiting--
	if state.held == 0 && state.waiting == 0 {
		delete(s.clients, key)
	}
	s.mu.Unlock()
}

func (s *brc121Shares) counts(key string) (held, waiting int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state := s.clients[key]; state != nil {
		return state.held, state.waiting
	}
	return 0, 0
}
