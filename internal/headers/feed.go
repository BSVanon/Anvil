package headers

import (
	"sync"

	p2pwire "github.com/libsv/go-p2p/chaincfg/chainhash"
)

// broadcaster fans a value out to subscriber channels with a non-blocking
// send: a slow or absent subscriber is skipped rather than ever stalling the
// publisher. AddHeaders and ReorgTo publish while holding Store's own write
// lock, so a blocking send here would stall header sync itself.
type broadcaster[T any] struct {
	mu   sync.Mutex
	subs map[chan T]struct{}
}

func newBroadcaster[T any]() *broadcaster[T] {
	return &broadcaster[T]{subs: make(map[chan T]struct{})}
}

// subscribe registers ch and returns an unsubscribe function.
func (b *broadcaster[T]) subscribe(ch chan T) func() {
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}
}

func (b *broadcaster[T]) publish(v T) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- v:
		default:
		}
	}
}

// ReorgNotice is published once per adopted reorg — ReorgTo returning
// adopted=true — never for a plain forward AddHeaders append (which cannot
// fork below the tip by construction). OrphanedHashes is captured from the
// rolled-back range while ReorgTo still holds it: once ReorgTo returns, those
// headers are deleted from the store, so a subscriber could never
// reconstruct them from a later read.
type ReorgNotice struct {
	ForkHeight     uint32
	NewTip         uint32
	OrphanedHashes []p2pwire.Hash
}
