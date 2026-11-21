package txrelay

import "github.com/bsv-blockchain/go-sdk/transaction"

// Observer is told about every transaction the broadcaster admits to its
// mempool, whoever sent it: the /broadcast route, the overlay engine or the
// node's own wallet. beef is the BEEF the transaction arrived in, or nil for
// a raw one. It runs on the broadcasting goroutine, so it must not block.
type Observer func(tx *transaction.Transaction, beef []byte)

// SetObserver sets the observer; nil removes it. It may be called at any
// time.
func (b *Broadcaster) SetObserver(fn Observer) {
	if fn == nil {
		b.observer.Store(nil)
		return
	}
	b.observer.Store(&fn)
}

func (b *Broadcaster) observe(tx *transaction.Transaction, beef []byte) {
	if fn := b.observer.Load(); fn != nil {
		(*fn)(tx, beef)
	}
}
