package storage

import (
	"fmt"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// safeNewBeefFromBytes parses a stored blob so that one corrupt blob cannot
// crash a whole lookup: a panic becomes an error the caller skips. go-sdk
// v1.2.x panicked on an out-of-range BUMP index; v1.7.7 returns an ordinary
// error, and no known input reaches the recover now.
var newBeefFromBytes = transaction.NewBeefFromBytes

func safeNewBeefFromBytes(blob []byte) (beef *transaction.Beef, err error) {
	defer func() {
		if r := recover(); r != nil {
			beef, err = nil, fmt.Errorf("BEEF parse panicked: %v", r)
		}
	}()
	return newBeefFromBytes(blob)
}

// beefnormParse is a variable so tests can exercise the panic guard.
var beefnormParse = beefnorm.Parse

// normalizedBeefFromBytes returns a stored BEEF with beefnorm's canonical
// proofs. BEEFs written before beefnorm existed can otherwise reach the
// engine's MergeBeef with incompatible proof shapes and panic there.
func normalizedBeefFromBytes(blob []byte) (beef *transaction.Beef, err error) {
	defer func() {
		if r := recover(); r != nil {
			beef, err = nil, fmt.Errorf("BEEF parse panicked: %v", r)
		}
	}()
	n, err := beefnormParse(blob)
	if err != nil {
		return nil, fmt.Errorf("normalize: %w", err)
	}
	return n.Beef, nil
}

// storableBeefBytes serialises a BEEF as V2, whose parser round-trips stored
// data reliably. Clone first: the engine can reuse its BEEF for other topics.
func storableBeefBytes(beef *transaction.Beef) ([]byte, error) {
	b := beef.Clone()
	b.Version = transaction.BEEF_V2
	return b.Bytes()
}
