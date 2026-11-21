package beefnorm

import (
	"errors"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// ErrBareV2 is the relay-format rule shared by every BEEF ingress: a V2
// BEEF is accepted only when an Atomic BEEF names its subject transaction.
var ErrBareV2 = errors.New("a V2 BEEF is accepted only inside an Atomic BEEF")

// ValidateRelayFormat applies the relay-format rules that follow Parse.
func ValidateRelayFormat(n *BEEF) error {
	if n != nil && n.Format == transaction.BEEF_V2 {
		return ErrBareV2
	}
	return nil
}
