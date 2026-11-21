// Package ordtrack follows the chains of 1Sat ordinal tokens (BRC-159) that
// start at a bounded set of tracked origins, and records which links along
// them carry an inscription (BRC-160), so a node can serve an origin's
// latest version and any earlier one by number.
//
// A link is accepted only after this node verifies the spend itself: the
// forward rule run on input values taken from verified source transactions,
// and go-sdk's spv.Verify against the node's own headers. Who reported the
// spend, a peer, a poll or a client, is never trusted.
package ordtrack

// Kind is what spending a token's current outpoint does to the token.
type Kind int

// BRC-159's three outcomes of the forward rule.
const (
	// Transfer: the token's sat lands in a 1-sat output, the new location.
	Transfer Kind = iota + 1
	// End: it lands in an output worth more than 1 sat. The chain ends.
	End
	// Burn: no output reaches it, so it is paid as fee. The chain ends.
	Burn
)

func (k Kind) String() string {
	switch k {
	case Transfer:
		return "transfer"
	case End:
		return "end"
	case Burn:
		return "burn"
	default:
		return "unknown"
	}
}

// Forward is BRC-159's forward rule for the 1-sat input at tipInputIndex:
// its sat's position is the sum of the values of every earlier input, plus
// one. The first output whose running total reaches that position holds the
// sat: an output of exactly 1 sat is a Transfer to it, a larger one an End,
// and when no output reaches it the sat is a Burn (vout -1).
//
// inputs holds the value of each input up to and including the token's;
// later inputs do not move the sat, so they may be left out. outputs holds
// every output's value, in order.
func Forward(inputs []uint64, tipInputIndex int, outputs []uint64) (kind Kind, vout int) {
	if tipInputIndex < 0 || tipInputIndex >= len(inputs) {
		return Burn, -1
	}
	position := uint64(1)
	for _, v := range inputs[:tipInputIndex] {
		position = saturatingAdd(position, v)
	}
	var total uint64
	for i, v := range outputs {
		total = saturatingAdd(total, v)
		if total >= position {
			if v == 1 {
				return Transfer, i
			}
			return End, i
		}
	}
	return Burn, -1
}

// saturatingAdd is a+b, held at the largest uint64 instead of wrapping.
func saturatingAdd(a, b uint64) uint64 {
	if a+b < a {
		return ^uint64(0)
	}
	return a + b
}
