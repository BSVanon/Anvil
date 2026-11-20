package api

import (
	"fmt"

	"github.com/BSVanon/Anvil/internal/txrelay"
)

// arcAccepted reports whether an ARC txStatus shows that the network accepted
// a payment transaction, which means its inputs exist and are unspent. Both
// payment paths ask it after broadcasting (verifyProof when the challenge
// requires mempool acceptance, and verifyDirectPayment always).
//
// The statuses, in ARC's own order (ARC metamorph_api.pb.go:32-45; each
// meaning is ARC's README, lines 197-210):
//
//   - UNKNOWN, QUEUED, RECEIVED, STORED: still inside ARC, before any node
//     has seen the transaction. Refused.
//   - ANNOUNCED_TO_NETWORK, REQUESTED_BY_NETWORK, SENT_TO_NETWORK: a node was
//     told about it, asked for it or sent it; none of these says the node
//     accepted it. Refused.
//   - ACCEPTED_BY_NETWORK: "accepted by a connected Bitcoin node on the ZMQ
//     interface", and never set when ARC has no ZMQ connection. Refused for
//     now; whether to accept it is a question for review.
//   - SEEN_IN_ORPHAN_MEMPOOL: sent to a node, but "parent transaction was not
//     found", so an input may not exist. Refused. go-sdk's ARC broadcaster
//     treats any status containing ORPHAN as a failure (go-sdk v1.7.7
//     transaction/broadcaster/arc.go:186-196,219-225).
//   - SEEN_ON_NETWORK: "seen on the Bitcoin network and propagated to other
//     nodes", set when ARC hears the transaction announced back from a node
//     other than the one it sent it to. Accepted. It is also the status ARC
//     waits for by default before it answers a submit (ARC
//     internal/metamorph/server.go:276-278), for up to 5 seconds by default
//     (internal/api/handler/default.go:32).
//   - DOUBLE_SPEND_ATTEMPTED, REJECTED, MINED_IN_STALE_BLOCK: failures, as
//     go-sdk's ARC broadcaster also treats them. Refused.
//   - MINED: "mined into a block by a mining node". Accepted.
//
// txrelay's own broadcast path counts the same two statuses as accepted
// (internal/txrelay/broadcast.go).
func arcAccepted(status string) bool {
	return status == "SEEN_ON_NETWORK" || status == "MINED"
}

// checkARCAcceptance refuses a payment whose broadcast ARC did not report as
// accepted by the network (arcAccepted).
func checkARCAcceptance(resp *txrelay.ARCResponse) error {
	if !arcAccepted(resp.Status) {
		return &paymentRefusal{
			code: codePaymentNotAccepted,
			msg:  fmt.Sprintf("ARC did not report the payment as accepted by the network: status %q, want SEEN_ON_NETWORK or MINED", resp.Status),
		}
	}
	return nil
}
