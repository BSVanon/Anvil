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
//     interface", and never set when ARC has no ZMQ connection. Refused, as
//     the narrower choice; accepting it is still an open question.
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

// maxDirectPaymentDepth is the deepest a direct payment that ARC reports as
// MINED may be below this node's header tip: 144 blocks, about 24 hours at
// 10 minutes a block, the same span as directPaymentReplayWindow
// (payment_replay.go).
const maxDirectPaymentDepth = 144

// maxPaymentHeightAboveTip is how far above this node's header tip ARC may
// report a MINED direct payment: 2 blocks, the lag ordinary block
// propagation leaves between ARC and this node. A height further above the
// tip means this node's headers are behind, so it cannot tell how deep the
// payment is.
const maxPaymentHeightAboveTip = 2

// checkPaymentDepth refuses a direct payment that ARC reports as MINED more
// than maxDirectPaymentDepth blocks below the node's header tip, so a payment
// the replay set no longer remembers, after eviction or a restart, cannot pay
// again once it is buried. A MINED report whose depth the node cannot work
// out is refused as well: one with no block height, one when the node has no
// header tip, and one more than maxPaymentHeightAboveTip blocks above the
// tip, which a node whose headers have stopped syncing would otherwise accept
// whatever the payment's real depth. Other accepted statuses are unmined and
// pass.
func (pg *PaymentGate) checkPaymentDepth(resp *txrelay.ARCResponse) error {
	if resp.Status != "MINED" {
		return nil
	}
	var tip uint32
	if pg.headerTip != nil {
		tip = pg.headerTip()
	}
	if resp.BlockHeight == 0 || tip == 0 {
		return &paymentRefusal{
			code: codePaymentTooOld,
			msg: fmt.Sprintf("ARC reports the payment mined at height %d and this node's header tip is %d, so the node cannot confirm it is recent; pay with a new transaction",
				resp.BlockHeight, tip),
		}
	}
	if resp.BlockHeight > tip && resp.BlockHeight-tip > maxPaymentHeightAboveTip {
		return &paymentRefusal{
			code: codePaymentHeadersBehind,
			msg: fmt.Sprintf("ARC reports the payment mined at height %d, %d blocks above this node's header tip %d: this node's headers are behind, so it cannot confirm how deep the payment is; retry the same transaction once they have caught up",
				resp.BlockHeight, resp.BlockHeight-tip, tip),
		}
	}
	if tip > resp.BlockHeight && tip-resp.BlockHeight > maxDirectPaymentDepth {
		return &paymentRefusal{
			code: codePaymentTooOld,
			msg: fmt.Sprintf("the payment was mined at height %d, %d blocks below this node's header tip %d, and a direct payment may be at most %d blocks deep; pay with a new transaction",
				resp.BlockHeight, tip-resp.BlockHeight, tip, maxDirectPaymentDepth),
		}
	}
	return nil
}
