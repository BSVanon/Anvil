package api

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/libsv/go-p2p/wire"
)

// arcAccepted reports whether ARC says the network has accepted a payment.
// SEEN_ON_NETWORK is the unmined acceptance state. MINED is only final after
// checkPaymentFinality verifies ARC's proof against this node's header.
func arcAccepted(status string) bool {
	return status == "SEEN_ON_NETWORK" || status == "MINED"
}

// checkARCAcceptance binds ARC's response to the transaction just submitted
// before considering its status.
func checkARCAcceptance(resp *txrelay.ARCResponse, expected *chainhash.Hash) error {
	if resp == nil || expected == nil || resp.TxID != expected.String() {
		got, want := "", ""
		if resp != nil {
			got = resp.TxID
		}
		if expected != nil {
			want = expected.String()
		}
		return paymentNotAccepted(fmt.Sprintf("ARC answered for transaction %q, want %q", got, want))
	}
	if !arcAccepted(resp.Status) {
		return paymentNotAccepted(fmt.Sprintf("ARC did not report the payment as accepted by the network: status %q, want SEEN_ON_NETWORK or MINED", resp.Status))
	}
	return nil
}

func paymentNotAccepted(reason string) error {
	return &paymentRefusal{
		code: codePaymentNotAccepted,
		msg:  reason + "; retry the same transaction shortly, as the network may still accept it, rather than paying with a new one",
	}
}

// maxDirectPaymentDepth is the deepest a mined payment may be below this
// node's header tip: 144 blocks, about the replay window at ten minutes per
// block.
const maxDirectPaymentDepth = 144

// maxPaymentMerklePathHex bounds ARC's BRC-74 proof before parsing it.
const maxPaymentMerklePathHex = 512 << 10

// checkPaymentFinality verifies every MINED response against the submitted
// txid and this node's own header at the reported height. Other accepted
// statuses are unmined and need no merkle proof.
func (pg *PaymentGate) checkPaymentFinality(resp *txrelay.ARCResponse, txid *chainhash.Hash) error {
	if resp.Status != "MINED" {
		return nil
	}
	var tip uint32
	if pg.headerTip != nil {
		tip = pg.headerTip()
	}
	if resp.BlockHeight == 0 || tip == 0 || pg.headerAtHeight == nil {
		return paymentNotFinal(fmt.Sprintf("ARC reports the payment mined at height %d, but this node has no header there", resp.BlockHeight))
	}
	if resp.BlockHeight > tip {
		return paymentNotFinal(fmt.Sprintf("ARC reports the payment mined at height %d above this node's header tip %d", resp.BlockHeight, tip))
	}
	if tip-resp.BlockHeight > maxDirectPaymentDepth {
		return &paymentRefusal{
			code: codePaymentTooOld,
			msg: fmt.Sprintf("the payment was mined at height %d, %d blocks below this node's header tip %d, and a payment may be at most %d blocks deep; pay with a new transaction",
				resp.BlockHeight, tip-resp.BlockHeight, tip, maxDirectPaymentDepth),
		}
	}
	if len(resp.MerklePath) == 0 || len(resp.MerklePath) > maxPaymentMerklePathHex {
		return paymentNotFinal("ARC's MINED answer has no bounded BRC-74 merkle path")
	}
	path, err := transaction.NewMerklePathFromHex(resp.MerklePath)
	if err != nil || path.BlockHeight != resp.BlockHeight {
		return paymentNotFinal("ARC's MINED answer has an invalid merkle path or height")
	}
	root, err := path.ComputeRoot(txid)
	if err != nil {
		return paymentNotFinal("ARC's MINED answer does not prove the submitted transaction")
	}
	raw, err := pg.headerAtHeight(resp.BlockHeight)
	if err != nil {
		return paymentNotFinal(fmt.Sprintf("this node does not yet have header %d", resp.BlockHeight))
	}
	var header wire.BlockHeader
	if len(raw) != 80 || header.Deserialize(bytes.NewReader(raw)) != nil {
		return paymentNotFinal(fmt.Sprintf("this node cannot read header %d", resp.BlockHeight))
	}
	if root.String() != header.MerkleRoot.String() {
		return paymentNotFinal("ARC's merkle path does not match this node's header")
	}
	if resp.BlockHash == "" || !strings.EqualFold(resp.BlockHash, header.BlockHash().String()) {
		return paymentNotFinal("ARC's block hash does not match this node's header")
	}
	return nil
}

func paymentNotFinal(reason string) error {
	return &paymentRefusal{
		code: codePaymentHeadersBehind,
		msg:  reason + "; retry the same transaction once this node can verify it",
	}
}

func (pg *PaymentGate) checkPaymentDepth(resp *txrelay.ARCResponse, txid *chainhash.Hash) error {
	return pg.checkPaymentFinality(resp, txid)
}
