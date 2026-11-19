package beefnorm

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Graph is what spv.Verify walks from the subject: proveMined and
// verifyUnmined (spv/verify.go:237-270, 374-411) follow SourceTransaction
// links breadth first, once per Transaction value, and stop at a transaction
// with a merkle path.
type Graph struct {
	// Unmined are the transactions without a merkle path, the subject first:
	// the ones whose scripts spv.Verify runs.
	Unmined []*transaction.Transaction
	// Heights holds the block height each proven transaction reached claims,
	// by txid: what spv.Verify records once it has verified the path, and
	// the height that sets the script flags for an output it created.
	Heights map[chainhash.Hash]uint32
}

// Graph walks n's subject as spv.Verify does.
func (n *BEEF) Graph() Graph {
	g := Graph{Heights: make(map[chainhash.Hash]uint32)}
	type node struct {
		tx   *transaction.Transaction
		txid chainhash.Hash
	}
	seen := map[*transaction.Transaction]bool{n.Tx: true}
	for queue := []node{{n.Tx, *n.Subject}}; len(queue) > 0; queue = queue[1:] {
		at := queue[0]
		if at.tx.MerklePath != nil {
			g.Heights[at.txid] = at.tx.MerklePath.BlockHeight
			continue
		}
		g.Unmined = append(g.Unmined, at.tx)
		for _, in := range at.tx.Inputs {
			// Parsing links an input only to the entry its SourceTXID names.
			if src := in.SourceTransaction; src != nil && !seen[src] {
				seen[src] = true
				queue = append(queue, node{src, *in.SourceTXID})
			}
		}
	}
	return g
}

// SpentOutput is the output spv.Verify takes input to spend (spentOutput,
// spv/verify.go:749-758): its source transaction's output when it carries
// one, nil when that transaction has no such output, and otherwise the
// output the extended format supplies, which may be nil.
// TransactionInput.SourceTxOutput differs: it falls back to the supplied
// output when the source transaction lacks the index.
func SpentOutput(in *transaction.TransactionInput) *transaction.TransactionOutput {
	src := in.SourceTransaction
	if src == nil {
		return in.SourceTxOutput()
	}
	if int64(in.SourceTxOutIndex) >= int64(len(src.Outputs)) {
		return nil
	}
	return src.Outputs[in.SourceTxOutIndex]
}

// Unbacked returns an error wrapping ErrRefused when an input whose scripts
// spv.Verify runs spends an output that only the BEEF's extended format
// supplies, with no source transaction in the BEEF linked to it. spv.Verify
// trusts such an output as given (spv/verify.go:78-84): its amount and script
// are whatever the client wrote. The overlay routes refuse it; a BEEF carries
// the source transaction of every unmined input.
func (n *BEEF) Unbacked() error {
	for _, tx := range n.Graph().Unmined {
		for vin, in := range tx.Inputs {
			if in.SourceTransaction == nil && in.SourceTxOutput() != nil {
				return fmt.Errorf("%w: input %d of %s spends an output the BEEF supplies only in extended format", ErrRefused, vin, tx.TxID())
			}
		}
	}
	return nil
}

// Atomic serializes the subject and the kept ancestry as an Atomic BEEF of a
// V2 BEEF (Beef.AtomicBytes), the form the engine hands its lookup services.
func (n *BEEF) Atomic() ([]byte, error) {
	return n.Beef.AtomicBytes(n.Subject)
}

// Bytes is the BEEF as received when nothing changed, and otherwise the kept
// BEEF in the format received: V1 for V1, V2 for V2, and an Atomic BEEF of a
// V2 BEEF for an Atomic one.
func (n *BEEF) Bytes() ([]byte, error) {
	if !n.Changed {
		return n.raw, nil
	}
	switch n.Format {
	case transaction.ATOMIC_BEEF:
		return n.Atomic()
	case transaction.BEEF_V1:
		v1 := *n.Beef
		v1.Version = transaction.BEEF_V1
		return v1.Bytes()
	default:
		return n.Beef.Bytes()
	}
}
