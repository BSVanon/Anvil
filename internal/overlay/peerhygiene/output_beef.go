package peerhygiene

// Attribution: outputBEEF and walkAncestors are ported from go-sdk v1.7.7
// transaction/beef.go (Transaction.BEEF, collectAncestors and
// walkAncestors), Copyright the go-sdk authors, used under the Open BSV
// License (see the go-sdk LICENSE file). Anvil combines same-block proofs into
// a copy instead of into an ancestor's own MerklePath, and charges the work of
// combining to a budget before doing it.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

// errCombineBudget is returned once an answer's outputs would take more
// combining work than MaxAnswerCombineWork allows.
var errCombineBudget = errors.New("lookup: the outputs' proofs would take too much work to combine")

// combineBudget counts the merkle-path elements an answer's outputs make
// go-sdk's MerklePath.Combine walk: here, while rebuilding each output's BEEF,
// and later, wherever go-sdk parses an output's V1 BEEF (ParseBeef rebuilds
// its ancestry with NewBeefFromTransaction, which combines again). One
// Combine walks both paths about three times (two ComputeRoot calls and the
// merge), so the elements of both paths are what each one costs.
type combineBudget struct {
	used, max uint64
}

func (c *combineBudget) charge(elements uint64) error {
	c.used += elements
	if c.used > c.max {
		return fmt.Errorf("%w: over %d path elements", errCombineBudget, c.max)
	}
	return nil
}

// pathElements counts a merkle path's elements.
func pathElements(mp *transaction.MerklePath) uint64 {
	var n uint64
	for _, level := range mp.Path {
		n += uint64(len(level))
	}
	return n
}

// outputBEEF returns the V1 BEEF of t and its unproven ancestry, byte for
// byte as go-sdk's Transaction.BEEF writes it, with two differences. It
// combines the proofs of ancestors mined in the same block into a copy, where
// Transaction.BEEF combines them into the first such ancestor's MerklePath,
// so each output's BEEF depends on its own ancestry alone and not on which
// outputs were rebuilt before it. And it charges each combination to budget
// before making it.
//
// It also returns parseWork, what go-sdk's ParseBeef will spend combining
// when it parses the result: every proven ancestor after the first from a
// block makes NewBeefFromTransaction combine that block's BUMP with itself.
func outputBEEF(t *transaction.Transaction, txid chainhash.Hash, budget *combineBudget) (beef []byte, parseWork uint64, err error) {
	txns := map[chainhash.Hash]*transaction.Transaction{txid: t}
	var ancestors []chainhash.Hash
	if err := walkAncestors(t, txid, txns, make(map[chainhash.Hash]struct{}), &ancestors); err != nil {
		return nil, 0, err
	}
	var bumps []*transaction.MerklePath
	var combines []uint64 // per BUMP, how many proofs were combined into it
	bumpIndex := map[uint32]int{}
	for _, id := range ancestors {
		mp := txns[id].MerklePath
		if mp == nil {
			continue
		}
		i, ok := bumpIndex[mp.BlockHeight]
		if !ok {
			bumpIndex[mp.BlockHeight] = len(bumps)
			bumps = append(bumps, mp)
			combines = append(combines, 0)
			continue
		}
		if err := budget.charge(pathElements(bumps[i]) + pathElements(mp)); err != nil {
			return nil, 0, err
		}
		if combines[i] == 0 {
			if bumps[i] = bumps[i].Clone(); bumps[i] == nil {
				return nil, 0, errors.New("lookup: copying a merkle path failed")
			}
		}
		combines[i]++
		if err := bumps[i].Combine(mp); err != nil {
			return nil, 0, err
		}
	}
	for i, n := range combines {
		parseWork += n * 2 * pathElements(bumps[i])
	}

	b := new(bytes.Buffer)
	_ = binary.Write(b, binary.LittleEndian, transaction.BEEF_V1)
	b.Write(util.VarInt(len(bumps)).Bytes())
	for _, bump := range bumps {
		b.Write(bump.Bytes())
	}
	b.Write(util.VarInt(len(txns)).Bytes())
	for _, id := range ancestors {
		tx := txns[id]
		b.Write(tx.Bytes())
		if tx.MerklePath != nil {
			b.Write([]byte{1})
			b.Write(util.VarInt(bumpIndex[tx.MerklePath.BlockHeight]).Bytes()) //nolint:gosec // an index into bumps, never negative
		} else {
			b.Write([]byte{0})
		}
	}
	// A copy of exactly its length: the answer keeps every output's BEEF
	// until its query ends, and the buffer's spare capacity could double it.
	return bytes.Clone(b.Bytes()), parseWork, nil
}

// walkAncestors appends to ancestors the txids of t and its unproven
// ancestors, parents before children, and records each in txns, as go-sdk's
// walkAncestors does with allowPartial false.
func walkAncestors(t *transaction.Transaction, txid chainhash.Hash, txns map[chainhash.Hash]*transaction.Transaction,
	visited map[chainhash.Hash]struct{}, ancestors *[]chainhash.Hash) error {
	visited[txid] = struct{}{}
	if t.MerklePath != nil {
		*ancestors = append(*ancestors, txid)
		return nil
	}
	for _, input := range t.Inputs {
		if input.SourceTransaction == nil {
			return fmt.Errorf("missing previous transaction for %s", txid)
		}
		txns[*input.SourceTXID] = input.SourceTransaction
	}
	// Later inputs' ancestors come first, as in go-sdk.
	for i := len(t.Inputs) - 1; i >= 0; i-- {
		input := t.Inputs[i]
		if _, ok := visited[*input.SourceTXID]; ok {
			continue
		}
		if err := walkAncestors(input.SourceTransaction, *input.SourceTXID, txns, visited, ancestors); err != nil {
			return err
		}
	}
	*ancestors = append(*ancestors, txid)
	return nil
}
