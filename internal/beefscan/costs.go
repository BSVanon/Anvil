package beefscan

import (
	"cmp"
	"math/bits"
	"slices"
)

// costs derives the three costs and MixedLevels; see Shape for what each
// bounds. ProofCost and MixedLevels group the BUMPs by block height.
func (w *walker) costs() {
	s := &w.shape
	bumps, inputs := uint64(s.BUMPs), uint64(s.Inputs) //nolint:gosec // counts
	withTx := uint64(s.Txs) - w.txidOnly               //nolint:gosec // a count
	s.ChainCost = satMul(withTx, satAdd(withTx, inputs))
	s.FindCost = satMul(w.unproven, bumps)
	if s.BUMPs > len(w.bumps) {
		// Heights were not all kept: price every reference as naming one
		// height whose path has as many levels as a BUMP can declare.
		s.ProofCost = proofCost(w.refs, 255)
		return
	}
	slices.SortFunc(w.bumps, func(a, b bumpStat) int { return cmp.Compare(a.height, b.height) })
	var proof uint64
	for i := 0; i < len(w.bumps); {
		var k uint64
		var depth byte
		mixed := false
		j := i
		for ; j < len(w.bumps) && w.bumps[j].height == w.bumps[i].height; j++ {
			k += w.bumps[j].refs
			depth = max(depth, w.bumps[j].levels, w.bumps[j].need)
			mixed = mixed || w.bumps[j].levels != w.bumps[i].levels
		}
		if mixed {
			s.MixedLevels++
		}
		proof = satAdd(proof, proofCost(k, depth))
		i = j
	}
	s.ProofCost = proof
}

// proofCost is k^2 * (depth+1): the proof work for k entries naming BUMPs of
// one block whose tallest path has depth levels (see Shape.ProofCost).
func proofCost(k uint64, depth byte) uint64 {
	return satMul(satMul(k, k), uint64(depth)+1)
}

func satAdd(a, b uint64) uint64 {
	s, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return ^uint64(0)
	}
	return s
}

func satMul(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return ^uint64(0)
	}
	return lo
}
