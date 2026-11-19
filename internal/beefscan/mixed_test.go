package beefscan

import (
	"errors"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// mixedLevels builds the shape go-sdk v1.7.7 accepts and then crashes on: two
// parents A and B mined in one block of four transactions, A proven by a
// single-level compound BUMP (leaves at offsets 0 to 3, its root computed
// over two levels) and B by an ordinary two-level BUMP with the same root.
// The subject spends B, then A; go-sdk walks the later input first, so A's
// path is the one B's proof is combined into. With honest false, the subject
// spends A alone and the BEEF holds A's BUMP alone.
func mixedLevels(v2, honest bool) (beef []byte, subject [32]byte) {
	a, b := rawTx(1, nil, []int{1}), rawTx(2, nil, []int{1})
	ta, tb := sha256d(a), sha256d(b)
	x1, x3 := node(7, 1), node(7, 3)
	n0 := sha256d(append(ta[:], x1[:]...))
	compound := bump(100, [][]leaf{{{0, 2, ta}, {1, 0, x1}, {2, 0, tb}, {3, 0, x3}}})
	if honest {
		raw := rawTx(3, []outpoint{{ta, 0}}, []int{1})
		return beefBytes(v2, [][]byte{compound}, []entry{{raw: a, bump: 0}, {raw: raw, bump: -1}}), sha256d(raw)
	}
	tall := bump(100, [][]leaf{{{2, 2, tb}, {3, 0, x3}}, {{0, 0, n0}}})
	raw := rawTx(3, []outpoint{{tb, 0}, {ta, 0}}, []int{1})
	return beefBytes(v2, [][]byte{compound, tall}, []entry{{raw: a, bump: 0}, {raw: b, bump: 1}, {raw: raw, bump: -1}}), sha256d(raw)
}

// panics reports what f panicked with, or nil.
func panics(f func()) (p any) {
	defer func() { p = recover() }()
	f()
	return nil
}

// TestCheckRefusesMixedLevels: a BEEF holding two BUMPs of one block that
// declare different levels is refused in every version, by that rule alone,
// though go-sdk accepts both proofs as valid; the same compound BUMP alone
// passes.
func TestCheckRefusesMixedLevels(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		body, subject := mixedLevels(v2, false)
		if s := Scan(body); s.MixedLevels != 1 || s.BUMPs != 2 || s.Txs != 3 {
			t.Fatalf("v2=%v: Scan = %+v, want 1 mixed height, 2 BUMPs and 3 transactions", v2, s)
		}
		for name, b := range map[string][]byte{"plain": body, "atomic": atomicBEEF(subject, body)} {
			err := Check(b)
			if !errors.Is(err, ErrTooComplex) || !strings.Contains(err.Error(), "heights with BUMPs of mixed levels 1 over the cap of 0") {
				t.Errorf("v2=%v %s: Check = %v, want the mixed-levels refusal", v2, name, err)
			}
		}
		p := panics(func() { _, _, _, _ = transaction.ParseBeef(body) })
		t.Logf("v2=%v: go-sdk ParseBeef of the refused body panicked with %v", v2, p)

		alone, subject := mixedLevels(v2, true)
		for name, b := range map[string][]byte{"plain": alone, "atomic": atomicBEEF(subject, alone)} {
			if err := Check(b); err != nil {
				t.Errorf("v2=%v %s: the compound BUMP alone: %v", v2, name, err)
			}
		}
		if _, _, _, err := transaction.ParseBeef(alone); err != nil {
			t.Errorf("v2=%v: go-sdk refuses the compound BUMP alone: %v", v2, err)
		}
	}
	// Both proofs verify against one root.
	body, _ := mixedLevels(true, false)
	parsed, err := transaction.NewBeefFromBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	ta, tb := sha256d(rawTx(1, nil, []int{1})), sha256d(rawTx(2, nil, []int{1}))
	r1, err1 := parsed.BUMPs[0].ComputeRoot((*chainhash.Hash)(&ta))
	r2, err2 := parsed.BUMPs[1].ComputeRoot((*chainhash.Hash)(&tb))
	if err1 != nil || err2 != nil || !r1.IsEqual(r2) {
		t.Fatalf("roots %v (%v) and %v (%v), want one root", r1, err1, r2, err2)
	}
}
