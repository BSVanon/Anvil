package ordtrack

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// The first three cases are BRC-159's examples ("Examples").
func TestForward(t *testing.T) {
	cases := []struct {
		name     string
		inputs   []uint64
		tip      int
		outputs  []uint64
		wantKind Kind
		wantVout int
	}{
		{"simple transfer, token input first", []uint64{1, 10_000}, 0, []uint64{1, 4_000, 5_998}, Transfer, 0},
		{"counts not indexes, funding before the token on both sides", []uint64{3_000, 1, 5_000}, 1, []uint64{2_000, 1_000, 1, 4_999}, Transfer, 2},
		{"two tokens in one tx, token A", []uint64{1, 1, 10_000}, 0, []uint64{1, 1, 9_998}, Transfer, 0},
		{"two tokens in one tx, token B", []uint64{1, 1, 10_000}, 1, []uint64{1, 1, 9_998}, Transfer, 1},
		{"burn: no output reaches the sat", []uint64{5_000, 1}, 1, []uint64{4_000}, Burn, -1},
		{"burn: no outputs", []uint64{1}, 0, nil, Burn, -1},
		{"sat lands in an output worth more than 1", []uint64{3_000, 1}, 1, []uint64{2_000, 2_000}, End, 1},
		{"token first into a large output", []uint64{1, 10_000}, 0, []uint64{5_000, 5_000}, End, 0},
		{"tip input at index 2", []uint64{1, 1, 1}, 2, []uint64{1, 1, 1}, Transfer, 2},
		{"running total reaches the sat exactly at a 1-sat output", []uint64{3_000, 1}, 1, []uint64{3_000, 1}, Transfer, 1},
		{"running total one short of the sat", []uint64{3_000, 1}, 1, []uint64{2_999, 2}, End, 1},
		{"zero-value outputs before the sat", []uint64{1}, 0, []uint64{0, 0, 1}, Transfer, 2},
		{"later inputs do not move the sat", []uint64{2_000, 1}, 1, []uint64{2_000, 1, 50_000}, Transfer, 1},
		{"tip index out of range", []uint64{1}, 1, []uint64{1}, Burn, -1},
		{"negative tip index", []uint64{1}, -1, []uint64{1}, Burn, -1},
		{"sums saturate instead of wrapping", []uint64{math.MaxUint64, 1}, 1, []uint64{math.MaxUint64, 1}, End, 0},
	}
	for _, c := range cases {
		kind, vout := Forward(c.inputs, c.tip, c.outputs)
		if kind != c.wantKind || vout != c.wantVout {
			t.Errorf("%s: Forward = %s %d, want %s %d", c.name, kind, vout, c.wantKind, c.wantVout)
		}
	}
}

// synth builds unsigned transactions for the backward walk, which reads
// only values and outpoints.
type synth map[string]*transaction.Transaction

// tx adds a transaction spending ins ("txid_vout" of earlier ones, or a
// made-up outpoint) into outs, and returns its txid.
func (s synth) tx(ins []string, outs ...uint64) string {
	tx := transaction.NewTransaction()
	for _, in := range ins {
		txid, vout, ok := splitOutpoint(in)
		if !ok {
			panic(in)
		}
		h, err := chainhash.NewHashFromHex(txid)
		if err != nil {
			panic(err)
		}
		tx.AddInput(&transaction.TransactionInput{SourceTXID: h, SourceTxOutIndex: vout, SequenceNumber: transaction.DefaultSequenceNumber})
	}
	for _, v := range outs {
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: v, LockingScript: &script.Script{}})
	}
	id := tx.TxID().String()
	s[id] = tx
	return id
}

func (s synth) load(_ context.Context, txid string) (*transaction.Transaction, error) {
	if tx := s[txid]; tx != nil {
		return tx, nil
	}
	return nil, fmt.Errorf("%s not found", txid)
}

func TestProveOriginWalksBackToTheOrigin(t *testing.T) {
	s := synth{}
	made := outpointString(fmt.Sprintf("%064x", 7), 0)
	fund := s.tx([]string{made}, 100_000)
	origin := s.tx([]string{outpointString(fund, 0)}, 1, 90_000)
	// Token input first, funding after it: sat #1 lands in output 0.
	fund2 := s.tx([]string{made}, 10_000)
	t1 := s.tx([]string{outpointString(origin, 0), outpointString(fund2, 0)}, 1, 9_000)
	// Funding before the token on both sides (BRC-159's second example).
	fund3 := s.tx([]string{made}, 3_000)
	t2 := s.tx([]string{outpointString(fund3, 0), outpointString(t1, 0)}, 2_000, 1_000, 1, 4)
	// The token's sat lands in a 5,000-sat output: the chain ends there, and
	// the 1-sat output after it, fed by the funding input, is a new origin.
	fund4 := s.tx([]string{made}, 6_000)
	end := s.tx([]string{outpointString(t2, 2), outpointString(fund4, 0)}, 5_000, 1, 900)

	o := outpointString(origin, 0)
	for _, from := range []string{o, outpointString(t1, 0), outpointString(t2, 2)} {
		got, err := proveOrigin(context.Background(), from, s.load, 10)
		if err != nil || got != o {
			t.Errorf("proveOrigin(%s) = %s, %v; want %s", from, got, err, o)
		}
	}
	if got, err := proveOrigin(context.Background(), outpointString(end, 1), s.load, 10); err != nil || got != outpointString(end, 1) {
		t.Errorf("a 1-sat output fed by a larger input is its own origin: got %s, %v", got, err)
	}
	if got, err := proveOrigin(context.Background(), o, s.load, 0); err != nil || got != o {
		t.Errorf("an origin with no hops allowed: got %s, %v", got, err)
	}
	if _, err := proveOrigin(context.Background(), outpointString(t2, 2), s.load, 1); !errors.Is(err, errWalkTooLong) {
		t.Errorf("two hops with one allowed: err = %v, want errWalkTooLong", err)
	}
	if _, err := proveOrigin(context.Background(), outpointString(t1, 1), s.load, 10); !errors.Is(err, errNotOneSat) {
		t.Errorf("a 9,000-sat output: err = %v, want errNotOneSat", err)
	}
	if _, err := proveOrigin(context.Background(), outpointString(fund, 0), s.load, 10); !errors.Is(err, errNotOneSat) {
		t.Errorf("a funding output: err = %v, want errNotOneSat", err)
	}
	delete(s, fund)
	if _, err := proveOrigin(context.Background(), outpointString(t1, 0), s.load, 10); err == nil {
		t.Error("a walk through a transaction it cannot load must fail")
	}
}

func TestProveOriginRefusesTooManyInputs(t *testing.T) {
	s := synth{}
	made := fmt.Sprintf("%064x", 9)
	ins := make([]string, maxInputs+1)
	for i := range ins {
		ins[i] = outpointString(made, uint32(i)) // #nosec G115 // small test index
	}
	wide := s.tx(ins, 1)
	if _, err := proveOrigin(context.Background(), outpointString(wide, 0), s.load, 10); err == nil {
		t.Errorf("a transaction with %d inputs must be refused", maxInputs+1)
	}
}

func TestOutpointForms(t *testing.T) {
	txid := fmt.Sprintf("%064x", 0xab)
	upper := fmt.Sprintf("%064X", 0xab)
	for in, want := range map[string]string{
		txid + "_0":  txid + "_0",
		txid + ".3":  txid + "_3",
		upper + "_1": txid + "_1",
	} {
		if got, ok := NormalizeOutpoint(in); !ok || got != want {
			t.Errorf("NormalizeOutpoint(%s) = %s, %v; want %s", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", txid, txid + "_", txid + "_-1", txid + "_4294967296", txid[:63] + "_0", "zz" + txid[2:] + "_0", txid + "_0_1"} {
		if got, ok := NormalizeOutpoint(bad); ok {
			t.Errorf("NormalizeOutpoint(%q) = %s, want refused", bad, got)
		}
	}
}
