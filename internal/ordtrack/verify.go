package ordtrack

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/BSVanon/Anvil/internal/content"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// Bounds on verifying one candidate spend.
const (
	maxInputs     = 1000     // inputs per transaction read
	maxFetchBytes = 32 << 20 // transaction bytes fetched per candidate
	// verifyTimeout is the deadline spv.Verify gets; it has none of its own.
	verifyTimeout = 20 * time.Second
)

var (
	// errRetryLater means the spend cannot be verified yet: an ancestor
	// more than one unmined level deep, the fetch budget spent, or data
	// this path may not fetch. Nothing changes; the spend is tried again
	// the next time a source reports it.
	errRetryLater = errors.New("cannot verify the spend yet")
	// errInvalid means the spend fails verification.
	errInvalid = errors.New("spend fails verification")
)

// Status is what the node's tx-status path knows about a transaction.
type Status struct {
	Known  bool
	Mined  bool
	Height uint32
}

// Source supplies what a candidate's own BEEF does not carry.
type Source interface {
	// Tx returns txid's transaction, with its merkle path set when the
	// node can prove it mined. What it returns must hash to txid.
	Tx(ctx context.Context, txid string) (*transaction.Transaction, error)
	// Status returns txid's chain status from the node's tx-status path.
	Status(ctx context.Context, txid string) (Status, error)
}

// candidate is a reported spend of a chain's current tip.
type candidate struct {
	origin string
	tip    string // the outpoint spent
	txid   string // the spending transaction
	beef   *beefnorm.BEEF
	gossip bool // reported by a peer's hint
}

// spend is a verified spend of a tip.
type spend struct {
	kind        Kind
	txid        string
	vout        int
	inscribed   bool
	contentType string
	mined       bool
	height      uint32
}

// verifier checks candidate spends. spvVerify is spv.Verify; tests count
// its calls.
type verifier struct {
	source    Source
	chain     chaintracker.ChainTracker
	heights   scriptflag.ActivationHeights
	spvVerify func(context.Context, *transaction.Transaction, chaintracker.ChainTracker, transaction.FeeModel) (bool, error)
}

func newVerifier(source Source, chain chaintracker.ChainTracker) *verifier {
	heights := scriptflag.MainNetActivationHeights
	if p, ok := chain.(spv.ActivationHeightsProvider); ok {
		heights = p.ActivationHeights()
	}
	return &verifier{source: source, chain: chain, heights: heights, spvVerify: spv.Verify}
}

// verify checks that c.txid spends c.tip and returns what it does to the
// token. trusted holds the txids of chain links already verified; their
// outputs are taken as recorded instead of being proven again, which keeps
// a chain of unmined updates within the one-unmined-level rule. With fetch
// false nothing is fetched: every transaction must be in c.beef.
//
// Every input value the forward rule reads comes from a source transaction
// that hashes to the txid the input names. A mined candidate needs only its
// merkle path, which spv.Verify checks against the node's headers before
// any input is read. An unmined one has its token input's unlocking script
// run against the tip first, so a transaction that merely names the tip
// costs one script run; then spv.Verify checks it whole, scripts and
// amounts, with its unmined parents, each parent's own inputs mined or
// trusted.
func (v *verifier) verify(ctx context.Context, c candidate, trusted map[string]bool, fetch bool) (*spend, error) {
	r := &reader{v: v, fetch: fetch, held: heldTxs(c.beef)}
	tx, err := r.tx(ctx, c.txid)
	if err != nil {
		return nil, err
	}
	if len(tx.Inputs) > maxInputs {
		return nil, fmt.Errorf("%w: %d inputs, more than %d", errInvalid, len(tx.Inputs), maxInputs)
	}
	tipTxid, tipVout, ok := splitOutpoint(c.tip)
	if !ok {
		return nil, fmt.Errorf("%w: invalid tip %q", errInvalid, c.tip)
	}
	tipIdx := -1
	for i, in := range tx.Inputs {
		if in.SourceTXID != nil && in.SourceTxOutIndex == tipVout && in.SourceTXID.String() == tipTxid {
			tipIdx = i
			break
		}
	}
	if tipIdx < 0 {
		return nil, fmt.Errorf("%w: %s does not spend %s", errInvalid, c.txid, c.tip)
	}

	mined := tx.MerklePath != nil
	if mined {
		if err := v.spv(ctx, tx); err != nil {
			return nil, err
		}
	} else if err := r.tipUnlocks(ctx, tx, tipIdx, tipTxid, tipVout); err != nil {
		return nil, err
	}

	values := make([]uint64, tipIdx+1)
	for i, in := range tx.Inputs {
		if mined && i > tipIdx {
			// Consensus checked a mined transaction's inputs; the sat's
			// position depends only on those before the token's.
			break
		}
		out, err := r.spentOutput(ctx, in, mined, trusted)
		if err != nil {
			return nil, err
		}
		if i == tipIdx && out.Satoshis != 1 {
			return nil, fmt.Errorf("%w: tip %s holds %d sats", errInvalid, c.tip, out.Satoshis)
		}
		if i <= tipIdx {
			values[i] = out.Satoshis
		}
	}
	if !mined {
		if err := v.spv(ctx, tx); err != nil {
			return nil, err
		}
	}

	outs := make([]uint64, len(tx.Outputs))
	for i, o := range tx.Outputs {
		outs[i] = o.Satoshis
	}
	kind, vout := Forward(values, tipIdx, outs)
	s := &spend{kind: kind, txid: c.txid, vout: vout, mined: mined}
	if mined {
		s.height = tx.MerklePath.BlockHeight
	}
	if kind == Transfer {
		if env, ok := content.ParseOrdEnvelope(tx.Outputs[vout].LockingScript.Bytes()); ok {
			s.inscribed, s.contentType = true, env.ContentType
		}
	}
	return s, nil
}

// spv runs spv.Verify on tx under verifyTimeout.
func (v *verifier) spv(ctx context.Context, tx *transaction.Transaction) error {
	vctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	valid, err := v.spvVerify(vctx, tx, v.chain, nil)
	if err != nil || !valid {
		return fmt.Errorf("%w: %v", errInvalid, err)
	}
	return nil
}

// reader resolves the transactions one candidate's verification reads:
// those its BEEF holds first, then, when fetching is allowed, the Source's,
// within maxFetchBytes.
type reader struct {
	v       *verifier
	fetch   bool
	held    map[string]*transaction.Transaction
	fetched int
}

func heldTxs(n *beefnorm.BEEF) map[string]*transaction.Transaction {
	held := map[string]*transaction.Transaction{}
	if n == nil || n.Beef == nil {
		return held
	}
	for id, e := range n.Beef.Transactions {
		if e != nil && e.Transaction != nil {
			held[id.String()] = e.Transaction
		}
	}
	return held
}

func (r *reader) tx(ctx context.Context, txid string) (*transaction.Transaction, error) {
	if tx := r.held[txid]; tx != nil {
		return tx, nil
	}
	if !r.fetch {
		return nil, fmt.Errorf("%w: %s is not in the BEEF", errRetryLater, txid)
	}
	tx, err := r.v.source.Tx(ctx, txid)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch %s: %v", errRetryLater, txid, err)
	}
	if tx.TxID().String() != txid {
		return nil, fmt.Errorf("%w: fetched bytes for %s hash to %s", errInvalid, txid, tx.TxID())
	}
	r.fetched += tx.Size()
	if r.fetched > maxFetchBytes {
		return nil, fmt.Errorf("%w: more than %d bytes fetched", errRetryLater, maxFetchBytes)
	}
	r.held[txid] = tx
	return tx, nil
}

// tipUnlocks runs the unlocking script of tx's input idx against the tip it
// spends, under the rules spv.Verify applies to it: the tip's verified era
// when its transaction is proven mined, current rules otherwise. Only the
// tip's own transaction is read. A pay-to-script-hash-shaped tip, whose era
// spv.Verify settles differently, is left to spv.Verify.
func (r *reader) tipUnlocks(ctx context.Context, tx *transaction.Transaction, idx int, tipTxid string, tipVout uint32) error {
	src, err := r.tx(ctx, tipTxid)
	if err != nil {
		return err
	}
	if int(tipVout) >= len(src.Outputs) {
		return fmt.Errorf("%w: %s has no output %d", errInvalid, tipTxid, tipVout)
	}
	out := src.Outputs[tipVout]
	if out.Satoshis != 1 || out.LockingScript == nil {
		return fmt.Errorf("%w: tip %s_%d holds %d sats", errInvalid, tipTxid, tipVout, out.Satoshis)
	}
	if out.LockingScript.IsP2SH() {
		return nil
	}
	coin := uint32(math.MaxUint32)
	if src.MerklePath != nil {
		coin = src.MerklePath.BlockHeight
	}
	in := tx.Inputs[idx]
	in.SourceTransaction = nil
	in.SetSourceTxOutput(out)
	vctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	if err := interpreter.NewEngine().Execute(
		interpreter.WithTx(tx, idx, out),
		interpreter.WithFlags(r.v.heights.BlockValidationFlags(coin, math.MaxUint32)),
		interpreter.WithContext(vctx),
	); err != nil {
		return fmt.Errorf("%w: the token input does not unlock the tip: %v", errInvalid, err)
	}
	return nil
}

// spentOutput resolves the output in spends and links it the way
// spv.Verify should read it. Any output a mined spender spends is set as
// given; a source proven mined is linked, for spv.Verify to check its path;
// a trusted link's output is set as given; any other source is linked and
// must have only mined or trusted parents. An output the transaction format
// itself supplied is never used.
func (r *reader) spentOutput(ctx context.Context, in *transaction.TransactionInput, mined bool, trusted map[string]bool) (*transaction.TransactionOutput, error) {
	if in.SourceTXID == nil {
		return nil, fmt.Errorf("%w: input names no source", errInvalid)
	}
	srcTxid := in.SourceTXID.String()
	src, err := r.tx(ctx, srcTxid)
	if err != nil {
		return nil, err
	}
	if int(in.SourceTxOutIndex) >= len(src.Outputs) {
		return nil, fmt.Errorf("%w: %s has no output %d", errInvalid, srcTxid, in.SourceTxOutIndex)
	}
	out := src.Outputs[in.SourceTxOutIndex]
	in.SetSourceTxOutput(nil)
	in.SourceTransaction = nil
	switch {
	case mined || (src.MerklePath == nil && trusted[srcTxid]):
		in.SetSourceTxOutput(out)
	case src.MerklePath != nil:
		in.SourceTransaction = src
	default:
		if err := r.oneUnminedLevel(ctx, src, trusted); err != nil {
			return nil, err
		}
		in.SourceTransaction = src
	}
	return out, nil
}

// oneUnminedLevel accepts a mined source, or an unmined one whose own
// inputs all spend mined or trusted transactions. Anything deeper is
// errRetryLater.
func (r *reader) oneUnminedLevel(ctx context.Context, src *transaction.Transaction, trusted map[string]bool) error {
	if src.MerklePath != nil {
		return nil
	}
	if len(src.Inputs) > maxInputs {
		return fmt.Errorf("%w: an ancestor has more than %d inputs", errInvalid, maxInputs)
	}
	for _, in := range src.Inputs {
		if in.SourceTXID == nil {
			return fmt.Errorf("%w: input names no source", errInvalid)
		}
		id := in.SourceTXID.String()
		parent, err := r.tx(ctx, id)
		if err != nil {
			return err
		}
		if int(in.SourceTxOutIndex) >= len(parent.Outputs) {
			return fmt.Errorf("%w: %s has no output %d", errInvalid, id, in.SourceTxOutIndex)
		}
		in.SetSourceTxOutput(nil)
		in.SourceTransaction = nil
		switch {
		case parent.MerklePath != nil:
			in.SourceTransaction = parent
		case trusted[id]:
			in.SetSourceTxOutput(parent.Outputs[in.SourceTxOutIndex])
		default:
			return fmt.Errorf("%w: unmined ancestry deeper than one level", errRetryLater)
		}
	}
	return nil
}
