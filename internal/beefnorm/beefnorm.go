// Package beefnorm reduces an untrusted BEEF to what verifying its subject
// reads, with one canonical proof per block, before anything else works on
// it. The routes that take a BEEF from a client (routeguard.PreVerify for
// /submit and /overlay/submit, spv's Validator.ValidateBEEF for /broadcast)
// parse it only through Parse.
//
// Parse reads the BEEF in one linear pass (transaction.NewBeefFromBytes,
// never ParseBeef's V1 path, which combines proofs superlinearly), finds its
// subject the way go-sdk does (an Atomic BEEF's header txid, a V2 BEEF's
// newest transaction, a V1 BEEF's last one) and keeps what go-sdk's
// Beef.AtomicBytes keeps for that subject: the subject and the ancestry
// reached through its inputs, stopping at txid-only entries and at entries
// their BUMP proves. Every other entry is dropped, with the BUMPs only they
// named.
//
// Dropping rather than refusing is a deliberate divergence from BRC-95, whose
// text makes an Atomic BEEF holding a transaction outside the subject's
// dependency graph invalid ("Transaction Inclusion Rules", "Error
// Conditions"), and from go-sdk v1.7.7's NewBeefFromAtomicBytes, which refuses
// one. ts-sdk 2.0.4 to 2.1.0, which live clients run, builds Atomic BEEFs with
// Beef.getBeefForAtomic, which trims only the transactions newer than the
// subject, so it sends unrelated older ones; ts-sdk overlays and Anvil up to
// v3.4.0 accept them. Parse keeps less than the dependency graph, too: the
// ancestors of a proven transaction are dropped as well. Verification never
// reaches them, so nothing they carry, their BUMPs included, has been checked,
// and the engine would otherwise store them.
//
// The BUMPs left are made canonical, one per block: for each kept proven
// transaction, its txid and its sibling at every level of the block's tree,
// read from its BUMP after MerklePath.Extract has checked it, and nothing
// else (see canonicalize); the proof of a block of one transaction is its
// lone leaf, which is the root. A proof that cannot be extracted, or proofs
// of one block that disagree on the root, the tree height or a node, are
// refused. So a stored proof is never shorter than another of its block,
// which go-sdk v1.7.7 panics on when it later combines them
// (merklepath.go:468-480); every node it holds is one the verification of a
// kept transaction reads; and that verification finds every node it reads,
// where on the minimal paths ts-sdk sends it would compute again each one
// left out. ts-sdk reads the canonical form as it reads its own
// (MerklePath.ts:143-180 in 2.0.4).
package beefnorm

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/BSVanon/Anvil/internal/beefscan"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

var (
	// ErrRefused is wrapped by every refusal of a BEEF go-sdk parses but
	// Parse does not accept: a txid held by more than one entry, an entry
	// naming a BUMP that does not hold it, a proof that cannot be made
	// canonical, and, from Unbacked, an input whose spent output only the
	// extended format supplies. Routes answer 400.
	ErrRefused = errors.New("BEEF refused")

	// ErrNoSubject means the BEEF carries no subject transaction: none is
	// named, the one named is missing, or it is held as a bare txid.
	ErrNoSubject = errors.New("BEEF carries no subject transaction")
)

// BEEF is an untrusted BEEF after Parse.
type BEEF struct {
	// Beef holds the subject and the ancestry its verification reads, with
	// one canonical BUMP per block. Its Version is BEEF_V2 and its NewestTxID
	// is Subject.
	Beef *transaction.Beef
	// Subject is the subject's txid.
	Subject *chainhash.Hash
	// Tx is the subject, its inputs linked as FindTransactionForSigningByHash
	// links them.
	Tx *transaction.Transaction
	// Format is the outer format of the bytes parsed: transaction.BEEF_V1,
	// BEEF_V2 or ATOMIC_BEEF.
	Format uint32
	// Changed reports that the bytes held something Beef does not: an entry
	// or a BUMP dropped, or a proof not already in canonical form.
	Changed bool
	// Shape is what beefscan found in the bytes.
	Shape beefscan.Shape

	raw []byte
}

// Parse prices b with beefscan.Inspect, parses it and normalizes it. It
// returns beefscan's refusal (wrapping beefscan.ErrTooComplex), go-sdk's parse
// error, ErrNoSubject, or an error wrapping ErrRefused.
func Parse(b []byte) (n *BEEF, err error) {
	shape, err := beefscan.Inspect(b)
	if err != nil {
		return nil, err
	}
	format, inner, subject, err := split(b)
	if err != nil {
		return nil, err
	}
	raw, err := transaction.NewBeefFromBytes(inner)
	if err != nil {
		return nil, err
	}
	// Parsing keeps one entry per txid, the last; inputs read before it are
	// linked to the earlier one. Which copy is verified and which is stored
	// would then differ.
	if len(raw.Transactions) != shape.Txs {
		return nil, fmt.Errorf("%w: %d entries hold %d distinct txids", ErrRefused, shape.Txs, len(raw.Transactions))
	}
	if subject == nil {
		subject = raw.NewestTxID
	}
	if subject == nil {
		return nil, ErrNoSubject
	}
	if e := raw.Transactions[*subject]; e == nil || e.Transaction == nil {
		return nil, fmt.Errorf("%w: %s is not held as a transaction", ErrNoSubject, subject)
	}
	defer func() {
		// Extract and ComputeRoot run on attacker-chosen paths; a panic in
		// them refuses this BEEF instead of failing the request goroutine.
		if r := recover(); r != nil {
			n, err = nil, fmt.Errorf("%w: normalizing its proofs panicked: %v", ErrRefused, r)
		}
	}()
	kept, named, err := selectGraph(raw, *subject)
	if err != nil {
		return nil, err
	}
	bumps, changed, err := canonicalize(raw, kept, named)
	if err != nil {
		return nil, err
	}
	unlinkDropped(kept)
	beef := &transaction.Beef{Version: transaction.BEEF_V2, BUMPs: bumps, Transactions: kept, NewestTxID: subject}
	return &BEEF{
		Beef:    beef,
		Subject: subject,
		Tx:      beef.FindTransactionForSigningByHash(subject),
		Format:  format,
		Changed: changed || len(kept) != len(raw.Transactions),
		Shape:   shape,
		raw:     b,
	}, nil
}

// split separates an Atomic BEEF's header from the BEEF it wraps. subject is
// nil for a V1 or V2 BEEF. An Atomic BEEF wrapping another is refused, as
// go-sdk's NewBeefFromAtomicBytes refuses it.
func split(b []byte) (format uint32, inner []byte, subject *chainhash.Hash, err error) {
	if len(b) < 4 || binary.LittleEndian.Uint32(b) != transaction.ATOMIC_BEEF {
		if len(b) >= 4 {
			format = binary.LittleEndian.Uint32(b)
		}
		return format, b, nil, nil
	}
	if len(b) < 36 {
		return 0, nil, nil, fmt.Errorf("provided atomic BEEF length (%d) is too short", len(b))
	}
	inner = b[36:]
	if len(inner) >= 4 && binary.LittleEndian.Uint32(inner) == transaction.ATOMIC_BEEF {
		return 0, nil, nil, fmt.Errorf("an atomic BEEF wraps another atomic BEEF")
	}
	id := chainhash.Hash(b[4:36])
	return transaction.ATOMIC_BEEF, inner, &id, nil
}

// selectGraph walks raw from subject as Beef.AtomicBytes does
// (selectAtomicBeef, beef.go:1781-1810): through the inputs of every entry
// that carries an unproven transaction, stopping at txid-only entries and at
// entries with a BUMP index. It returns the entries reached and, for each BUMP
// index, the txids of the reached entries that name it. AtomicBytes walks on
// past an entry whose BUMP does not hold it; spv.Verify fails on any such
// entry it reaches, so Parse refuses it.
func selectGraph(raw *transaction.Beef, subject chainhash.Hash) (map[chainhash.Hash]*transaction.BeefTx, map[int][]*chainhash.Hash, error) {
	kept := make(map[chainhash.Hash]*transaction.BeefTx)
	named := make(map[int][]*chainhash.Hash)
	leaves := make(map[int]map[chainhash.Hash]struct{}) // each named BUMP's level-0 hashes, built once
	stack := []chainhash.Hash{subject}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := kept[id]; ok {
			continue
		}
		e := raw.Transactions[id]
		kept[id] = e
		switch e.DataFormat {
		case transaction.TxIDOnly:
			continue
		case transaction.RawTxAndBumpIndex:
			if !holds(raw, e.BumpIndex, id, leaves) {
				return nil, nil, fmt.Errorf("%w: transaction %s names BUMP %d, which does not hold it", ErrRefused, id, e.BumpIndex)
			}
			txid := id
			named[e.BumpIndex] = append(named[e.BumpIndex], &txid)
			continue
		}
		for _, in := range e.Transaction.Inputs {
			if _, ok := raw.Transactions[*in.SourceTXID]; ok {
				stack = append(stack, *in.SourceTXID)
			}
		}
	}
	return kept, named, nil
}

// holds reports whether BUMP i of raw has a level-0 leaf whose hash is id, as
// bumpHasMatchingLeaf (beef.go:1850-1860) does, from a set of the BUMP's
// leaves built on first use so that k entries naming one BUMP of n leaves
// cost n + k, not n * k.
func holds(raw *transaction.Beef, i int, id chainhash.Hash, leaves map[int]map[chainhash.Hash]struct{}) bool {
	set, ok := leaves[i]
	if !ok {
		set = make(map[chainhash.Hash]struct{})
		if p := raw.BUMPs[i].Path; len(p) > 0 {
			for _, l := range p[0] {
				if l.Hash != nil && (l.Duplicate == nil || !*l.Duplicate) {
					set[*l.Hash] = struct{}{}
				}
			}
		}
		leaves[i] = set
	}
	_, ok = set[id]
	return ok
}

// unlinkDropped clears the links from kept proven transactions to sources
// Parse dropped, so the Beef holds what its bytes say. Verification never
// follows a proven transaction's inputs.
func unlinkDropped(kept map[chainhash.Hash]*transaction.BeefTx) {
	for _, e := range kept {
		if e.DataFormat != transaction.RawTxAndBumpIndex {
			continue
		}
		for _, in := range e.Transaction.Inputs {
			if _, ok := kept[*in.SourceTXID]; !ok {
				in.SourceTransaction = nil
			}
		}
	}
}
