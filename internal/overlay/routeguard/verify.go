package routeguard

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/beefscan"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// VerifyBudget is how long a submit's scripts may take to verify before the
// engine sees the submit.
const VerifyBudget = 5 * time.Second

// ValidationBudgetCode is the error code of a submit whose scripts did not
// verify within VerifyBudget. The route answers 422.
const ValidationBudgetCode = "ERR_VALIDATION_BUDGET"

var (
	// ErrTooComplex is beefscan's: a BEEF whose structure, or one of whose
	// scripts, is over a cap. The route answers 400 with beefscan.Code.
	ErrTooComplex = beefscan.ErrTooComplex

	// ErrValidationBudget means the scripts did not verify within
	// VerifyBudget.
	ErrValidationBudget = errors.New("transaction scripts did not verify within the validation budget")
)

// Submit is one BEEF submit the guard has parsed and verified, ready for
// engine.SubmitParsedBeef.
type Submit struct {
	Beef *transaction.Beef
	Txid *chainhash.Hash

	t    *Ticket
	once sync.Once
}

// PreVerify does, under the ticket, what engine.Submit does before it admits
// a BEEF, in the engine's order, so a submit costs the engine nothing the
// guard has not paid for. The ticket must hold the body's ReadBody
// reservation on a Scripts route.
//
//  1. beefscan.Check prices the BEEF's structure before anything parses it.
//  2. transaction.ParseBeef, as engine.Submit does (engine.ErrInvalidBeef
//     when it finds no transaction).
//  3. Every topic must be one known reports true (engine.ErrUnknownTopic).
//  4. FindTransactionForSigningByHash links the ancestors
//     (engine.ErrInvalidBeef when the subject is missing).
//  5. scriptWeight prices the scripts (ErrTooComplex past MaxScriptOps), and
//     the ticket returns what ReadBody reserved for them beyond that.
//  6. A submit whose scripts may write new stack elements takes the
//     execution slot.
//  7. The ticket takes a CPU slot.
//  8. spv.Verify runs with ctx, the client's request context, and at most
//     VerifyBudget: ErrValidationBudget when that runs out, ctx's error when
//     the client goes away, and otherwise exactly the error engine.Submit
//     would return. A nil tracker skips this step (tests of fake engines).
//     After a verification in the execution slot the guard collects garbage,
//     so the engine's own verification does not stack on this one's.
//
// On success the caller hands the Submit to engine.SubmitParsedBeef with
// OnSteakReady, which returns the CPU slot and the execution slot once the
// engine has verified and admitted the transaction, and calls Done when the
// engine returns. On error the ticket is the caller's to close.
func (t *Ticket) PreVerify(ctx context.Context, tracker chaintracker.ChainTracker, known func(string) bool, beefBytes []byte, topics []string) (*Submit, error) {
	if err := beefscan.Check(beefBytes); err != nil {
		return nil, err
	}
	beef, parsed, txid, err := transaction.ParseBeef(beefBytes)
	if err != nil {
		return nil, err
	}
	if parsed == nil {
		return nil, engine.ErrInvalidBeef
	}
	for _, topic := range topics {
		if !known(topic) {
			return nil, engine.ErrUnknownTopic
		}
	}
	tx := beef.FindTransactionForSigningByHash(txid)
	if tx == nil {
		return nil, engine.ErrInvalidBeef
	}
	weight, copies, err := scriptWeight(tx)
	if err != nil {
		return nil, err
	}
	if err := t.keepHeadroom(weight); err != nil {
		return nil, err
	}
	if copies {
		if err := t.take(ctx, slotExec); err != nil {
			return nil, err
		}
	}
	if err := t.EnterCPU(ctx); err != nil {
		t.leave(slotExec) // nothing ran in it
		return nil, err
	}
	sub := &Submit{Beef: beef, Txid: txid, t: t}
	if tracker == nil {
		return sub, nil
	}
	vctx, cancel := context.WithTimeout(ctx, VerifyBudget)
	defer cancel()
	valid, err := spv.Verify(vctx, tx, tracker, nil)
	if err == nil && valid {
		if copies {
			runtime.GC()
		}
		return sub, nil
	}
	sub.release()
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case vctx.Err() != nil:
		return nil, ErrValidationBudget
	case err != nil:
		return nil, err
	default:
		return nil, engine.ErrInvalidTransaction
	}
}

// keepHeadroom returns what ReadBody reserved for the body's scripts beyond
// weight, or fails with ErrTooComplex when weight is more than that.
func (t *Ticket) keepHeadroom(weight int64) error {
	t.mu.Lock()
	headroom := t.headroom
	if weight <= headroom {
		t.headroom = weight
	}
	t.mu.Unlock()
	if weight > headroom {
		return fmt.Errorf("%w: verifying its scripts needs %d bytes of heap, more than the %d its length reserves", ErrTooComplex, weight, headroom)
	}
	t.Unreserve(headroom - weight)
	return nil
}

// handOnExec returns the execution slot, if the ticket holds it, once a
// garbage collection has freed what the scripts verified in it held, so the
// next holder starts from a collected heap. It does not wait for the
// collection.
func (t *Ticket) handOnExec() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.held[slotExec] {
		return
	}
	t.held[slotExec] = false
	go func(g *Guard) {
		runtime.GC()
		g.exec.Release(1)
	}(t.g)
}

// OnSteakReady wraps next, which may be nil, for engine.SubmitParsedBeef: it
// returns the CPU slot and the execution slot, then calls next. The heap
// reservation stays until Done: the engine's commit and propagation still use
// the BEEF.
func (s *Submit) OnSteakReady(next engine.OnSteakReady) engine.OnSteakReady {
	return func(steak *overlay.Steak) {
		s.release()
		if next != nil {
			next(steak)
		}
	}
}

// Done returns everything the submit's ticket still holds. Call it once the
// engine has returned.
func (s *Submit) Done() {
	s.release()
	s.t.Close()
}

// release returns the CPU slot and the execution slot, once.
func (s *Submit) release() {
	s.once.Do(func() {
		s.t.LeaveCPU()
		s.t.handOnExec()
	})
}
