package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/BSVanon/Anvil/internal/txrelay"
)

// A direct payment is broadcast while its request waits (verifyDirectPayment),
// so its ARC submit is bounded in time and in number.

// maxDirectPaymentSubmits is how many direct-payment ARC submits may be in
// flight at once, process-wide. A direct payment that finds them all taken is
// answered 503 at once rather than queued (errDirectPaymentSubmitsBusy).
const maxDirectPaymentSubmits = 16

// directPaymentSubmitTimeout bounds one direct payment's ARC submit, failover
// included: 10 seconds, twice the 5 seconds ARC itself waits for
// SEEN_ON_NETWORK before it answers (payment_arc.go). The submit also ends
// when the request's own context does. A var so tests can shorten it.
var directPaymentSubmitTimeout = 10 * time.Second

// directPaymentBusyRetry is the Retry-After for a direct payment refused
// because every submit slot is taken: a slot comes free as soon as any one of
// the submits in flight ends.
const directPaymentBusyRetry = time.Second

// directPaymentSubmitSlots holds one token for each direct-payment ARC submit
// in flight. A var so tests can use a smaller pool.
var directPaymentSubmitSlots = make(chan struct{}, maxDirectPaymentSubmits)

// errDirectPaymentSubmitsBusy refuses a direct payment when every submit slot
// is taken. Nothing was broadcast and the payment's transaction is not
// recorded, so the same transaction can be sent again.
var errDirectPaymentSubmitsBusy = &paymentRefusal{
	code:       codeDirectPaymentBusy,
	msg:        fmt.Sprintf("this node is already broadcasting %d direct payments; retry the same transaction shortly", maxDirectPaymentSubmits),
	retryAfter: directPaymentBusyRetry,
}

// takePaymentSubmitSlot takes shared admission for payment verification and
// ARC submission. Direct payments take it before decoding; proofs take it
// immediately before ARC because their challenge checks are separately
// bounded.
func takePaymentSubmitSlot() (func(), error) {
	slots := directPaymentSubmitSlots
	select {
	case slots <- struct{}{}:
	default:
		return nil, errDirectPaymentSubmitsBusy
	}
	return func() { <-slots }, nil
}

// submitPaymentWithSlot broadcasts raw while the caller holds a shared slot.
func submitPaymentWithSlot(ctx context.Context, arc *txrelay.ARCClient, raw []byte) (*txrelay.ARCResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, directPaymentSubmitTimeout)
	defer cancel()
	resp, err := arc.SubmitContext(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("ARC broadcast failed: %w", err)
	}
	return resp, nil
}

// submitPayment takes a shared slot for a proof-path ARC submission.
func submitPayment(ctx context.Context, arc *txrelay.ARCClient, raw []byte) (*txrelay.ARCResponse, error) {
	release, err := takePaymentSubmitSlot()
	if err != nil {
		return nil, err
	}
	defer release()
	return submitPaymentWithSlot(ctx, arc, raw)
}

// ambiguousPaymentSubmit turns a submit error that does not prove ARC
// rejected the transaction into a retryable 503. ARC's documented
// transaction-policy errors in arcRefusedHTTP are definite rejections;
// transport, form and server failures may have happened after acceptance.
func ambiguousPaymentSubmit(err error) error {
	if !paymentSubmitIsAmbiguous(err) {
		return err
	}
	return &paymentRefusal{
		code:       codePaymentSubmitUncertain,
		msg:        err.Error() + "; ARC may have accepted this transaction, so retry the same transaction rather than paying again",
		retryAfter: directPaymentBusyRetry,
		cause:      err,
	}
}

func paymentSubmitIsAmbiguous(err error) bool {
	var httpErr *txrelay.ARCHTTPError
	if errors.As(err, &httpErr) {
		return !arcRefusedHTTP[httpErr.StatusCode]
	}
	return true
}
