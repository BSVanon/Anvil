package api

import (
	"context"
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

// submitDirectPayment broadcasts a direct payment's transaction raw through
// arc, holding one of directPaymentSubmitSlots, under ctx (the request's
// context) and directPaymentSubmitTimeout. It refuses at once with
// errDirectPaymentSubmitsBusy when no slot is free.
func submitDirectPayment(ctx context.Context, arc *txrelay.ARCClient, raw []byte) (*txrelay.ARCResponse, error) {
	slots := directPaymentSubmitSlots
	select {
	case slots <- struct{}{}:
	default:
		return nil, errDirectPaymentSubmitsBusy
	}
	defer func() { <-slots }()
	ctx, cancel := context.WithTimeout(ctx, directPaymentSubmitTimeout)
	defer cancel()
	resp, err := arc.SubmitContext(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("ARC broadcast failed: %w", err)
	}
	return resp, nil
}
