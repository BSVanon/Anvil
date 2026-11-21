package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/BSVanon/Anvil/internal/refusallog"
)

// Stable codes for the payment refusals a client can act on. Each one is
// answered 402, like every other refused payment, with the body shape of
// BRC-105 section 6.2 (status, code, description; writeCodedError,
// coded_error.go), except the ones for a node too busy to take the payment
// now, which are answered 503 with a Retry-After.
const (
	// codeDirectPaymentUnavailable: the node has no ARC client, so it takes
	// no X-Bsv-Payment (errDirectPaymentUnavailable).
	codeDirectPaymentUnavailable = "ERR_DIRECT_PAYMENT_UNAVAILABLE"
	// codePaymentMalformed: the X-Bsv-Payment header holds no transaction
	// the node parses (errPaymentMalformed).
	codePaymentMalformed = "ERR_PAYMENT_MALFORMED"
	// codeDirectPaymentUnverifiable: the direct payment's inputs cannot be
	// verified as sent: no inputs, more than maxDirectPaymentInputs, or an
	// input without the output it spends, its locking script or its
	// unlocking script (errDirectPaymentUnverifiable,
	// payment_direct_verify.go).
	codeDirectPaymentUnverifiable = "ERR_DIRECT_PAYMENT_UNVERIFIABLE"
	// codePaymentNotAccepted: ARC did not report the payment transaction as
	// accepted by the network (checkARCAcceptance, payment_arc.go).
	codePaymentNotAccepted = "ERR_PAYMENT_NOT_ACCEPTED"
	// codePaymentReplayed: the payment's transaction already paid for a
	// request, on either payment path (paymentReplaySet, payment_replay.go).
	codePaymentReplayed = "ERR_PAYMENT_REPLAYED"
	// codePaymentTooOld: ARC reports the direct payment mined deeper than this
	// node accepts, or at a depth it cannot work out (checkPaymentDepth,
	// payment_arc.go).
	codePaymentTooOld = "ERR_PAYMENT_TOO_OLD"
	// codePaymentHeadersBehind: ARC reports the direct payment mined more
	// than maxPaymentHeightAboveTip blocks above this node's header tip, so
	// the node's headers are behind and it cannot confirm the payment's depth
	// (checkPaymentDepth, payment_arc.go). The same transaction can be
	// retried once they catch up.
	codePaymentHeadersBehind = "ERR_PAYMENT_HEADERS_BEHIND"
	// codeMempoolCheckUnavailable: the challenge requires that the network
	// accept the payment, and the node has no ARC client to ask
	// (errMempoolCheckUnavailable).
	codeMempoolCheckUnavailable = "ERR_MEMPOOL_CHECK_UNAVAILABLE"
	// codeDirectPaymentBusy (503): every direct-payment ARC submit slot is
	// taken (errDirectPaymentSubmitsBusy, payment_submit.go).
	codeDirectPaymentBusy = "ERR_DIRECT_PAYMENT_BUSY"
	// codePaymentBodyShare (503): the client already has its share of
	// payment request bodies being read (errPaymentBodyShare,
	// payment_bodyshare.go).
	codePaymentBodyShare = "ERR_PAYMENT_BODY_SHARE"
)

// paymentRefusal is a payment refused with one of the codes above. One with a
// retryAfter refuses it because the node is busy, not because the payment is
// wrong: it is answered 503 with that Retry-After.
type paymentRefusal struct {
	code       string
	msg        string
	retryAfter time.Duration
}

func (e *paymentRefusal) Error() string { return e.msg }

// errDirectPaymentUnavailable refuses every X-Bsv-Payment on a node with no
// ARC client. A direct payment carries its inputs' source outputs as the
// client wrote them (an Extended Format input, go-sdk v1.7.7
// transaction/input.go), and nothing else ties them to a transaction that
// exists. Only a node that broadcasts the payment and hears back that the
// network accepted it learns that the inputs exist and are unspent.
var errDirectPaymentUnavailable = &paymentRefusal{
	code: codeDirectPaymentUnavailable,
	msg:  "this node takes no X-Bsv-Payment because it has no ARC client to confirm that a payment's inputs exist and are unspent",
}

// errPaymentMalformed refuses a payment header that does not hold a
// transaction: not hex or base64, or bytes that do not parse as one, such as
// Atomic BEEF, which is not parsed.
func errPaymentMalformed(msg string) error {
	return &paymentRefusal{code: codePaymentMalformed, msg: msg}
}

// errMempoolCheckUnavailable refuses an X402-Proof whose challenge requires
// mempool acceptance (the operator's require_mempool setting) on a node with
// no ARC client. Such a node cannot learn whether the network accepted the
// payment, so it fails closed rather than skip the check.
var errMempoolCheckUnavailable = &paymentRefusal{
	code: codeMempoolCheckUnavailable,
	msg:  "this node requires that the network accept a payment before it serves the request, and it has no ARC client to confirm that",
}

// writePaymentRejection answers a refused payment: the body-read status for
// a request body that could not be read (writePaymentBodyError,
// payment_bodyread.go), 431 for a payment header refused by its size
// (paymentRejectionStatus, payment_bounds.go), a coded 503 for a busy
// paymentRefusal, a coded 402 for any other paymentRefusal, and a plain 402
// for any other payment failure. prefix names the payment path in the
// message.
func writePaymentRejection(w http.ResponseWriter, r *http.Request, prefix string, err error) {
	var bodyErr *paymentBodyError
	if errors.As(err, &bodyErr) {
		writePaymentBodyError(w, r, bodyErr)
		return
	}
	status := paymentRejectionStatus(r, err)
	var refusal *paymentRefusal
	if status == http.StatusPaymentRequired && errors.As(err, &refusal) {
		if refusal.retryAfter > 0 {
			refusallog.Log(r, http.StatusServiceUnavailable, refusallog.ReasonBusy)
			writeCodedUnavailable(w, refusal.retryAfter, refusal.code, prefix+err.Error())
			return
		}
		writeCodedError(w, status, refusal.code, prefix+err.Error())
		return
	}
	writeError(w, status, prefix+err.Error())
}

// writeCodedUnavailable answers 503 with a stable code and a Retry-After of
// at least one second.
func writeCodedUnavailable(w http.ResponseWriter, retryAfter time.Duration, code, msg string) {
	setRetryAfter(w, retryAfter)
	writeCodedError(w, http.StatusServiceUnavailable, code, msg)
}
