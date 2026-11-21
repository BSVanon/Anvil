package api

import (
	"errors"
	"net/http"
)

// Stable codes for the payment refusals a client can act on. Each one is
// answered 402, like every other refused payment, with the body shape of
// BRC-105 section 6.2 (status, code, description; writeCodedError,
// coded_error.go).
const (
	// codeDirectPaymentUnavailable: the node has no ARC client, so it takes
	// no X-Bsv-Payment (errDirectPaymentUnavailable).
	codeDirectPaymentUnavailable = "ERR_DIRECT_PAYMENT_UNAVAILABLE"
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
)

// paymentRefusal is a payment refused with one of the codes above.
type paymentRefusal struct {
	code string
	msg  string
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
	msg: "this node takes no X-Bsv-Payment because it has no ARC client to confirm that a payment's inputs exist and are unspent; " +
		"send the request without a payment header to get an X402-Challenge, then pay it with an X402-Proof",
}

// writePaymentRejection answers a refused payment: the body-read status for
// a request body that could not be read (writePaymentBodyError,
// payment_bodyread.go), 431 for a payment header refused by its size
// (paymentRejectionStatus, payment_bounds.go), a coded 402 for a
// paymentRefusal, and a plain 402 for any other payment failure. prefix names
// the payment path in the message.
func writePaymentRejection(w http.ResponseWriter, r *http.Request, prefix string, err error) {
	var bodyErr *paymentBodyError
	if errors.As(err, &bodyErr) {
		writePaymentBodyError(w, r, bodyErr)
		return
	}
	status := paymentRejectionStatus(r, err)
	var refusal *paymentRefusal
	if status == http.StatusPaymentRequired && errors.As(err, &refusal) {
		writeCodedError(w, status, refusal.code, prefix+err.Error())
		return
	}
	writeError(w, status, prefix+err.Error())
}
