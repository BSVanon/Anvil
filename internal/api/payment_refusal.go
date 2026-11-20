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

// writePaymentRejection answers a refused payment: 431 for a payment header
// refused by its size (paymentRejectionStatus, payment_bounds.go), a coded
// 402 for a paymentRefusal, and a plain 402 for any other payment failure.
// prefix names the payment path in the message.
func writePaymentRejection(w http.ResponseWriter, r *http.Request, prefix string, err error) {
	status := paymentRejectionStatus(r, err)
	var refusal *paymentRefusal
	if status == http.StatusPaymentRequired && errors.As(err, &refusal) {
		writeCodedError(w, status, refusal.code, prefix+err.Error())
		return
	}
	writeError(w, status, prefix+err.Error())
}
