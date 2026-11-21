package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/BSVanon/Anvil/internal/refusallog"
)

// Stable codes for the BRC-121 refusals. Each refused payment is answered 402
// with the offer headers repeated (x-bsv-sats, x-bsv-server; BRC-121 section 5
// answers every refusal 402), with the body shape of the node's other coded
// refusals (writeCodedError, coded_error.go). Three are not: a request that
// pays by more than one method is answered 400, a node too busy to take the
// payment now answers 503 with a Retry-After, and a node wallet that cannot
// answer answers 500 (BRC-121 section 7).
const (
	// codeBRC121MixedMethods (400): the request carries x-bsv-beef together
	// with X-Bsv-Payment or X402-Proof.
	codeBRC121MixedMethods = "ERR_BRC121_MIXED_METHODS"
	// codeBRC121Malformed: a payment header is missing, too long or not in
	// the shape the reference middleware checks (402-pay server.ts:107-123).
	codeBRC121Malformed = "ERR_BRC121_MALFORMED"
	// codeBRC121Stale: x-bsv-time is more than 30 seconds from the node's
	// clock (BRC-121 section 5, step 2).
	codeBRC121Stale = "ERR_BRC121_STALE"
	// codeBRC121BadBEEF: x-bsv-beef is not an Atomic BEEF (BRC-95) whose
	// subject the node can read, or the subject has more than
	// maxDirectPaymentInputs inputs.
	codeBRC121BadBEEF = "ERR_BRC121_BAD_BEEF"
	// codeBRC121Underpaid: x-bsv-vout names no output, or one paying less
	// than the node's price.
	codeBRC121Underpaid = "ERR_BRC121_UNDERPAID"
	// codeBRC121WrongKey: the output does not pay the key the node wallet
	// derives from x-bsv-sender, x-bsv-nonce and x-bsv-time.
	codeBRC121WrongKey = "ERR_BRC121_WRONG_KEY"
	// codeBRC121Unverifiable: an input's script or signature does not verify
	// against the output the BEEF says it spends, or the BEEF's proofs do
	// not verify against this node's headers.
	codeBRC121Unverifiable = "ERR_BRC121_UNVERIFIABLE"
	// codeBRC121Replayed: the transaction already paid for a request (the
	// node's replay record), or the node wallet already holds it.
	codeBRC121Replayed = "ERR_BRC121_REPLAYED"
	// codeBRC121NotAccepted: the payment was verified but not recorded. ARC
	// refused it, did not answer, or reported it mined deeper than the
	// node takes, or the node wallet could not record it. Unless ARC refused
	// it, the node keeps it (brc121_journal.go) and records it once the
	// network accepts it; it is not served again.
	codeBRC121NotAccepted = "ERR_BRC121_NOT_ACCEPTED"
	// codeBRC121Busy (503): every ARC submit slot is taken, or the client
	// already has brc121ClientShare payments in validation.
	codeBRC121Busy = "ERR_BRC121_BUSY"
	// codeBRC121WalletUnavailable (500): the node wallet failed to derive the
	// payment key or to read its own records.
	codeBRC121WalletUnavailable = "ERR_BRC121_WALLET_UNAVAILABLE"
)

// brc121Refusal is a refused BRC-121 payment: its code, its HTTP status and,
// for a busy refusal, its Retry-After. reason names it in the counters.
type brc121Refusal struct {
	status     int
	code       string
	msg        string
	retryAfter time.Duration
}

func (e *brc121Refusal) Error() string { return e.msg }

func brc121Refuse(code, msg string) error {
	return &brc121Refusal{status: http.StatusPaymentRequired, code: code, msg: msg}
}

var (
	errBRC121MixedMethods = &brc121Refusal{status: http.StatusBadRequest, code: codeBRC121MixedMethods,
		msg: "pay a request by one method: x-bsv-beef cannot be sent with X-Bsv-Payment or X402-Proof"}
	errBRC121ClientBusy = &brc121Refusal{status: http.StatusServiceUnavailable, code: codeBRC121Busy,
		msg: "this client already has its share of BRC-121 payments in validation; retry the same payment shortly", retryAfter: time.Second}
	errBRC121SubmitsBusy = &brc121Refusal{status: http.StatusServiceUnavailable, code: codeBRC121Busy,
		msg: "every payment submit slot is in use; retry the same payment shortly", retryAfter: directPaymentBusyRetry}
)

func errBRC121Wallet(msg string) error {
	return &brc121Refusal{status: http.StatusInternalServerError, code: codeBRC121WalletUnavailable, msg: msg}
}

// writeBRC121Refusal answers a refused BRC-121 payment. A 402 or 503 repeats
// the offer when the request's challenge would make one (offerSats above 0).
func (b *brc121Gate) writeBRC121Refusal(w http.ResponseWriter, r *http.Request, offerSats int, err error) {
	var ref *brc121Refusal
	if !errors.As(err, &ref) {
		ref = &brc121Refusal{status: http.StatusPaymentRequired, code: codeBRC121NotAccepted, msg: err.Error()}
	}
	b.counts.refused(ref.code)
	if offerSats > 0 && ref.status != http.StatusInternalServerError && ref.status != http.StatusBadRequest {
		b.setOffer(w, offerSats)
	}
	msg := "BRC-121 payment refused: " + err.Error()
	if ref.retryAfter > 0 {
		refusallog.Log(r, http.StatusServiceUnavailable, refusallog.ReasonBusy)
		writeCodedUnavailable(w, ref.retryAfter, ref.code, msg)
		return
	}
	writeCodedError(w, ref.status, ref.code, msg)
}

// setOffer sets the BRC-121 offer headers (BRC-121 section 2) and exposes
// them to browsers, on routes whose CORS answer does not already do so.
func (b *brc121Gate) setOffer(w http.ResponseWriter, sats int) {
	h := w.Header()
	h.Set(headerBRC121Sats, strconv.Itoa(sats))
	h.Set(headerBRC121Server, b.server)
	if h.Get("Access-Control-Expose-Headers") == "" {
		h.Set("Access-Control-Expose-Headers", headerBRC121Sats+", "+headerBRC121Server)
	}
}
