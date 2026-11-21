package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	codePaymentRequired         = "ERR_PAYMENT_REQUIRED"
	codeProofPaymentUnavailable = "ERR_PROOF_PAYMENT_UNAVAILABLE"
)

// directPaymentOffer is the proof-free 402 body. It keeps the price and
// recipient fields used by direct-payment clients without minting a nonce.
type directPaymentOffer struct {
	AmountSats            int      `json:"amount_sats"`
	PayeeLockingScriptHex string   `json:"payee_locking_script_hex"`
	Payees                []Payee  `json:"payees,omitempty"`
	Accepts               []string `json:"accepts"`
	Code                  string   `json:"code"`
	Description           string   `json:"description,omitempty"`
}

// issueDirectPaymentOffer applies the same request-footprint bound as proof
// challenge issuance, then advertises only the challenge-free payment path.
func (pg *PaymentGate) issueDirectPaymentOffer(w http.ResponseWriter, r *http.Request, payees []Payee, code, description string) {
	if n := challengeFootprint(r, payees); n > maxChallengeFootprint {
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"request too large for a payment challenge: method, host, path, query and payee scripts are %d bytes, the limit is %d",
			n, maxChallengeFootprint))
		return
	}
	offer := directPaymentOffer{
		PayeeLockingScriptHex: pg.payeeScriptHex,
		Accepts:               []string{HeaderBSVPayment},
		Code:                  code,
		Description:           description,
	}
	for _, payee := range payees {
		offer.AmountSats += payee.AmountSats
	}
	if len(payees) == 1 {
		offer.PayeeLockingScriptHex = payees[0].LockingScriptHex
	} else if len(payees) > 1 {
		offer.Payees = payees
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(w).Encode(offer)
}
