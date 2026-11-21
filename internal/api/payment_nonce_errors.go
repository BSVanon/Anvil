package api

import (
	"errors"
	"net/http"

	"github.com/BSVanon/Anvil/internal/refusallog"
)

// writeMintNonceError answers a NonceProvider.MintNonce error with the
// status it belongs to, so issueChallengeForPayees (payment.go) stays a
// single call here:
//
//   - *mintBudgetError (payment_budget.go) gets its own 503 with
//     Retry-After: the node's own nonce budget is spent, which is not a
//     payment failure.
//   - Anything else is a node-side mint failure and gets 500. That includes
//     go-sdk's auth.ErrReplayedNonce: a mint runs while the node issues a
//     challenge, before the client has paid anything, so no payment exists
//     yet that could be replayed or answered with 402.
func writeMintNonceError(w http.ResponseWriter, r *http.Request, err error) {
	var busy *mintCapacityError
	if errors.As(err, &busy) {
		refusallog.Log(r, http.StatusServiceUnavailable, refusallog.ReasonBusy)
		writeUnavailable(w, busy.retryAfter, "no payment nonce available: "+busy.Error()+", retry later")
		return
	}
	var spent *mintBudgetError
	if errors.As(err, &spent) {
		refusallog.Log(r, http.StatusServiceUnavailable, refusallog.ReasonMintBudgetExceeded)
		writeUnavailable(w, spent.retryAfter, "no payment nonce available: the node's nonce budget is spent, retry later")
		return
	}
	writeError(w, http.StatusInternalServerError, "failed to mint nonce: "+err.Error())
}
