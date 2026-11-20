package api

import (
	"errors"
	"net/http"

	"github.com/BSVanon/Anvil/internal/refusallog"
	sdkauth "github.com/bsv-blockchain/go-sdk/auth"
)

// writeMintNonceError answers a NonceProvider.MintNonce error with the
// status it belongs to, so issueChallengeForPayees (payment.go) stays a
// single call here:
//
//   - *mintBudgetError (payment_budget.go) gets its own 503 with
//     Retry-After — the node's own nonce budget is spent, not a payment
//     failure.
//   - go-sdk's auth.ErrReplayedNonce gets 402. It is not reachable through
//     WalletNonceProvider today — that provider mints locally via the
//     embedded wallet's GetPublicKey/CreateAction/SignAction, none of which
//     touch BRC-103 message authentication — but NonceProvider is an
//     interface, and per BRC-121 (the x402 canon this gate otherwise
//     follows) a replayed payment is the CLIENT's failure, not the node's:
//     "If the isMerge field of the internalization result is true, the
//     transaction was already known to the wallet, indicating a replayed
//     payment. The server MUST reject the request and respond with 402."
//     (BRC-121 S5 step 5; S7 reserves 500 for the server's own
//     wallet-initialization failure, not a payment-shaped one).
//     Classifying it here, ahead of any NonceProvider implementation that
//     might actually return it, keeps a future replay-aware provider from
//     defaulting to a 500 it was never supposed to get — a payment
//     rejection, not a node error.
//   - Anything else is an unclassified node-side mint failure: 500, as
//     before.
func writeMintNonceError(w http.ResponseWriter, r *http.Request, err error) {
	var spent *mintBudgetError
	if errors.As(err, &spent) {
		refusallog.Log(r, http.StatusServiceUnavailable, refusallog.ReasonMintBudgetExceeded)
		writeUnavailable(w, spent.retryAfter, "no payment nonce available: the node's nonce budget is spent, retry later")
		return
	}
	if errors.Is(err, sdkauth.ErrReplayedNonce) {
		writeError(w, http.StatusPaymentRequired, "payment rejected: replayed nonce")
		return
	}
	writeError(w, http.StatusInternalServerError, "failed to mint nonce: "+err.Error())
}
