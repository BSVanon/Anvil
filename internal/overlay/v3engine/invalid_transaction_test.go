package v3engine

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/refusallog"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestSubmit_RawTransactionIsRefused400NotCrashed: a raw transaction,
// serialized on its own and never wrapped in any BEEF envelope -- the shape
// a client sends when it mistakes a raw transaction for a BEEF -- posted to
// /submit answers 400 with the clear refusal message, not a 500
// (bu_b4_specs.md item 4). beefnorm.Parse's call to go-sdk's
// NewBeefFromBytes used to return that error unwrapped, which fell through
// both routeguard and the route's own classification to a generic failure.
func TestSubmit_RawTransactionIsRefused400NotCrashed(t *testing.T) {
	logs := watchRefusals(t)
	_, _, url := normEngine(t)
	code, resp := postSubmit(t, url, overlaytest.FundingTx().Bytes())
	if code != http.StatusBadRequest {
		t.Fatalf("submit: %d %s, want 400", code, resp)
	}
	if !strings.Contains(string(resp), "expected BEEF; a raw transaction cannot be verified") {
		t.Fatalf("response %s lacks the clear refusal message", resp)
	}
	logs.assertLogged(t, http.StatusBadRequest, refusallog.ReasonRefusedBEEF, "/submit")
}

// failingScriptBEEF is a V2 BEEF of a transaction that spends overlaytest's
// funding output with an unlocking script that always fails -- OP_FALSE
// OP_VERIFY -- rather than one only the extended format backs (efSpendBEEF's
// ErrMalformed case, exercised elsewhere): its parent is included with a
// real BUMP, so PreVerify reaches spv.Verify instead of being refused
// earlier, and spv.Verify returns go-sdk's own script failure as a plain
// error (bu_b4_specs.md item 4b; cycle-6b re-review, NIT 1).
func failingScriptBEEF(t *testing.T) []byte {
	t.Helper()
	subject := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: beefnormtest.Lock(), Satoshis: 1000})
	subject.Inputs[0].UnlockingScript = &script.Script{script.OpFALSE, script.OpVERIFY}
	funding := subject.Inputs[0].SourceTransaction
	return beefnormtest.Encode(t, transaction.BEEF_V2, subject, []*transaction.MerklePath{funding.MerklePath}, funding)
}

// TestSubmit_FailingScriptIsClassifiedInvalidTransaction: a BEEF whose
// subject's script genuinely fails verification -- a verification verdict
// PreVerify returns that is not a guard refusal, budget or size error --
// answers 400 with invalidTransactionCode and logs ReasonInvalidTransaction,
// instead of the unclassified ReasonOtherGuardError it used to log
// (bu_b4_specs.md item 4b).
func TestSubmit_FailingScriptIsClassifiedInvalidTransaction(t *testing.T) {
	logs := watchRefusals(t)
	_, _, url := normEngine(t)
	code, resp := postSubmit(t, url, failingScriptBEEF(t))
	if code != http.StatusBadRequest {
		t.Fatalf("submit: %d %s, want 400", code, resp)
	}
	var envelope struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(resp, &envelope); err != nil {
		t.Fatalf("response %s: %v", resp, err)
	}
	if envelope.Code != invalidTransactionCode {
		t.Fatalf("response %s: code = %q, want %q", resp, envelope.Code, invalidTransactionCode)
	}
	logs.assertLogged(t, http.StatusBadRequest, refusallog.ReasonInvalidTransaction, "/submit")
}
