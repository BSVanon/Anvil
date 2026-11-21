package legacyshim_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/BSVanon/Anvil/internal/refusallog"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestLegacySubmit_RawTransactionIsRefused400NotCrashed: a raw transaction,
// serialized on its own and never wrapped in any BEEF envelope -- the shape
// a client sends when it mistakes a raw transaction for a BEEF -- posted to
// /overlay/submit answers 400 with the clear refusal message, not the 500
// it used to answer. beefnorm.Parse's call to
// go-sdk's NewBeefFromBytes used to return that error unwrapped, which fell
// through legacyshim's own classification to statusForSubmitError's generic
// 500.
func TestLegacySubmit_RawTransactionIsRefused400NotCrashed(t *testing.T) {
	logs := watchRefusals(t)
	url := guardedShimServer(t, newWiredShim(t), routeguard.New(testPool, routeguard.CPUSlots, routeguard.JSONSlots, routeguard.Wait))
	code, resp := submitUHRP(t, url, overlaytest.FundingTx().Bytes())
	if code != http.StatusBadRequest {
		t.Fatalf("submit: %d %s, want 400", code, resp)
	}
	if !strings.Contains(resp, "expected BEEF; a raw transaction cannot be verified") {
		t.Fatalf("response %s lacks the clear refusal message", resp)
	}
	logs.assertLogged(t, http.StatusBadRequest, refusallog.ReasonRefusedBEEF, "/overlay/submit")
}

// failingScriptBEEF is a V2 BEEF of a transaction that spends overlaytest's
// funding output with an unlocking script that always fails -- OP_FALSE
// OP_VERIFY -- rather than one only the extended format backs (the
// ErrMalformed case TestLegacySubmit_RefusesSpendsOnlyTheExtendedFormatBacks
// exercises): its parent is included with a real BUMP, so PreVerify reaches
// spv.Verify instead of being refused earlier, and spv.Verify returns
// go-sdk's own script failure as a plain error.
func failingScriptBEEF(t *testing.T) []byte {
	t.Helper()
	subject := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: beefnormtest.Lock(), Satoshis: 1000})
	subject.Inputs[0].UnlockingScript = &script.Script{script.OpFALSE, script.OpVERIFY}
	funding := subject.Inputs[0].SourceTransaction
	return beefnormtest.Encode(t, transaction.BEEF_V2, subject, []*transaction.MerklePath{funding.MerklePath}, funding)
}

// TestLegacySubmit_FailingScriptIsClassifiedInvalidTransaction: a BEEF whose
// subject's script genuinely fails verification -- a verification verdict
// PreVerify returns that is not a guard refusal, budget or size error --
// answers 400 with invalidTransactionCode and logs ReasonInvalidTransaction,
// instead of the 500 under ReasonOtherGuardError it used to answer and log
// before the error classification was corrected.
func TestLegacySubmit_FailingScriptIsClassifiedInvalidTransaction(t *testing.T) {
	logs := watchRefusals(t)
	url := guardedShimServer(t, newWiredShim(t), routeguard.New(testPool, routeguard.CPUSlots, routeguard.JSONSlots, routeguard.Wait))
	code, resp := submitUHRP(t, url, failingScriptBEEF(t))
	if code != http.StatusBadRequest {
		t.Fatalf("submit: %d %s, want 400", code, resp)
	}
	var envelope struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(resp), &envelope); err != nil {
		t.Fatalf("response %s: %v", resp, err)
	}
	if envelope.Code != "ERR_INVALID_TRANSACTION" {
		t.Fatalf("response %s: code = %q, want ERR_INVALID_TRANSACTION", resp, envelope.Code)
	}
	logs.assertLogged(t, http.StatusBadRequest, refusallog.ReasonInvalidTransaction, "/overlay/submit")
}
