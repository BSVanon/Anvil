package scriptguard

import (
	"testing"

	"github.com/BSVanon/Anvil/internal/scriptcost"
	"github.com/bsv-blockchain/go-sdk/script"
)

// TestHonestShapes_NeverEndMalformed proves routeguard's malformed-script refusal.
// scriptcost.EndsMalformed, wired at
// internal/overlay/routeguard/scriptcheck.go) never trips on real, honest
// traffic. Every fixture here is a realistic unlocking script this
// package's own TestCheckPassesHonestScripts already proves passes Check
// and the real interpreter; this is the honest corpus C1.4 asks for the
// OrdLock purchase and cancel, PushDrop, P2PKH, multisig and BSV-21/MNEE
// shapes. A multisig spend is not in honestSpends (it is cost-guard test
// machinery, not a wallet template), so it is added here with two realistic
// m-of-m shapes, one for each affected CHECKMULTISIG variant; its
// signatures are not cryptographically valid (multisigLock's unlock is
// OP_0 OP_1 OP_1..., built for pricing, not for spending), which does not
// matter here: EndsMalformed is a purely syntactic, node-exact decode of
// the unlocking script's instruction stream, not a check of what the
// script would compute.
func TestHonestShapes_NeverEndMalformed(t *testing.T) {
	shapes := honestSpends(t)
	shapes["multisig 3-of-3 OP_CHECKMULTISIG"] = multisigLock(0, 3, script.OpCHECKMULTISIG)
	shapes["multisig 3-of-3 OP_CHECKMULTISIGVERIFY"] = multisigLock(0, 3, script.OpCHECKMULTISIGVERIFY)

	checked, flagged := 0, 0
	for name, s := range shapes {
		checked++
		us := s.tx.Inputs[s.vin].UnlockingScript
		if us == nil {
			t.Errorf("%s: no unlocking script", name)
			continue
		}
		if scriptcost.EndsMalformed(*us) {
			flagged++
			t.Errorf("%s: EndsMalformed flagged honest traffic, want not refused", name)
		}
	}
	t.Logf("honest corpus (P2PKH, PushDrop x2 sizes, BSV-21, MNEE, OrdLock purchase+cancel, multisig x2 opcodes): %d shapes checked, %d flagged malformed", checked, flagged)
}
