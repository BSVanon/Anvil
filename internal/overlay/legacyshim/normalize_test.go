package legacyshim_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/BSVanon/Anvil/internal/refusallog"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// uhrpAd is an output advertising contentHashHex under BRC-26 UHRP.
func uhrpAd(t *testing.T, contentHashHex string) *transaction.TransactionOutput {
	t.Helper()
	hash, err := hex.DecodeString(contentHashHex)
	if err != nil || len(hash) != 32 {
		t.Fatalf("bad content hash: %v", err)
	}
	b := append([]byte{0x00, 0x6a, byte(len(topics.UHRPProtocolID))}, topics.UHRPProtocolID...)
	s := script.Script(append(append(b, byte(len(hash))), hash...))
	return &transaction.TransactionOutput{LockingScript: &s, Satoshis: 0}
}

// TestLegacySubmit_StoresOnlyTheSubjectsGraph: on /overlay/submit, an Atomic
// BEEF holding a transaction outside its subject's graph, as ts-sdk 2.1.0's
// Beef.getBeefForAtomic leaves an older unrelated one, which go-sdk's own
// Atomic parser refuses, is admitted, and the BEEF stored lacks it.
func TestLegacySubmit_StoresOnlyTheSubjectsGraph(t *testing.T) {
	shim := newWiredShim(t)
	url := guardedShimServer(t, shim, routeguard.New(testPool, routeguard.CPUSlots, routeguard.JSONSlots, routeguard.Wait))
	subject := overlaytest.SpendingTx(t, uhrpAd(t, "abababababababababababababababababababababababababababababababab"))
	funding := subject.Inputs[0].SourceTransaction
	unrelated := beefnormtest.Parent(60, 1, 1000)
	body := beefnormtest.Atomic(subject, beefnormtest.Encode(t, transaction.BEEF_V2, subject, []*transaction.MerklePath{funding.MerklePath}, unrelated, funding))
	if _, _, err := transaction.NewBeefFromAtomicBytes(body); err == nil {
		t.Fatal("go-sdk accepts the unrelated transaction; the case is not the one ts-sdk sends")
	}
	if code, raw := submitUHRP(t, url, body); code != http.StatusOK {
		t.Fatalf("submit: %d %s", code, raw)
	}
	eng, ok := shim.Engine.(*engine.Engine)
	if !ok {
		t.Fatal("the wired shim's engine is not an *engine.Engine")
	}
	topic := topics.UHRPTopicName
	out, err := eng.Storage.FindOutput(context.Background(), &transaction.Outpoint{Txid: *subject.TxID(), Index: 0}, &topic, nil, true)
	if err != nil || out == nil || out.Beef == nil {
		t.Fatalf("output 0 of the subject: %v", err)
	}
	if out.Beef.FindTransactionByHash(unrelated.TxID()) != nil || out.Beef.FindTransactionByHash(funding.TxID()) == nil {
		t.Error("the stored BEEF holds the unrelated transaction or lacks the funding one")
	}
}

// TestLegacySubmit_RefusesSpendsOnlyTheExtendedFormatBacks: on
// /overlay/submit, a transaction whose spent output only the extended format
// supplies is refused with 400, logged once with the client's address.
func TestLegacySubmit_RefusesSpendsOnlyTheExtendedFormatBacks(t *testing.T) {
	logs := watchRefusals(t)
	url := guardedShimServer(t, newWiredShim(t), routeguard.New(testPool, routeguard.CPUSlots, routeguard.JSONSlots, routeguard.Wait))

	prevTxid := chainhash.DoubleHashH([]byte("an output no BEEF holds"))
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{SourceTXID: &prevTxid, UnlockingScript: &script.Script{}, SequenceNumber: transaction.DefaultSequenceNumber})
	tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: 10_000, LockingScript: beefnormtest.Lock()})
	tx.AddOutput(uhrpAd(t, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"))
	ef, err := tx.EF()
	if err != nil {
		t.Fatal(err)
	}
	body := append(binary.LittleEndian.AppendUint32(nil, transaction.BEEF_V2), 0, 1, 0) // no BUMPs, one raw transaction
	body = append(body, ef...)

	if code, raw := submitUHRP(t, url, body); code != http.StatusBadRequest || !strings.Contains(raw, "extended format") {
		t.Fatalf("submit: %d %s, want 400", code, raw)
	}
	logs.assertLogged(t, http.StatusBadRequest, refusallog.ReasonRefusedBEEF, "/overlay/submit")
}
