package v3engine

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// buildUMPTaggedBEEF makes an 11-field UMP PushDrop token (no signature —
// matching Satsu's on-chain layout: presentationHash at field[6],
// recoveryHash at field[7]) and wraps it as a submittable TaggedBEEF.
func buildUMPTaggedBEEF(t *testing.T, presH, recH []byte, atomic bool) overlay.TaggedBEEF {
	t.Helper()
	priv, _ := ec.NewPrivateKey()
	w, _ := wallet.NewCompletedProtoWallet(priv)
	fields := [][]byte{
		make([]byte, 16), make([]byte, 80), make([]byte, 80), make([]byte, 80),
		make([]byte, 32), make([]byte, 32),
		presH, recH,
		make([]byte, 32), make([]byte, 32), make([]byte, 32),
	}
	pd := &pushdrop.PushDrop{Wallet: w}
	s, err := pd.Lock(context.Background(), fields,
		wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "user management"},
		"1", wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}, false, false, pushdrop.LockBefore)
	if err != nil {
		t.Fatalf("pushdrop lock: %v", err)
	}
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: s, Satoshis: 1})
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("beef: %v", err)
	}
	var blob []byte
	if atomic {
		blob, err = beef.AtomicBytes(tx.TxID())
	} else {
		blob, err = beef.Bytes()
	}
	if err != nil {
		t.Fatalf("encode beef: %v", err)
	}
	return overlay.TaggedBEEF{Beef: blob, Topics: []string{topics.UMPTopicName}}
}

// TestEngine_SubmitAndLookupUMP is the decisive Satsu reproduction: drive a
// UMP token all the way through eng.Submit -> admit -> lookup-notify -> index
// -> eng.Lookup (which hydrates formulas from storage). The existing UMP unit
// test only covers ls_users.Lookup's formula return, NOT the engine hydration
// — exactly the gap where Satsu's "admits but lookup empty" could live.
func TestEngine_SubmitAndLookupUMP(t *testing.T) {
	eng, _ := newTestEngine(t)
	presH := make([]byte, 32)
	for i := range presH {
		presH[i] = 0xa1
	}
	recH := make([]byte, 32)
	for i := range recH {
		recH[i] = 0xb2
	}
	tagged := buildUMPTaggedBEEF(t, presH, recH, false) // V1 BEEF, as a real SDK submits

	steak, err := eng.Submit(context.Background(), tagged, engine.SubmitModeHistorical, nil)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	inst, ok := steak[topics.UMPTopicName]
	if !ok || inst == nil || len(inst.OutputsToAdmit) != 1 {
		t.Fatalf("expected tm_users admit of output 0, got %+v", inst)
	}
	t.Logf("tm_users admitted outputs: %v", inst.OutputsToAdmit)

	q, _ := json.Marshal(topics.UMPLookupQuery{PresentationHash: hex.EncodeToString(presH)})
	answer, err := eng.Lookup(context.Background(), &lookup.LookupQuestion{
		Service: topics.UMPLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	t.Logf("ls_users answer: type=%s outputs=%d", answer.Type, len(answer.Outputs))
	if answer.Type != lookup.AnswerTypeOutputList || len(answer.Outputs) != 1 {
		t.Fatalf(">>> REPRODUCED: UMP submit->index->lookup did NOT round-trip (type=%s n=%d)", answer.Type, len(answer.Outputs))
	}
	if len(answer.Outputs[0].Beef) == 0 {
		t.Fatalf("expected engine-hydrated BEEF, got empty")
	}
	t.Logf(">>> UMP round-trip OK — full engine path resolves this token")
}
