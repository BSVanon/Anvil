package topics

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// kvSettingsProtocol is the canonical SendBSV settings protocol
// (security-level 1, "sendbsv settings") used by GlobalKVStore.
var kvSettingsProtocol = wallet.Protocol{
	SecurityLevel: wallet.SecurityLevelEveryApp,
	Protocol:      "sendbsv settings",
}

// kvControllerWallet returns a fresh CompletedProtoWallet plus its
// identity (root) pubkey compressed bytes — the value that goes in the
// KVStore controller field. Admission verifies the appended signature
// with this pubkey as the counterparty.
func kvControllerWallet(t *testing.T) (wallet.Interface, []byte) {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	w, err := wallet.NewCompletedProtoWallet(priv)
	if err != nil {
		t.Fatalf("new wallet: %v", err)
	}
	return w, priv.PubKey().Compressed()
}

// buildKVScript builds a signed KVStore PushDrop locking script via the
// canonical pushdrop.Lock path. The controller wallet signs the field
// preimage with counterparty=anyone (the symmetric partner of the
// admission-side anyone-wallet verify with counterparty=controller).
// When tagged is true a tags field is included (6-field tagged format);
// otherwise the legacy 5-field format is produced.
func buildKVScript(t *testing.T, w wallet.Interface, controllerPub []byte, key, value string, tags []string, tagged bool) []byte {
	t.Helper()
	protoJSON, err := json.Marshal(&kvSettingsProtocol)
	if err != nil {
		t.Fatalf("marshal protocol: %v", err)
	}
	fields := [][]byte{
		protoJSON,        // 0: protocolID
		[]byte(key),      // 1: key
		[]byte(value),    // 2: value
		controllerPub,    // 3: controller
	}
	if tagged {
		tagsJSON, err := json.Marshal(tags)
		if err != nil {
			t.Fatalf("marshal tags: %v", err)
		}
		fields = append(fields, tagsJSON) // 4: tags
	}
	pd := &pushdrop.PushDrop{Wallet: w}
	s, err := pd.Lock(
		context.Background(),
		fields,
		kvSettingsProtocol,
		key, // keyID == UTF-8 key (matches admission keyID)
		wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		false, // forSelf
		true,  // includeSignature: KVStore tokens carry an appended signature
		pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}
	return s.Bytes()
}

// txWith wraps a locking script in a single-output transaction and
// returns its serialized bytes (the input to TopicManager.Admit).
func txWith(t *testing.T, scriptBytes []byte) []byte {
	t.Helper()
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		LockingScript: script.NewFromBytes(scriptBytes),
		Satoshis:      1,
	})
	return tx.Bytes()
}

// TestKVStoreAdmit_TaggedTokenAdmitted pins the happy path: a signed
// 6-field tagged KVStore token verifies + is admitted.
func TestKVStoreAdmit_TaggedTokenAdmitted(t *testing.T) {
	w, ctrl := kvControllerWallet(t)
	scriptBytes := buildKVScript(t, w, ctrl, "fiat-currency", "GBP", []string{"prefs", "display"}, true)

	m := NewKVStoreTopicManager()
	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst == nil || len(inst.OutputsToAdmit) != 1 || inst.OutputsToAdmit[0] != 0 {
		t.Fatalf("expected output 0 admitted, got %+v", inst)
	}
}

// TestKVStoreAdmit_LegacyTokenAdmitted verifies the 5-field legacy
// format (no tags) is also admitted.
func TestKVStoreAdmit_LegacyTokenAdmitted(t *testing.T) {
	w, ctrl := kvControllerWallet(t)
	scriptBytes := buildKVScript(t, w, ctrl, "cold-address", "sendbsv-enc:v1:abc", nil, false)

	m := NewKVStoreTopicManager()
	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst == nil || len(inst.OutputsToAdmit) != 1 {
		t.Fatalf("expected legacy token admitted, got %+v", inst)
	}
}

// TestKVStoreAdmit_TamperedSignatureRejected is the load-bearing
// security check: an output whose signed preimage is altered after
// signing (here, by signing with a DIFFERENT controller pubkey in the
// controller field than the wallet that signed) fails verification and
// is not admitted.
func TestKVStoreAdmit_TamperedControllerRejected(t *testing.T) {
	w, _ := kvControllerWallet(t)
	_, otherCtrl := kvControllerWallet(t) // controller field belongs to a different identity
	scriptBytes := buildKVScript(t, w, otherCtrl, "fiat-currency", "GBP", nil, false)

	m := NewKVStoreTopicManager()
	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst != nil && len(inst.OutputsToAdmit) != 0 {
		t.Fatalf("expected no admission for mismatched controller, got %+v", inst)
	}
}

// TestKVStoreAdmit_RetainsPreviousCoins confirms the canonical
// coinsToRetain: previousCoins semantic (KVStore does NOT remove prior
// coins, unlike UMP/Identity).
func TestKVStoreAdmit_RetainsPreviousCoins(t *testing.T) {
	w, ctrl := kvControllerWallet(t)
	scriptBytes := buildKVScript(t, w, ctrl, "k", "v", nil, false)
	m := NewKVStoreTopicManager()
	// Two previous coins consumed.
	inst, err := m.Admit(txWith(t, scriptBytes), make([]anviloverlay.AdmittedOutput, 2))
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst == nil {
		t.Fatal("expected non-nil instructions")
	}
	if len(inst.CoinsToRetain) != 2 {
		t.Fatalf("expected 2 retained coins, got %d", len(inst.CoinsToRetain))
	}
	if len(inst.CoinsRemoved) != 0 {
		t.Fatalf("expected 0 removed coins, got %d", len(inst.CoinsRemoved))
	}
}

// TestParseKVStoreOutput_FieldsExtracted pins the lookup-side parse:
// entry carries the UTF-8 key, raw protocolID, hex controller, and tags.
func TestParseKVStoreOutput_FieldsExtracted(t *testing.T) {
	w, ctrl := kvControllerWallet(t)
	scriptBytes := buildKVScript(t, w, ctrl, "fiat-currency", "GBP", []string{"prefs"}, true)

	entry, err := ParseKVStoreOutput(scriptBytes)
	if err != nil {
		t.Fatalf("ParseKVStoreOutput: %v", err)
	}
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	if entry.Key != "fiat-currency" {
		t.Fatalf("Key mismatch: got %q", entry.Key)
	}
	if entry.Controller != hex.EncodeToString(ctrl) {
		t.Fatalf("Controller mismatch: want %s, got %s", hex.EncodeToString(ctrl), entry.Controller)
	}
	if entry.ProtocolID != `[1,"sendbsv settings"]` {
		t.Fatalf("ProtocolID mismatch: got %q", entry.ProtocolID)
	}
	if len(entry.Tags) != 1 || entry.Tags[0] != "prefs" {
		t.Fatalf("Tags mismatch: got %+v", entry.Tags)
	}
}

// NOTE: an empty-value guard exists in decodeKVStore (mirrors the
// canonical valueBuffer.length === 0 check) but cannot be exercised
// through the canonical pushdrop.Lock path: PushDrop encodes an empty
// field as OP_0, which Decode round-trips back to a 1-byte {0} (non-
// empty). The guard is defensive parity with the upstream contract.

// TestParseKVStoreOutput_WrongFieldCountSkipped confirms a PushDrop
// output that's neither 5 nor 6 fields is not a KVStore token.
func TestParseKVStoreOutput_WrongFieldCountSkipped(t *testing.T) {
	priv, _ := ec.NewPrivateKey()
	w, _ := wallet.NewCompletedProtoWallet(priv)
	pd := &pushdrop.PushDrop{Wallet: w}
	// 3 fields, no signature → 3 total. Neither 5 nor 6.
	s, err := pd.Lock(
		context.Background(),
		[][]byte{{0x01}, {0x02}, {0x03}},
		kvSettingsProtocol, "1",
		wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		false, false, pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	entry, err := ParseKVStoreOutput(s.Bytes())
	if err != nil {
		t.Fatalf("ParseKVStoreOutput: %v", err)
	}
	if entry != nil {
		t.Fatalf("expected nil entry for 3-field output, got %+v", entry)
	}
}

// TestParseKVStoreOutput_NonPushDropIgnored / empty-script guards.
func TestParseKVStoreOutput_NonPushDropIgnored(t *testing.T) {
	entry, err := ParseKVStoreOutput([]byte{0x51}) // OP_1
	if err != nil || entry != nil {
		t.Fatalf("expected (nil, nil), got (%+v, %v)", entry, err)
	}
	entry, err = ParseKVStoreOutput(nil)
	if err != nil || entry != nil {
		t.Fatalf("expected (nil, nil) for empty, got (%+v, %v)", entry, err)
	}
}
