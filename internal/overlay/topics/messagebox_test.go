package topics

import (
	"context"
	"testing"

	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// mbIdentityWallet returns a fresh CompletedProtoWallet plus its own
// identity (compressed) pubkey bytes — the value that goes in the
// MessageBox advert's identity-key field. An advert is self-signed: the
// identity names itself as field[0] and signs with its own key,
// mirroring MessageBoxClient.ts:1271-1307 anointHost, where
// `identityKey = await this.getIdentityKey()` is the caller's own
// wallet identity.
func mbIdentityWallet(t *testing.T) (wallet.Interface, []byte) {
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

// lockMessageBoxFields signs an arbitrary field set with the canonical
// MessageBox advert protocol/keyID/counterparty
// (MessageBoxClient.ts:1296-1307 anointHost), returning the PushDrop
// locking script. Tests vary the field set itself (e.g. only one field,
// or a field containing invalid UTF-8) to exercise
// decodeMessageBoxAdvert's shape guards through the real Admit() path.
func lockMessageBoxFields(t *testing.T, w wallet.Interface, fields [][]byte) []byte {
	t.Helper()
	pd := &pushdrop.PushDrop{Wallet: w}
	s, err := pd.Lock(
		context.Background(),
		fields,
		messageBoxProtocol,
		messageBoxKeyID,
		wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		true, // forSelf, matching canonical anointHost (MessageBoxClient.ts:1553)
		true, // includeSignature
		pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}
	return s.Bytes()
}

// buildMessageBoxScript builds a signed MessageBox PushDrop locking
// script exactly the way MessageBoxClient.ts's anointHost builds one
// (:1296-1307): fields = [identityKey bytes, host UTF-8]. identityPub is
// the raw bytes to place in field[0] — pass a wallet-matching key for a
// valid advert, or a mismatched one to exercise the signature-mismatch
// rejection path.
func buildMessageBoxScript(t *testing.T, w wallet.Interface, identityPub []byte, host string) []byte {
	t.Helper()
	return lockMessageBoxFields(t, w, [][]byte{identityPub, []byte(host)})
}

// txWithMB wraps a locking script in a single-output transaction and
// returns its serialized bytes (the input to TopicManager.Admit).
func txWithMB(t *testing.T, scriptBytes []byte) []byte {
	t.Helper()
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		LockingScript: script.NewFromBytes(scriptBytes),
		Satoshis:      1,
	})
	return tx.Bytes()
}

// admitOne runs Admit on a single-output tx wrapping scriptBytes and
// returns the resulting instructions.
func admitOne(t *testing.T, scriptBytes []byte, previous []anviloverlay.AdmittedOutput) *anviloverlay.AdmittanceInstructions {
	t.Helper()
	m := NewMessageBoxTopicManager()
	inst, err := m.Admit(txWithMB(t, scriptBytes), previous)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	return inst
}

func assertNotAdmitted(t *testing.T, inst *anviloverlay.AdmittanceInstructions) {
	t.Helper()
	if inst != nil && len(inst.OutputsToAdmit) != 0 {
		t.Fatalf("expected no admission, got %+v", inst)
	}
}

// TestMessageBoxAdmit_AnointHostShapeAdmitted pins the canonical port's
// primary contract: an advert built exactly the way anointHost builds it
// is admitted (Tests: "an advert built exactly the way
// anointHost builds it is admitted and found" — the "found" half is
// lookups/messagebox_test.go).
func TestMessageBoxAdmit_AnointHostShapeAdmitted(t *testing.T) {
	w, identityPub := mbIdentityWallet(t)
	scriptBytes := buildMessageBoxScript(t, w, identityPub, "https://messagebox.example")

	inst := admitOne(t, scriptBytes, nil)
	if inst == nil || len(inst.OutputsToAdmit) != 1 || inst.OutputsToAdmit[0] != 0 {
		t.Fatalf("expected output 0 admitted, got %+v", inst)
	}
}

// TestMessageBoxAdmit_BadSignatureRejected: a signature that does not
// verify against the claimed identity key (here, signed by a DIFFERENT
// key than the one named in field[0] — the "swapped identity key" case
// from the spec's test list) is refused.
func TestMessageBoxAdmit_BadSignatureRejected(t *testing.T) {
	w, _ := mbIdentityWallet(t)
	_, otherIdentity := mbIdentityWallet(t) // field[0] names a different identity than the signer
	scriptBytes := buildMessageBoxScript(t, w, otherIdentity, "https://messagebox.example")

	assertNotAdmitted(t, admitOne(t, scriptBytes, nil))
}

// TestMessageBoxAdmit_MissingHostFieldRejected: an advert with no host
// field at all (only the identity key survives popping the signature) is
// refused — "field 1 is the host, and must be non-empty". Built with a
// genuine 1-field PushDrop (not a padded/empty push), so this exercises
// the real "fewer than 2 fields remain" shape, not an encoder quirk.
func TestMessageBoxAdmit_MissingHostFieldRejected(t *testing.T) {
	w, identityPub := mbIdentityWallet(t)
	scriptBytes := lockMessageBoxFields(t, w, [][]byte{identityPub})

	assertNotAdmitted(t, admitOne(t, scriptBytes, nil))
}

// TestMessageBoxAdmit_EmptyIdentityKeyRejected: field 0 present but
// zero-length (as opposed to MissingHostFieldRejected's "field 1 absent
// entirely") is refused — "field 0 is the identity key, and must be
// non-empty", the left-hand operand of messagebox.go's
// identityKeyBuf/hostBuf emptiness check, which MissingHostFieldRejected
// alone never exercises (it only ever hits the right-hand, host-side
// operand).
func TestMessageBoxAdmit_EmptyIdentityKeyRejected(t *testing.T) {
	w, _ := mbIdentityWallet(t)
	scriptBytes := lockMessageBoxFields(t, w, [][]byte{{}, []byte("https://messagebox.example")})

	assertNotAdmitted(t, admitOne(t, scriptBytes, nil))
}

// TestMessageBoxAdmit_InvalidUTF8HostAdmitted, corrected from a
// stricter prior pass: a host field containing a byte sequence that
// cannot be valid UTF-8 ({0xff, 0xfe, 0xfd}) is still admitted — canon's
// own host decode (Utils.toUTF8) is a non-fatal TextDecoder that never
// refuses this, so admission doesn't either. The host simply never
// resolves to anything useful: it isn't counted by the Home Rule (see
// TestQualifyAndNormalise_InvalidUTF8HostNotCounted,
// internal/messaging/home_test.go).
func TestMessageBoxAdmit_InvalidUTF8HostAdmitted(t *testing.T) {
	w, identityPub := mbIdentityWallet(t)
	scriptBytes := lockMessageBoxFields(t, w, [][]byte{identityPub, {0xff, 0xfe, 0xfd}})

	inst := admitOne(t, scriptBytes, nil)
	if inst == nil || len(inst.OutputsToAdmit) != 1 || inst.OutputsToAdmit[0] != 0 {
		t.Fatalf("expected output 0 admitted (invalid UTF-8 host is non-fatal, matching canon), got %+v", inst)
	}
}

// TestMessageBoxAdmit_RemovesPreviousCoins confirms the corrected
// canonical coinsToRetain: [], coinsRemoved: previousCoins semantic
// (MessageBoxTopicManager.ts:95-96): every previously-admitted coin a
// submission spends is reported as removed, never retained, so a
// revocation's OutputSpent always fires and the lookup-side storage row
// is cleaned up (see messagebox.go's header comment for the full
// history). An identity may still hold several live adverts at once —
// this governs only the coins THIS transaction's inputs actually spend.
func TestMessageBoxAdmit_RemovesPreviousCoins(t *testing.T) {
	w, identityPub := mbIdentityWallet(t)
	scriptBytes := buildMessageBoxScript(t, w, identityPub, "https://messagebox.example")
	inst := admitOne(t, scriptBytes, make([]anviloverlay.AdmittedOutput, 2))
	if inst == nil {
		t.Fatal("expected non-nil instructions")
	}
	if len(inst.CoinsToRetain) != 0 {
		t.Fatalf("expected 0 retained coins, got %d", len(inst.CoinsToRetain))
	}
	if len(inst.CoinsRemoved) != 2 {
		t.Fatalf("expected 2 removed coins, got %d", len(inst.CoinsRemoved))
	}
}

// TestParseMessageBoxOutput_FieldsExtracted pins the lookup-side parse.
func TestParseMessageBoxOutput_FieldsExtracted(t *testing.T) {
	w, identityPub := mbIdentityWallet(t)
	scriptBytes := buildMessageBoxScript(t, w, identityPub, "https://messagebox.example")

	entry, err := ParseMessageBoxOutput(scriptBytes)
	if err != nil {
		t.Fatalf("ParseMessageBoxOutput: %v", err)
	}
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	if entry.Host != "https://messagebox.example" {
		t.Fatalf("Host mismatch: got %q", entry.Host)
	}
}

// TestParseMessageBoxOutput_NonPushDropIgnored / empty-script guards.
func TestParseMessageBoxOutput_NonPushDropIgnored(t *testing.T) {
	entry, err := ParseMessageBoxOutput([]byte{0x51}) // OP_1
	if err != nil || entry != nil {
		t.Fatalf("expected (nil, nil), got (%+v, %v)", entry, err)
	}
	entry, err = ParseMessageBoxOutput(nil)
	if err != nil || entry != nil {
		t.Fatalf("expected (nil, nil) for empty, got (%+v, %v)", entry, err)
	}
}
