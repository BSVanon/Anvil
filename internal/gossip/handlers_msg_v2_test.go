package gossip

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/messaging"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func v2Forward(t *testing.T) (*messaging.Message, MsgForwardPayload, *ec.PrivateKey) {
	t.Helper()
	node, origin := newID(t)
	_, sender := newID(t)
	_, recipient := newID(t)
	msg := &messaging.Message{Sender: sender, Recipient: recipient, MessageBox: "box", Body: "body", Timestamp: 1700000000}
	id, err := messaging.NewMessageID(msg, origin)
	if err != nil {
		t.Fatal(err)
	}
	msg.MessageID = id
	return msg, originAttest(t, node, msg), node
}

func TestForwardForgedThenLegitimateSameID(t *testing.T) {
	msg, legitimate, _ := v2Forward(t)
	other, _ := newID(t)
	d := messageForwardDigest(msg, legitimate.OriginNode)
	badSig, _ := other.Sign(d[:])
	forged := legitimate
	forged.Signature = hex.EncodeToString(badSig.Serialize())

	store, err := messaging.NewStore(t.TempDir(), messaging.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	badRaw, _ := json.Marshal(forged)
	goodRaw, _ := json.Marshal(legitimate)
	_ = mgr.onMsgForward("peer", badRaw)
	_ = mgr.onMsgForward("peer", goodRaw)
	got, _ := store.List(msg.Recipient, msg.MessageBox)
	if len(got) != 1 || got[0].MessageID != msg.MessageID {
		t.Fatalf("legitimate forward was suppressed: %+v", got)
	}
}

func TestForwardRejectsV2BindingTamperAndAcceptsLegacy(t *testing.T) {
	base, fwd, originKey := v2Forward(t)
	for name, mutate := range map[string]func(*MsgForwardPayload){
		"body": func(value *MsgForwardPayload) { value.Message.Body += "!" },
		"origin": func(value *MsgForwardPayload) {
			node, origin := newID(t)
			value.OriginNode = origin
			d := messageForwardDigest(&value.Message, origin)
			sig, _ := node.Sign(d[:])
			value.Signature = hex.EncodeToString(sig.Serialize())
		},
		"nonce": func(value *MsgForwardPayload) {
			first := byte('0')
			if value.Message.MessageID[0] == '0' {
				first = '1'
			}
			value.Message.MessageID = string(first) + value.Message.MessageID[1:]
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := fwd
			mutate(&value)
			if name == "body" || name == "nonce" {
				// Keep the original origin and re-sign the tampered content so the
				// rejection specifically exercises the ID binding.
				d := messageForwardDigest(&value.Message, value.OriginNode)
				sig, _ := originKey.Sign(d[:])
				value.Signature = hex.EncodeToString(sig.Serialize())
			}
			store, _ := messaging.NewStore(t.TempDir(), messaging.Options{})
			defer store.Close()
			mgr := NewManager(ManagerConfig{Logger: slog.Default()})
			mgr.SetMsgStore(store)
			raw, _ := json.Marshal(value)
			_ = mgr.onMsgForward("peer", raw)
			if store.Count() != 0 {
				t.Fatal("binding-tampered message stored")
			}
		})
	}

	senderKey, sender := newID(t)
	legacy := &messaging.Message{MessageID: "1000000", Sender: sender, Recipient: base.Recipient, MessageBox: "box", Body: "legacy", Timestamp: 1700000001}
	d := messageDigest(legacy)
	sig, _ := senderKey.Sign(d[:])
	legacyFwd := MsgForwardPayload{Message: *legacy, Signature: hex.EncodeToString(sig.Serialize())}
	store, _ := messaging.NewStore(t.TempDir(), messaging.Options{})
	defer store.Close()
	mgr := NewManager(ManagerConfig{Logger: slog.Default()})
	mgr.SetMsgStore(store)
	raw, _ := json.Marshal(legacyFwd)
	_ = mgr.onMsgForward("peer", raw)
	got, _ := store.List(legacy.Recipient, "box")
	if len(got) != 1 || got[0].AttestedBy != "sender" {
		t.Fatalf("legacy forward = %+v", got)
	}
}

func TestSendOriginMatchesForwardOriginAndNoStorageFieldsOnWire(t *testing.T) {
	node, origin := newID(t)
	_, sender := newID(t)
	_, recipient := newID(t)
	store, _ := messaging.NewStore(t.TempDir(), messaging.Options{})
	defer store.Close()
	msg := &messaging.Message{Sender: sender, Recipient: recipient, MessageBox: "box", Body: "body"}
	if _, err := store.Send(msg, origin); err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(ManagerConfig{Logger: slog.Default(), IdentityKey: node})
	fwd := mgr.signedForwardPayload(msg)
	if fwd.OriginNode != origin || !messaging.VerifyMessageID(&fwd.Message, fwd.OriginNode) || !verifyForwardSignature(&fwd) {
		t.Fatalf("forward origin/binding mismatch: %+v", fwd)
	}
	raw, _ := json.Marshal(fwd)
	if strings.Contains(string(raw), "senderAttestedBy") || strings.Contains(string(raw), "receivedAt") {
		t.Fatalf("storage metadata leaked onto forward: %s", raw)
	}

	var incoming MsgForwardPayload
	injected := strings.Replace(string(raw), `"body":"body"`, `"body":"body","senderAttestedBy":"mallory"`, 1)
	if err := json.Unmarshal([]byte(injected), &incoming); err != nil {
		t.Fatal(err)
	}
	if encoded, _ := json.Marshal(incoming); strings.Contains(string(encoded), "senderAttestedBy") {
		t.Fatalf("incoming storage attestation survived: %s", encoded)
	}
	receiver, _ := messaging.NewStore(t.TempDir(), messaging.Options{})
	defer receiver.Close()
	receivingManager := NewManager(ManagerConfig{Logger: slog.Default()})
	receivingManager.SetMsgStore(receiver)
	_ = receivingManager.onMsgForward("peer", json.RawMessage(injected))
	got, _ := receiver.List(recipient, "box")
	if len(got) != 1 || got[0].AttestedBy != origin {
		t.Fatalf("incoming attestation was not ignored: %+v", got)
	}
}
