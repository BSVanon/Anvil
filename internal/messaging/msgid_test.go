package messaging

import "testing"

func TestMessageIDBindingAndLegacyShape(t *testing.T) {
	origin := testIdentity(t)
	msg := &Message{Sender: testIdentity(t), Recipient: testIdentity(t), MessageBox: "box", Body: "body", Timestamp: 1700000000}
	id, err := NewMessageID(msg, origin)
	if err != nil {
		t.Fatal(err)
	}
	msg.MessageID = id
	if !VerifyMessageID(msg, origin) {
		t.Fatal("valid binding rejected")
	}
	for name, mutate := range map[string]func(*Message, *string){
		"body":   func(m *Message, _ *string) { m.Body += "!" },
		"origin": func(_ *Message, o *string) { *o = testIdentity(t) },
		"nonce": func(m *Message, _ *string) {
			first := "0"
			if m.MessageID[0] == '0' {
				first = "1"
			}
			m.MessageID = first + m.MessageID[1:]
		},
	} {
		t.Run(name, func(t *testing.T) {
			copyMsg, copyOrigin := *msg, origin
			mutate(&copyMsg, &copyOrigin)
			if VerifyMessageID(&copyMsg, copyOrigin) {
				t.Fatal("tampered binding accepted")
			}
		})
	}
	if IsV2MessageID("1000000") {
		t.Fatal("legacy decimal ID classified as v2")
	}
}
