package messaging

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

const messageIDDomain = "anvil-msgid-v2\n"

func NewMessageID(msg *Message, originNode string) (string, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate message nonce: %w", err)
	}
	return deriveMessageID(msg, originNode, nonce[:]), nil
}

func IsV2MessageID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range []byte(id) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func VerifyMessageID(msg *Message, originNode string) bool {
	if msg == nil || !IsV2MessageID(msg.MessageID) || originNode == "" {
		return false
	}
	nonce, err := hex.DecodeString(msg.MessageID[:16])
	if err != nil {
		return false
	}
	return deriveMessageID(msg, originNode, nonce) == msg.MessageID
}

func deriveMessageID(msg *Message, originNode string, nonce []byte) string {
	nonceHex := hex.EncodeToString(nonce)
	canonical := messageIDDomain + originNode + "\n" + msg.Sender + "\n" +
		msg.Recipient + "\n" + msg.MessageBox + "\n" + msg.Body + "\n" +
		strconv.FormatInt(msg.Timestamp, 10) + "\n" + nonceHex
	h := sha256.Sum256([]byte(canonical))
	return nonceHex + hex.EncodeToString(h[:24])
}
