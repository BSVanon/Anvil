// Package gossip implements the Forge mesh protocol using the canonical
// go-sdk auth.Peer for authenticated peer communication.
//
// The four message types (data, topics, data_request, data_response) are
// identical to relay-federation's data-relay.js wire protocol. They are
// serialized as JSON payloads inside auth.GeneralMessage. The auth layer
// handles identity verification, session management, and transport.
package gossip

import (
	"encoding/json"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// MessageType identifies the kind of mesh message.
type MessageType string

const (
	// MsgData carries a signed data envelope to interested peers.
	MsgData MessageType = "data"

	// MsgTopics declares which topic prefixes this peer is interested in.
	MsgTopics MessageType = "topics"

	// MsgDataRequest asks a peer for cached envelopes on a topic.
	MsgDataRequest MessageType = "data_request"

	// MsgDataResponse replies with cached envelopes.
	MsgDataResponse MessageType = "data_response"
)

// Message is the wire format for all mesh messages, serialized as
// the payload of an auth.GeneralMessage.
type Message struct {
	Type MessageType     `json:"type"`
	Data json.RawMessage `json:"data"`
}

// TopicsPayload declares interest prefixes.
type TopicsPayload struct {
	Prefixes []string `json:"prefixes"`
}

// DataRequestPayload requests cached envelopes for a topic.
type DataRequestPayload struct {
	Topic string `json:"topic"`
	Since int64  `json:"since,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

// DataResponsePayload replies with cached envelopes.
type DataResponsePayload struct {
	Topic     string               `json:"topic"`
	Envelopes []*envelope.Envelope `json:"envelopes"`
	HasMore   bool                 `json:"hasMore"`
}

// Encode serializes a message for transport via auth.GeneralMessage.
func Encode(msgType MessageType, payload any) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Message{Type: msgType, Data: data})
}

// Decode deserializes a mesh message from auth.GeneralMessage payload.
func Decode(raw []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}
