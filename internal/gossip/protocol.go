// Package gossip implements the Anvil mesh protocol using the canonical
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

	// MsgSHIPSync shares SHIP overlay registrations between peers.
	// Sent on connect (full sync) and when a new registration is added.
	MsgSHIPSync MessageType = "ship_sync"

	// MsgSlashWarning notifies a peer (and the mesh) of a protocol violation.
	// First warning starts a 48-hour grace period. Repeated violations
	// within the grace period trigger deregistration from the overlay.
	MsgSlashWarning MessageType = "slash_warning"

	// MsgTxAnnounce announces a transaction by txid. Peers that don't
	// have it can request the full tx via MsgTxRequest.
	MsgTxAnnounce MessageType = "tx_announce"

	// MsgTxRequest asks a peer for a transaction by txid.
	MsgTxRequest MessageType = "tx_request"

	// MsgTxResponse carries the raw transaction hex in response to a request.
	MsgTxResponse MessageType = "tx_response"

	// MsgForward forwards a point-to-point message to the recipient's node.
	// Used for cross-node BRC-33 message delivery.
	MsgForward MessageType = "msg_forward"

	// MsgACMEChallenge replicates one ACME challenge cache entry (a
	// tls-alpn-01 token certificate or an http-01 token value) to a peer
	// gateway, point-to-point, so either gateway can answer an ACME
	// validation request for a domain both serve. It carries no
	// certificate, private key or account key — see
	// internal/gateway/acmecache.go, the only sender and receiver of this
	// type. A peer on a version that predates this type ignores it
	// (handlers.go's dispatch default case), so sending it is safe on a
	// mixed-version mesh.
	MsgACMEChallenge MessageType = "acme_challenge"
)

// ACMEChallengePayload is MsgACMEChallenge's wire payload: one
// autocert.Cache entry, named exactly as the autocert package itself
// keys it (e.g. "<domain>+token" or "<token>+http-01" — see
// certKey.String and httpTokenCacheKey in
// golang.org/x/crypto/acme/autocert). Expires is a Unix-seconds
// deadline the sender sets at most 600s ahead; the receiver never
// extends it.
type ACMEChallengePayload struct {
	Key     string `json:"key"`
	Value   []byte `json:"value"`
	Expires int64  `json:"expires"`
}

// Message is the wire format for all mesh messages, serialized as
// the payload of an auth.GeneralMessage.
type Message struct {
	Type MessageType     `json:"type"`
	Data json.RawMessage `json:"data"`
}

// TopicsPayload declares interest prefixes.
type TopicsPayload struct {
	Prefixes     []string `json:"prefixes"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// DataRequestPayload requests cached envelopes for a topic.
type DataRequestPayload struct {
	Topic  string               `json:"topic"`
	Since  int64                `json:"since,omitempty"`
	Limit  int                  `json:"limit,omitempty"`
	Cursor *envelope.PageCursor `json:"cursor,omitempty"`
}

// DataResponsePayload replies with cached envelopes.
type DataResponsePayload struct {
	Topic      string               `json:"topic"`
	Envelopes  []*envelope.Envelope `json:"envelopes"`
	HasMore    bool                 `json:"hasMore"`
	NextCursor *envelope.PageCursor `json:"nextCursor,omitempty"`
}

// SHIPSyncPayload carries SHIP peer registrations between mesh peers.
type SHIPSyncPayload struct {
	Peers []SHIPPeerInfo `json:"peers"`
}

// SHIPPeerInfo is the wire format for a SHIP registration.
type SHIPPeerInfo struct {
	IdentityPub string `json:"identity_pub"`
	Domain      string `json:"domain"`
	NodeName    string `json:"node_name,omitempty"`
	Version     string `json:"version,omitempty"`
	Topic       string `json:"topic"`
}

// TxAnnouncePayload announces a transaction by its txid.
type TxAnnouncePayload struct {
	TxID string `json:"txid"`
	Size int    `json:"size,omitempty"` // tx size in bytes (hint for receiver)
}

// TxRequestPayload requests a full transaction by txid.
type TxRequestPayload struct {
	TxID string `json:"txid"`
}

// TxResponsePayload carries the raw transaction hex.
type TxResponsePayload struct {
	TxID   string `json:"txid"`
	RawHex string `json:"raw_hex"`
}

// SlashReason identifies the type of protocol violation.
type SlashReason string

const (
	// SlashDoublePublish is retained for wire compatibility with older nodes
	// but is no longer generated. Second-granular timestamps make fast publishers
	// (oracles, IoT, agents) indistinguishable from attackers. Existing defenses
	// (rate limiting, dedup, bonds) cover the real threat surface.
	SlashDoublePublish SlashReason = "double_publish"
	SlashGossipSpam    SlashReason = "gossip_spam" // sustained rate limit violation
	SlashBadProof      SlashReason = "bad_proof"   // invalid SPV proof or forged headers
)

// SlashWarningPayload carries a protocol violation report.
type SlashWarningPayload struct {
	// Target is the identity pubkey hex of the offending peer.
	Target    string      `json:"target"`
	Reason    SlashReason `json:"reason"`
	Evidence  string      `json:"evidence,omitempty"` // human-readable or hash of proof
	Timestamp int64       `json:"timestamp"`          // unix seconds
	Reporter  string      `json:"reporter"`           // identity pubkey hex of reporting peer
}

// SlashSeverity returns the slash percentage for a given reason.
func SlashSeverity(reason SlashReason) int {
	switch reason {
	case SlashGossipSpam:
		return 25
	case SlashBadProof:
		return 50
	default:
		return 0
	}
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
