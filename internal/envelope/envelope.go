package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// Valid monetization models per NON_CUSTODIAL_PAYMENT_POLICY.md.
const (
	MonetizationPassthrough = "passthrough" // App is direct merchant (Model 2)
	MonetizationSplit       = "split"       // Atomic dual-pay: node + app (Model 3)
	MonetizationToken       = "token"       // License/token gating (Model 4)
	MonetizationFree        = "free"        // Explicit free (same as absent)
)

// Monetization declares how consumers pay for data in this envelope.
// Per NON_CUSTODIAL_PAYMENT_POLICY.md, the node never receives funds
// destined for another party. All payment flows are direct.
type Monetization struct {
	// Model identifies the payment model: "passthrough", "split", "token", or "free".
	// When absent or "free", the node's own x402 config applies (Model 1) or data is free.
	Model string `json:"model"`

	// PayeeLockingScriptHex is the app's P2PKH (or other) locking script in hex.
	// Required for "passthrough" and "split" models. Payments go directly to this
	// script — the node never touches these funds.
	PayeeLockingScriptHex string `json:"payee_locking_script_hex,omitempty"`

	// PriceSats is the app's price per query in satoshis.
	// Required for "passthrough" and "split" models.
	PriceSats int `json:"price_sats,omitempty"`

	// AuthPubkey is the app's signing pubkey for credential verification.
	// Required for "token" model. The node verifies credentials against
	// this key but handles zero payment.
	AuthPubkey string `json:"auth_pubkey,omitempty"`
}

// Validate checks that the monetization fields are internally consistent.
func (m *Monetization) Validate() error {
	switch m.Model {
	case "passthrough":
		if m.PayeeLockingScriptHex == "" {
			return fmt.Errorf("passthrough model requires payee_locking_script_hex")
		}
		if m.PriceSats <= 0 {
			return fmt.Errorf("passthrough model requires price_sats > 0")
		}
		if _, err := hex.DecodeString(m.PayeeLockingScriptHex); err != nil {
			return fmt.Errorf("invalid payee_locking_script_hex: %w", err)
		}
	case "split":
		if m.PayeeLockingScriptHex == "" {
			return fmt.Errorf("split model requires payee_locking_script_hex")
		}
		if m.PriceSats <= 0 {
			return fmt.Errorf("split model requires price_sats > 0")
		}
		if _, err := hex.DecodeString(m.PayeeLockingScriptHex); err != nil {
			return fmt.Errorf("invalid payee_locking_script_hex: %w", err)
		}
	case "token":
		if m.AuthPubkey == "" {
			return fmt.Errorf("token model requires auth_pubkey")
		}
		pubBytes, err := hex.DecodeString(m.AuthPubkey)
		if err != nil || len(pubBytes) != 33 {
			return fmt.Errorf("auth_pubkey must be 33-byte compressed pubkey hex")
		}
	case "free":
		// No additional fields required
	default:
		return fmt.Errorf("unknown model %q — must be passthrough, split, token, or free", m.Model)
	}
	return nil
}

// Envelope is a signed data envelope that can be ephemeral (TTL-bounded)
// or durable (persisted, never expired). This is the core data primitive
// for the relay mesh — the fix for SessionRelay's problem.
//
// The signature covers the canonical digest of all semantic fields:
// sha256(type + "\n" + topic + "\n" + payload + "\n" + ttl + "\n" + durable + "\n" + timestamp)
// This prevents any field from being changed without breaking the signature.
type Envelope struct {
	Version   int    `json:"version,omitempty"`   // protocol version (0/absent = v0, future-proofing)
	Type      string `json:"type"`                // always "data"
	Topic     string `json:"topic"`               // topic string e.g. "oracle:rates:bsv"
	Payload   string `json:"payload"`             // application data (opaque to the node)
	Signature string `json:"signature"`           // DER hex signature over canonical digest
	Pubkey    string `json:"pubkey"`              // compressed pubkey hex of the signer
	TTL       int    `json:"ttl"`                 // seconds until expiry (0 = check Durable)
	Durable   bool   `json:"durable,omitempty"`   // if true + TTL==0: persist forever
	Timestamp int64  `json:"timestamp"`           // unix timestamp when created (required)

	// Gossip controls whether this envelope is forwarded to mesh peers.
	// Default (false/absent) = gossip to all peers. Set true to keep local-only.
	// Local-only envelopes are served via API but never forwarded via mesh gossip.
	NoGossip bool `json:"no_gossip,omitempty"`

	// Monetization declares how consumers pay for this data. Optional.
	// When present, it is included in the signing digest so the app
	// controls the payment terms and they can't be altered in transit.
	Monetization *Monetization `json:"monetization,omitempty"`

	// Set by the node on ingest, not by the sender
	ReceivedAt time.Time `json:"-"`
}

// SigningDigest computes the canonical digest that the signature must cover.
// All semantic fields are included so that changing any field invalidates
// the signature. Fields are joined with newlines in a fixed order.
//
// The monetization block is included when present so that the app controls
// payment terms — a node or intermediary cannot alter the payee script,
// price, or model without breaking the signature.
func (e *Envelope) SigningDigest() [32]byte {
	durableStr := "false"
	if e.Durable {
		durableStr = "true"
	}
	canonical := e.Type + "\n" +
		e.Topic + "\n" +
		e.Payload + "\n" +
		strconv.Itoa(e.TTL) + "\n" +
		durableStr + "\n" +
		strconv.FormatInt(e.Timestamp, 10)

	// NoGossip flag is appended when true — backwards compatible with
	// envelopes that don't set it (digest is identical to before).
	if e.NoGossip {
		canonical += "\nno_gossip"
	}

	// Version is appended when > 0 — backwards compatible with
	// v0 envelopes (digest is identical to before).
	if e.Version > 0 {
		canonical += "\nv" + strconv.Itoa(e.Version)
	}

	// Monetization is appended when present — backwards compatible with
	// envelopes that have no monetization (digest is identical to before).
	if e.Monetization != nil {
		canonical += "\n" + e.Monetization.Model
		if e.Monetization.PayeeLockingScriptHex != "" {
			canonical += "\n" + e.Monetization.PayeeLockingScriptHex
		}
		if e.Monetization.PriceSats > 0 {
			canonical += "\n" + strconv.Itoa(e.Monetization.PriceSats)
		}
		if e.Monetization.AuthPubkey != "" {
			canonical += "\n" + e.Monetization.AuthPubkey
		}
	}

	return sha256.Sum256([]byte(canonical))
}

// Sign signs the envelope with the given private key, setting Signature and Pubkey.
// Sign signs the envelope with the given private key using go-sdk's ec.Sign.
func (e *Envelope) Sign(key *ec.PrivateKey) {
	digest := e.SigningDigest()
	sig, _ := key.Sign(digest[:])
	e.Signature = hex.EncodeToString(sig.Serialize())
	e.Pubkey = hex.EncodeToString(key.PubKey().Compressed())
}

// Validate checks structural validity and signature.
// Returns an error if the envelope is malformed or the signature is invalid.
func (e *Envelope) Validate() error {
	if e.Topic == "" {
		return fmt.Errorf("empty topic")
	}
	if e.Payload == "" {
		return fmt.Errorf("empty payload")
	}
	if e.Signature == "" {
		return fmt.Errorf("empty signature")
	}
	if e.Pubkey == "" {
		return fmt.Errorf("empty pubkey")
	}
	if e.TTL < 0 {
		return fmt.Errorf("negative TTL")
	}
	// Timestamp=0 is accepted for backward compat with legacy envelopes.
	// Callers (e.g. Store.Ingest) backfill after signature verification.
	if e.TTL == 0 && !e.Durable {
		return fmt.Errorf("TTL=0 requires durable=true")
	}

	// Validate monetization if present
	if e.Monetization != nil {
		if err := e.Monetization.Validate(); err != nil {
			return fmt.Errorf("invalid monetization: %w", err)
		}
	}

	// Verify signature over canonical digest (all semantic fields)
	pubBytes, err := hex.DecodeString(e.Pubkey)
	if err != nil {
		return fmt.Errorf("invalid pubkey hex: %w", err)
	}
	pub, err := ec.PublicKeyFromBytes(pubBytes)
	if err != nil {
		return fmt.Errorf("invalid pubkey: %w", err)
	}

	sigBytes, err := hex.DecodeString(e.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}
	sig, err := ec.FromDER(sigBytes)
	if err != nil {
		return fmt.Errorf("invalid DER signature: %w", err)
	}

	digest := e.SigningDigest()
	if !sig.Verify(digest[:], pub) {
		return fmt.Errorf("signature does not match envelope contents")
	}

	return nil
}

// IsExpired returns whether an ephemeral envelope has exceeded its TTL.
func (e *Envelope) IsExpired() bool {
	if e.Durable {
		return false
	}
	if e.ReceivedAt.IsZero() {
		return false
	}
	return time.Since(e.ReceivedAt) > time.Duration(e.TTL)*time.Second
}

// Key returns the storage key for this envelope: topic + pubkey prefix + payload hash.
func (e *Envelope) Key() string {
	h := sha256.Sum256([]byte(e.Payload))
	return e.Topic + ":" + e.Pubkey[:16] + ":" + hex.EncodeToString(h[:8])
}

// Marshal encodes the envelope as JSON for storage/transmission.
func (e *Envelope) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// UnmarshalEnvelope decodes an envelope from JSON.
func UnmarshalEnvelope(data []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// HashEnvelope returns a dedup key for an envelope based on its identifying fields.
// Includes payload hash so two envelopes in the same second from the same key
// with different payloads are not falsely deduped.
func HashEnvelope(topic, pubkey, payload string, timestamp int64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%d", topic, pubkey, payload, timestamp)))
	return hex.EncodeToString(h[:16])
}
