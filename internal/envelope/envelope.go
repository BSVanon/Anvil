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

// Envelope is a signed data envelope that can be ephemeral (TTL-bounded)
// or durable (persisted, never expired). This is the core data primitive
// for the relay mesh — the fix for SessionRelay's problem.
//
// The signature covers the canonical digest of all semantic fields:
// sha256(type + "\n" + topic + "\n" + payload + "\n" + ttl + "\n" + durable + "\n" + timestamp)
// This prevents any field from being changed without breaking the signature.
type Envelope struct {
	Type      string `json:"type"`                // always "data"
	Topic     string `json:"topic"`               // topic string e.g. "oracle:rates:bsv"
	Payload   string `json:"payload"`             // application data (opaque to the node)
	Signature string `json:"signature"`           // DER hex signature over canonical digest
	Pubkey    string `json:"pubkey"`              // compressed pubkey hex of the signer
	TTL       int    `json:"ttl"`                 // seconds until expiry (0 = check Durable)
	Durable   bool   `json:"durable,omitempty"`   // if true + TTL==0: persist forever
	Timestamp int64  `json:"timestamp,omitempty"` // unix timestamp when created

	// Set by the node on ingest, not by the sender
	ReceivedAt time.Time `json:"-"`
}

// SigningDigest computes the canonical digest that the signature must cover.
// All semantic fields are included so that changing any field invalidates
// the signature. Fields are joined with newlines in a fixed order.
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
	if e.TTL == 0 && !e.Durable {
		return fmt.Errorf("TTL=0 requires durable=true")
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
