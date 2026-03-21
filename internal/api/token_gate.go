package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TokenGate verifies signed credentials for token-gated topics (Model 4).
// The app sells access credentials independently — the node only verifies
// the credential's signature against the pubkey declared in the envelope's
// monetization metadata. No funds flow through the node.
//
// Credential format (X-App-Token header):
//
//	<signature_hex>:<message_hex>
//
// Where message is: sha256(topic + ":" + timestamp_unix)
// The timestamp must be within the validity window (default 5 minutes).
// The signature is DER-encoded, verified against the auth_pubkey from
// the topic's envelope monetization metadata.
type TokenGate struct {
	resolver     *TopicMonetizationResolver
	enabled      bool
	validityWindow time.Duration
}

// NewTokenGate creates a token gating middleware.
// Returns nil if token gating is disabled or no resolver is available.
func NewTokenGate(resolver *TopicMonetizationResolver, enabled bool) *TokenGate {
	if !enabled || resolver == nil {
		return nil
	}
	return &TokenGate{
		resolver:       resolver,
		enabled:        true,
		validityWindow: 5 * time.Minute,
	}
}

// Middleware returns HTTP middleware that checks for token-gated topics.
// If the topic uses the "token" monetization model, it verifies the
// X-App-Token header. For all other models (or no monetization), the
// request passes through unchanged.
func (tg *TokenGate) Middleware(next http.HandlerFunc) http.HandlerFunc {
	if tg == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		topic := r.URL.Query().Get("topic")
		if topic == "" {
			next(w, r)
			return
		}

		mon := tg.resolver.Resolve(topic)
		if mon == nil || mon.Model != envelope.MonetizationToken {
			next(w, r)
			return
		}

		// This topic requires token authentication
		tokenHeader := r.Header.Get("X-App-Token")
		if tokenHeader == "" {
			writeError(w, http.StatusUnauthorized, "this topic requires X-App-Token credential")
			return
		}

		if err := tg.verifyToken(tokenHeader, topic, mon.AuthPubkey); err != nil {
			writeError(w, http.StatusForbidden, fmt.Sprintf("invalid token: %v", err))
			return
		}

		r.Header.Set("X-Anvil-Authed", "true")
		next(w, r)
	}
}

// verifyToken checks a credential against the expected pubkey.
// Format: <signature_hex>:<timestamp_unix>
// Signature covers: sha256(topic + ":" + timestamp_unix)
func (tg *TokenGate) verifyToken(token, topic, authPubkeyHex string) error {
	parts := strings.SplitN(token, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("expected format: <signature_hex>:<timestamp_unix>")
	}
	sigHex := parts[0]
	timestampStr := parts[1]

	// Parse the auth pubkey
	pubBytes, err := hex.DecodeString(authPubkeyHex)
	if err != nil || len(pubBytes) != 33 {
		return fmt.Errorf("invalid auth pubkey in envelope metadata")
	}
	pub, err := ec.PublicKeyFromBytes(pubBytes)
	if err != nil {
		return fmt.Errorf("invalid auth pubkey: %w", err)
	}

	// Parse the signature
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}
	sig, err := ec.FromDER(sigBytes)
	if err != nil {
		return fmt.Errorf("invalid DER signature: %w", err)
	}

	// Verify the message: sha256(topic + ":" + timestamp)
	message := topic + ":" + timestampStr
	digest := sha256.Sum256([]byte(message))

	if !sig.Verify(digest[:], pub) {
		return fmt.Errorf("signature verification failed")
	}

	// Check timestamp freshness
	var ts int64
	if _, err := fmt.Sscanf(timestampStr, "%d", &ts); err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	now := time.Now().Unix()
	if now-ts > int64(tg.validityWindow.Seconds()) || ts-now > 60 {
		return fmt.Errorf("token expired or too far in the future")
	}

	return nil
}
