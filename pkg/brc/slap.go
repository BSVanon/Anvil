package brc

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// SLAPToken holds the parsed fields of a SLAP registration token.
type SLAPToken struct {
	IdentityPub string
	Domain      string
	Provider    string
	LockingPub  []byte
}

// BuildSLAPScript builds a SLAP token locking script.
func BuildSLAPScript(identityKey *secp256k1.PrivateKey, domain, provider string) ([]byte, *secp256k1.PublicKey, error) {
	identityPub := identityKey.PubKey()
	identityPubHex := hex.EncodeToString(identityPub.SerializeCompressed())

	_, lockingPub := DeriveChild(identityKey, InvoiceSLAP)

	fields := []string{"SLAP", identityPubHex, domain, provider}
	script := BuildTokenScript(fields, lockingPub)
	return script, lockingPub, nil
}

// ParseSLAPScript extracts SLAP token fields from a locking script.
func ParseSLAPScript(script []byte) (*SLAPToken, error) {
	tf, err := ParseTokenScript(script)
	if err != nil {
		return nil, err
	}
	if tf.Protocol != "SLAP" {
		return nil, fmt.Errorf("expected SLAP protocol, got %q", tf.Protocol)
	}
	return &SLAPToken{
		IdentityPub: tf.IdentityPub,
		Domain:      tf.Domain,
		Provider:    tf.TopicProvider,
		LockingPub:  tf.LockingPub,
	}, nil
}

// ValidateSLAPToken validates that the locking pubkey in a SLAP script
// matches the BRC-42 derivation from the claimed identity pubkey.
func ValidateSLAPToken(script []byte) (*SLAPToken, error) {
	token, err := ParseSLAPScript(script)
	if err != nil {
		return nil, err
	}

	identityPubBytes, err := hex.DecodeString(token.IdentityPub)
	if err != nil {
		return nil, fmt.Errorf("invalid identity pubkey hex: %w", err)
	}
	identityPub, err := secp256k1.ParsePubKey(identityPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid identity pubkey: %w", err)
	}

	expectedPub := DeriveChildPub(identityPub, InvoiceSLAP)
	expectedBytes := expectedPub.SerializeCompressed()

	if !bytesEqual(token.LockingPub, expectedBytes) {
		return nil, fmt.Errorf("locking pubkey does not match BRC-42 derivation from identity")
	}

	return token, nil
}
