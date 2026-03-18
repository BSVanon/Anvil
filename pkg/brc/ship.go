package brc

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// SHIPToken holds the parsed fields of a SHIP registration token.
type SHIPToken struct {
	IdentityPub string
	Domain      string
	Topic       string
	LockingPub  []byte
}

// BuildSHIPScript builds a SHIP token locking script.
//
//	pushData("SHIP") pushData(identityPubHex) pushData(domain) pushData(topic)
//	OP_DROP OP_2DROP OP_DROP
//	pushData(lockingPub) OP_CHECKSIG
func BuildSHIPScript(identityKey *secp256k1.PrivateKey, domain, topic string) ([]byte, *secp256k1.PublicKey, error) {
	identityPub := identityKey.PubKey()
	identityPubHex := hex.EncodeToString(identityPub.SerializeCompressed())

	_, lockingPub := DeriveChild(identityKey, InvoiceSHIP)

	fields := []string{"SHIP", identityPubHex, domain, topic}
	script := BuildTokenScript(fields, lockingPub)
	return script, lockingPub, nil
}

// ParseSHIPScript extracts SHIP token fields from a locking script.
func ParseSHIPScript(script []byte) (*SHIPToken, error) {
	tf, err := ParseTokenScript(script)
	if err != nil {
		return nil, err
	}
	if tf.Protocol != "SHIP" {
		return nil, fmt.Errorf("expected SHIP protocol, got %q", tf.Protocol)
	}
	return &SHIPToken{
		IdentityPub: tf.IdentityPub,
		Domain:      tf.Domain,
		Topic:       tf.TopicProvider,
		LockingPub:  tf.LockingPub,
	}, nil
}

// ValidateSHIPToken validates that the locking pubkey in a SHIP script
// matches the BRC-42 derivation from the claimed identity pubkey.
func ValidateSHIPToken(script []byte) (*SHIPToken, error) {
	token, err := ParseSHIPScript(script)
	if err != nil {
		return nil, err
	}

	// Decode the claimed identity pubkey
	identityPubBytes, err := hex.DecodeString(token.IdentityPub)
	if err != nil {
		return nil, fmt.Errorf("invalid identity pubkey hex: %w", err)
	}
	identityPub, err := secp256k1.ParsePubKey(identityPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid identity pubkey: %w", err)
	}

	// Derive expected locking pubkey using public derivation
	expectedPub := DeriveChildPub(identityPub, InvoiceSHIP)
	expectedBytes := expectedPub.SerializeCompressed()

	if !bytesEqual(token.LockingPub, expectedBytes) {
		return nil, fmt.Errorf("locking pubkey does not match BRC-42 derivation from identity")
	}

	return token, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
