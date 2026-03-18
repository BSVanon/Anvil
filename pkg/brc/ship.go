package brc

import (
	"bytes"
	"encoding/hex"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
)


// SHIPToken holds the parsed fields of a SHIP registration token.
type SHIPToken struct {
	IdentityPub string
	Domain      string
	Topic       string
	LockingPub  *ec.PublicKey
}

// ParseSHIPScript extracts SHIP token fields from a locking script
// using go-sdk's canonical admintoken.Decode.
func ParseSHIPScript(scriptBytes []byte) (*SHIPToken, error) {
	s := script.NewFromBytes(scriptBytes)
	// Use pushdrop.Decode to get the locking public key and fields
	pd := pushdrop.Decode(s)
	if pd == nil || len(pd.Fields) < 4 {
		return nil, fmt.Errorf("not a valid BRC-48 push-drop script")
	}
	if string(pd.Fields[0]) != string(overlay.ProtocolSHIP) {
		return nil, fmt.Errorf("expected SHIP protocol, got %q", string(pd.Fields[0]))
	}

	identityKeyHex := hex.EncodeToString(pd.Fields[1])

	return &SHIPToken{
		IdentityPub: identityKeyHex,
		Domain:      string(pd.Fields[2]),
		Topic:       string(pd.Fields[3]),
		LockingPub:  pd.LockingPublicKey, // the actual locking key from the script
	}, nil
}

// ValidateSHIPToken validates that a SHIP script's locking pubkey matches
// the BRC-42 derivation from the claimed identity pubkey.
// Uses go-sdk's canonical ec.PublicKey.DeriveChild.
func ValidateSHIPToken(scriptBytes []byte) (*SHIPToken, error) {
	token, err := ParseSHIPScript(scriptBytes)
	if err != nil {
		return nil, err
	}

	identityPubBytes, err := hex.DecodeString(token.IdentityPub)
	if err != nil {
		return nil, fmt.Errorf("invalid identity pubkey hex: %w", err)
	}
	identityPub, err := ec.PublicKeyFromBytes(identityPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid identity pubkey: %w", err)
	}

	// Derive expected locking pubkey using canonical SDK derivation
	expectedPub, err := DeriveChildPub(identityPub, InvoiceSHIP)
	if err != nil {
		return nil, fmt.Errorf("derive child pub: %w", err)
	}

	if !bytes.Equal(expectedPub.Compressed(), token.LockingPub.Compressed()) {
		return nil, fmt.Errorf("locking pubkey does not match BRC-42 derivation from identity")
	}

	return token, nil
}

// BuildSHIPScript builds a SHIP token locking script in lock-before format
// compatible with go-sdk's pushdrop.Decode.
// Uses go-sdk's ec.PrivateKey.DeriveChild for key derivation and
// pushdrop.CreateMinimallyEncodedScriptChunk for script encoding.
func BuildSHIPScript(identityKey *ec.PrivateKey, domain, topic string) ([]byte, *ec.PublicKey, error) {
	anyonePub := AnyonePub()
	lockingKey, err := identityKey.DeriveChild(anyonePub, InvoiceSHIP)
	if err != nil {
		return nil, nil, fmt.Errorf("derive SHIP key: %w", err)
	}
	lockingPub := lockingKey.PubKey()
	identityPubHex := hex.EncodeToString(identityKey.PubKey().Compressed())

	fields := [][]byte{
		[]byte("SHIP"),
		identityKey.PubKey().Compressed(), // raw 33-byte pubkey, not hex string
		[]byte(domain),
		[]byte(topic),
	}
	_ = identityPubHex // used in return value via admintoken.Decode

	s, err := buildPushDropScript(lockingPub, fields)
	if err != nil {
		return nil, nil, err
	}
	return *s, lockingPub, nil
}
