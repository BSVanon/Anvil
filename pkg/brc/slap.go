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

// SLAPToken holds the parsed fields of a SLAP registration token.
type SLAPToken struct {
	IdentityPub string
	Domain      string
	Provider    string
	LockingPub  *ec.PublicKey
}

// ParseSLAPScript extracts SLAP token fields from a locking script
// using go-sdk's canonical admintoken.Decode.
func ParseSLAPScript(scriptBytes []byte) (*SLAPToken, error) {
	s := script.NewFromBytes(scriptBytes)
	pd := pushdrop.Decode(s)
	if pd == nil || len(pd.Fields) < 4 {
		return nil, fmt.Errorf("not a valid BRC-48 push-drop script")
	}
	if string(pd.Fields[0]) != string(overlay.ProtocolSLAP) {
		return nil, fmt.Errorf("expected SLAP protocol, got %q", string(pd.Fields[0]))
	}

	identityKeyHex := hex.EncodeToString(pd.Fields[1])

	return &SLAPToken{
		IdentityPub: identityKeyHex,
		Domain:      string(pd.Fields[2]),
		Provider:    string(pd.Fields[3]),
		LockingPub:  pd.LockingPublicKey,
	}, nil
}

// ValidateSLAPToken validates that a SLAP script's locking pubkey matches
// the BRC-42 derivation from the claimed identity pubkey.
func ValidateSLAPToken(scriptBytes []byte) (*SLAPToken, error) {
	token, err := ParseSLAPScript(scriptBytes)
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

	expectedPub, err := DeriveChildPub(identityPub, InvoiceSLAP)
	if err != nil {
		return nil, fmt.Errorf("derive child pub: %w", err)
	}

	if !bytes.Equal(expectedPub.Compressed(), token.LockingPub.Compressed()) {
		return nil, fmt.Errorf("locking pubkey does not match BRC-42 derivation from identity")
	}

	return token, nil
}

// BuildSLAPScript builds a SLAP token locking script in lock-before format.
func BuildSLAPScript(identityKey *ec.PrivateKey, domain, provider string) ([]byte, *ec.PublicKey, error) {
	anyonePub := AnyonePub()
	lockingKey, err := identityKey.DeriveChild(anyonePub, InvoiceSLAP)
	if err != nil {
		return nil, nil, fmt.Errorf("derive SLAP key: %w", err)
	}
	lockingPub := lockingKey.PubKey()
	identityPubHex := hex.EncodeToString(identityKey.PubKey().Compressed())

	fields := [][]byte{
		[]byte("SLAP"),
		identityKey.PubKey().Compressed(), // raw 33-byte pubkey
		[]byte(domain),
		[]byte(provider),
	}
	_ = identityPubHex

	s, err := buildPushDropScript(lockingPub, fields)
	if err != nil {
		return nil, nil, err
	}
	return *s, lockingPub, nil
}
