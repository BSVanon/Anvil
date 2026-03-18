// Package brc provides BRC-42/43/48 key derivation and SHIP/SLAP token
// operations. All crypto is delegated to go-sdk's canonical implementations.
package brc

import (
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// DeriveChild derives a child key pair from an identity private key and an
// invoice string, using BRC-42 key derivation via go-sdk.
//
// For SHIP/SLAP with "anyone" counterparty, pass AnyonePub() as the
// counterparty public key.
func DeriveChild(identityKey *ec.PrivateKey, counterpartyPub *ec.PublicKey, invoice string) (*ec.PrivateKey, error) {
	return identityKey.DeriveChild(counterpartyPub, invoice)
}

// DeriveChildPub derives a child public key from an identity public key
// using the "anyone" private key. This is the public-only variant.
func DeriveChildPub(identityPub *ec.PublicKey, invoice string) (*ec.PublicKey, error) {
	anyonePriv, _ := wallet.AnyoneKey()
	return identityPub.DeriveChild(anyonePriv, invoice)
}

// AnyonePub returns the "anyone" public key (generator point G, scalar 1).
func AnyonePub() *ec.PublicKey {
	_, pub := wallet.AnyoneKey()
	return pub
}

// AnyonePriv returns the "anyone" private key (scalar 1).
func AnyonePriv() *ec.PrivateKey {
	priv, _ := wallet.AnyoneKey()
	return priv
}
