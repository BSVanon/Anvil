package brc

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// anyonePub returns the generator point G — used as the "anyone" counterparty
// for SHIP/SLAP derivation where anyone can derive the child public key.
func anyonePub() *secp256k1.PublicKey {
	var oneScalar secp256k1.ModNScalar
	oneScalar.SetInt(1)
	var result secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&oneScalar, &result)
	result.ToAffine()
	return secp256k1.NewPublicKey(&result.X, &result.Y)
}

// ecdhSharedSecret computes ECDH: privKey * pubKey, returns the compressed
// point encoding (33 bytes) as used by BSV SDK's deriveSharedSecret.
func ecdhSharedSecret(privKey *secp256k1.PrivateKey, pubKey *secp256k1.PublicKey) []byte {
	var point secp256k1.JacobianPoint
	pubKey.AsJacobian(&point)
	secp256k1.ScalarMultNonConst(&privKey.Key, &point, &point)
	point.ToAffine()
	result := secp256k1.NewPublicKey(&point.X, &point.Y)
	return result.SerializeCompressed()
}

// deriveOffset computes HMAC-SHA256(sharedSecretCompressed, invoiceUTF8)
// matching BSV SDK: sha256hmac(sharedSecret.encode(true), invoiceNumberBin)
func deriveOffset(sharedSecret []byte, invoice string) []byte {
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write([]byte(invoice))
	return mac.Sum(nil)
}

// DeriveChild derives a child key pair from an identity private key and an
// invoice string, using BRC-42 key derivation.
//
// Matches BSV SDK PrivateKey.deriveChild(counterpartyPub, invoice):
//
//	sharedSecret = ECDH(identityKey, anyonePub).encode(true)  // 33-byte compressed
//	hmac = HMAC-SHA256(sharedSecret, invoiceUTF8)
//	childPriv = identityPriv + hmac (mod n)
func DeriveChild(identityKey *secp256k1.PrivateKey, invoice string) (*secp256k1.PrivateKey, *secp256k1.PublicKey) {
	shared := ecdhSharedSecret(identityKey, anyonePub())
	offset := deriveOffset(shared, invoice)

	var offScalar secp256k1.ModNScalar
	offScalar.SetByteSlice(offset)
	var childScalar secp256k1.ModNScalar
	childScalar.Set(&identityKey.Key)
	childScalar.Add(&offScalar)

	childPriv := secp256k1.NewPrivateKey(&childScalar)
	return childPriv, childPriv.PubKey()
}

// DeriveChildPub derives a child public key from an identity public key and
// an invoice string. This is the public-only variant — anyone can compute
// this without knowing the private key.
//
// Matches BSV SDK PublicKey.deriveChild(counterpartyPriv, invoice):
//
//	sharedSecret = ECDH(scalar(1), identityPub).encode(true)
//	hmac = HMAC-SHA256(sharedSecret, invoiceUTF8)
//	childPub = identityPub + hmac*G
func DeriveChildPub(identityPub *secp256k1.PublicKey, invoice string) *secp256k1.PublicKey {
	// ECDH with "anyone" private key (scalar 1)
	var anyoneKey secp256k1.ModNScalar
	anyoneKey.SetInt(1)
	anyonePriv := secp256k1.NewPrivateKey(&anyoneKey)
	shared := ecdhSharedSecret(anyonePriv, identityPub)
	offset := deriveOffset(shared, invoice)

	// childPub = identityPub + offset*G
	var offScalar secp256k1.ModNScalar
	offScalar.SetByteSlice(offset)
	var offsetPoint secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&offScalar, &offsetPoint)

	var idPoint secp256k1.JacobianPoint
	identityPub.AsJacobian(&idPoint)
	secp256k1.AddNonConst(&idPoint, &offsetPoint, &idPoint)
	idPoint.ToAffine()

	return secp256k1.NewPublicKey(&idPoint.X, &idPoint.Y)
}
