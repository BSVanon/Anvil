package messaging

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	PrivateHomeClaim   = "claim"
	PrivateHomeRelease = "release"

	privateHomeProtocolName = "anvil private home"
	privateHomeKeyID        = "1"
	privateHomeMaxFuture    = 10 * time.Minute
	privateHomeMaxSignature = 160
)

var (
	ErrPrivateHomeInvalid      = errors.New("invalid private home claim")
	ErrPrivateHomeStale        = errors.New("private home claim is stale")
	ErrPrivateHomeLimit        = errors.New("private home member limit reached")
	ErrPrivateHomeIncompatible = errors.New("private home gateway is incompatible")
)

// PrivateHomeRecord is an Anvil-only off-chain home claim or release.
type PrivateHomeRecord struct {
	Kind      string   `json:"kind"`
	Member    string   `json:"member"`
	Homes     []string `json:"homes"`
	IssuedAt  int64    `json:"issuedAt"`
	ExpiresAt int64    `json:"expiresAt"`
	Signature string   `json:"signature"`
}

var privateHomeProtocol = wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: privateHomeProtocolName}

// PrivateHomeCanonicalBytes returns the exact bytes signed by a member wallet.
func PrivateHomeCanonicalBytes(record PrivateHomeRecord) []byte {
	return []byte("anvil-private-home/v1\n" + record.Kind + "\n" + record.Member + "\n" +
		strings.Join(record.Homes, ",") + "\n" + strconv.FormatInt(record.IssuedAt, 10) + "\n" +
		strconv.FormatInt(record.ExpiresAt, 10))
}

// PrivateHomeVerifier validates record shape, policy, time bounds, and signature.
type PrivateHomeVerifier struct {
	maxTTL       int64
	allowedHomes map[string]struct{}
	now          func() time.Time
	anyoneWallet *wallet.ProtoWallet
}

func newPrivateHomeVerifier(maxTTL int64, allowedHomes []string, now func() time.Time) *PrivateHomeVerifier {
	allowed := make(map[string]struct{}, len(allowedHomes))
	for _, home := range allowedHomes {
		allowed[strings.ToLower(home)] = struct{}{}
	}
	if now == nil {
		now = time.Now
	}
	anyone, _ := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypeAnyone})
	return &PrivateHomeVerifier{maxTTL: maxTTL, allowedHomes: allowed, now: now, anyoneWallet: anyone}
}

// Validate verifies a signed record. It checks bounded string shapes before
// decoding any hexadecimal material.
func (v *PrivateHomeVerifier) Validate(ctx context.Context, record PrivateHomeRecord) error {
	if record.Kind != PrivateHomeClaim && record.Kind != PrivateHomeRelease {
		return invalidPrivateHome("kind")
	}
	if len(record.Member) != 66 || len(record.Signature) == 0 || len(record.Signature) > privateHomeMaxSignature {
		return invalidPrivateHome("member or signature size")
	}
	member, err := strictCompressedKey(record.Member)
	if err != nil {
		return invalidPrivateHome("member")
	}
	if len(record.Homes) > 3 {
		return invalidPrivateHome("homes")
	}
	if record.Kind == PrivateHomeClaim {
		if len(record.Homes) == 0 {
			return invalidPrivateHome("homes")
		}
		for i, home := range record.Homes {
			if len(home) != 66 {
				return invalidPrivateHome("home size")
			}
			if _, err := strictCompressedKey(home); err != nil {
				return invalidPrivateHome("home")
			}
			if i > 0 && record.Homes[i-1] >= home {
				return invalidPrivateHome("homes must be strictly ascending")
			}
			if _, ok := v.allowedHomes[home]; !ok {
				return invalidPrivateHome("home is not an allowed peer")
			}
		}
	} else if record.Homes == nil || len(record.Homes) != 0 || record.ExpiresAt != 0 {
		return invalidPrivateHome("release shape")
	}

	now := v.now()
	if record.IssuedAt > now.Add(privateHomeMaxFuture).UnixMilli() {
		return invalidPrivateHome("issuedAt is too far in the future")
	}
	if record.Kind == PrivateHomeClaim {
		if record.ExpiresAt <= now.Unix() || record.ExpiresAt > record.IssuedAt/1000+v.maxTTL {
			return invalidPrivateHome("expiresAt")
		}
	}
	if len(record.Signature)%2 != 0 {
		return invalidPrivateHome("signature")
	}
	rawSignature, err := hex.DecodeString(record.Signature)
	if err != nil || len(rawSignature) > privateHomeMaxSignature/2 {
		return invalidPrivateHome("signature")
	}
	signature, err := ec.FromDER(rawSignature)
	if err != nil {
		return invalidPrivateHome("signature")
	}
	if v.anyoneWallet == nil {
		return fmt.Errorf("%w: verifier unavailable", ErrPrivateHomeInvalid)
	}
	_, err = v.anyoneWallet.VerifySignature(ctx, wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   privateHomeProtocol,
			KeyID:        privateHomeKeyID,
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: member},
		},
		Data:      PrivateHomeCanonicalBytes(record),
		Signature: signature,
	}, "")
	if err != nil {
		return invalidPrivateHome("signature")
	}
	return nil
}

func strictCompressedKey(value string) (*ec.PublicKey, error) {
	if value != strings.ToLower(value) || len(value) != 66 || value[0] != '0' || (value[1] != '2' && value[1] != '3') {
		return nil, ErrPrivateHomeInvalid
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 33 {
		return nil, ErrPrivateHomeInvalid
	}
	return ec.PublicKeyFromBytes(raw)
}

func invalidPrivateHome(field string) error {
	return fmt.Errorf("%w: %s", ErrPrivateHomeInvalid, field)
}
