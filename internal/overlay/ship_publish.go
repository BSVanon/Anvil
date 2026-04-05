package overlay

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/BSVanon/Anvil/pkg/brc"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
)

// PublishSHIPOnChain creates a BSV transaction containing a SHIP PushDrop
// output and broadcasts it via the node wallet. This makes the node
// discoverable on-chain via JungleBus subscriptions.
//
// The transaction has one output: a SHIP token with 1 satoshi.
// The wallet handles UTXO selection and change.
//
// Returns the txid hex on success.
func PublishSHIPOnChain(
	ctx context.Context,
	wallet sdk.Interface,
	identityKey *ec.PrivateKey,
	domain string,
	topic string,
	logger *slog.Logger,
) (string, error) {
	if wallet == nil {
		return "", fmt.Errorf("no wallet configured")
	}
	if identityKey == nil {
		return "", fmt.Errorf("no identity key configured")
	}

	// Build the SHIP PushDrop script
	scriptBytes, _, err := brc.BuildSHIPScript(identityKey, domain, topic)
	if err != nil {
		return "", fmt.Errorf("build SHIP script: %w", err)
	}

	logger.Info("publishing SHIP token on-chain",
		"topic", topic,
		"domain", domain,
		"identity", hex.EncodeToString(identityKey.PubKey().Compressed())[:16],
	)

	// Create + sign + broadcast via wallet
	result, err := wallet.CreateAction(ctx, sdk.CreateActionArgs{
		Description: fmt.Sprintf("SHIP advertisement: %s on %s", topic, domain),
		Outputs: []sdk.CreateActionOutput{
			{
				LockingScript:     scriptBytes,
				Satoshis:          1,
				OutputDescription: "SHIP PushDrop token",
			},
		},
		Options: &sdk.CreateActionOptions{
			SignAndProcess:   boolPtr(true),
			RandomizeOutputs: boolPtr(false),
		},
	}, "anvil-ship")
	if err != nil {
		return "", fmt.Errorf("create SHIP tx: %w", err)
	}

	// Sign if needed (wallet may return a signable transaction)
	if result.SignableTransaction != nil {
		_, err = wallet.SignAction(ctx, sdk.SignActionArgs{
			Reference: result.SignableTransaction.Reference,
		}, "anvil-ship")
		if err != nil {
			return "", fmt.Errorf("sign SHIP tx: %w", err)
		}
	}

	txid := result.Txid.String()
	logger.Info("SHIP token published on-chain",
		"txid", txid,
		"topic", topic,
		"domain", domain,
	)

	return txid, nil
}

func boolPtr(v bool) *bool { return &v }
