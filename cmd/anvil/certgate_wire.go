package main

import (
	"context"
	"log/slog"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/certgate"
	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/gateway"
	"github.com/BSVanon/Anvil/internal/spendwatch"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// wireCertificateGate starts the shared verifier only for a configured policy.
func wireCertificateGate(cfg *config.Config, verifierWallet wallet.Interface, logger *slog.Logger) (*certgate.Gate, func()) {
	if cfg == nil || !cfg.CertGate.Enabled() {
		return nil, func() {}
	}
	watch := spendwatch.New(spendwatch.Config{MaxWatched: spendwatch.DefaultMaxWatched, Logger: logger})
	gate, err := certgate.New(certgate.Config{
		Certifiers: cfg.CertGate.Certifiers, Types: cfg.CertGate.Types,
		RevealFields: cfg.CertGate.RevealFields, AllowUnrevocable: cfg.CertGate.AllowUnrevocable,
		RevocationCheck: cfg.CertGate.RevocationCheck, Recheck: cfg.CertGate.RevocationRecheckDuration(),
		Wallet: verifierWallet, Watcher: watch,
	})
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go watch.Run(ctx)
	return gate, cancel
}

func wireAPICertificateGate(cfg *config.Config, gate *certgate.Gate, logger *slog.Logger) api.CertificateAdmission {
	admission := api.CertificateAdmission{Gate: gate, RequireSender: cfg.CertGate.SenderRequired}
	if gate != nil && cfg.CertGate.RegistrationAllowed {
		admission.Registration = gateway.NewRegistrar(
			cfg.Gateway.SitesFile,
			gateway.RegistrationFile(cfg.Node.DataDir),
			cfg.Gateway.APIHost,
			gate,
			logger,
		)
	}
	return admission
}

func wireCertificateSpendVerifier(gate *certgate.Gate, source certgate.TransactionSource) {
	if gate != nil {
		gate.SetSpendVerifier(certgate.SpendVerifier(source))
	}
}
