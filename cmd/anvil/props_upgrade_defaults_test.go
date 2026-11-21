package main

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/gateway"
)

type startupCallRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *startupCallRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.calls = append(r.calls, req.Method+" "+req.URL.String())
	r.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

func (r *startupCallRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func TestVersion340ConfigurationsRemainFeatureColdAtStartup(t *testing.T) {
	fixture := filepath.Join("..", "..", "internal", "config", "testdata", "anvil-v3.4.0.example.toml")
	original, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	foundry := strings.Replace(string(original), "[mesh]", "[foundry]", 1)
	foundryPath := filepath.Join(t.TempDir(), "anvil.toml")
	if err := os.WriteFile(foundryPath, []byte(foundry), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{fixture, foundryPath} {
		path := path
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("load v3.4 configuration: %v", err)
			}
			assertUpgradeSwitchesOff(t, cfg)

			cfg.Node.DataDir = t.TempDir()
			calls := &startupCallRecorder{}
			oldClient, oldTransport := http.DefaultClient, http.DefaultTransport
			http.DefaultTransport = calls
			http.DefaultClient = &http.Client{Transport: calls}
			t.Cleanup(func() {
				http.DefaultClient = oldClient
				http.DefaultTransport = oldTransport
			})

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			wallet := &countedPaymentWallet{}
			if _, _, nonce, err := wireX402Payment(cfg.API, cfg.Identity.WIF, wallet, logger); err != nil || nonce != nil {
				t.Fatalf("proof-off payment wiring = nonce %T, error %v", nonce, err)
			}
			if wallet.calls.Load() != 0 {
				t.Fatalf("challenge wallet calls = %d, want 0", wallet.calls.Load())
			}
			gate, stopGate := wireCertificateGate(cfg, nil, logger)
			defer stopGate()
			if gate != nil {
				t.Fatal("certificate gate started from v3.4 configuration")
			}

			srv := api.NewServer(api.ServerConfig{DataDir: cfg.Node.DataDir, Logger: logger})
			if tracker := wireTracking(cfg, srv, logger, trackingDeps{}); tracker != nil {
				t.Fatal("spend-backed version tracker started from v3.4 configuration")
			}
			handler := wireGateway(cfg, srv, logger, trackingDeps{})
			if _, ok := handler.(*gateway.Router); ok {
				t.Fatal("gateway router started from v3.4 configuration")
			}
			for _, name := range []string{"acme", "ordtrack", "gateway-registrations.conf"} {
				if _, err := os.Stat(filepath.Join(cfg.Node.DataDir, name)); !os.IsNotExist(err) {
					t.Fatalf("disabled startup created %s: %v", name, err)
				}
			}
			if got := calls.snapshot(); len(got) != 0 {
				t.Fatalf("new feature startup outbound calls = %v, want none", got)
			}
		})
	}
}

func assertUpgradeSwitchesOff(t *testing.T, cfg *config.Config) {
	t.Helper()
	if cfg.API.X402ProofScheme {
		t.Error("x402 proof scheme is on")
	}
	if cfg.CertGate.Enabled() || cfg.CertGate.SenderRequired || cfg.CertGate.RegistrationAllowed {
		t.Errorf("certificate switches are on: gate=%v sender=%v registration=%v", cfg.CertGate.Enabled(), cfg.CertGate.SenderRequired, cfg.CertGate.RegistrationAllowed)
	}
	if cfg.Gateway.Enabled {
		t.Error("gateway mode is on")
	}
	if len(cfg.Content.TrackOrigins) != 0 {
		t.Errorf("version tracking origins = %v, want none", cfg.Content.TrackOrigins)
	}
}
