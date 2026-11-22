package config

import (
	"strings"
	"testing"
)

func TestMeshPeerExchangeDefaultsAndOverrides(t *testing.T) {
	cfg, err := Load(writeTestConfig(t, t.TempDir(), "[node]\nname = \"test\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Mesh.PeerExchange || cfg.Mesh.MaxExchangePeers != 8 || cfg.Mesh.AdvertiseURL != "" {
		t.Fatalf("unexpected defaults: %+v", cfg.Mesh)
	}
	override, err := Load(writeTestConfig(t, t.TempDir(), `[mesh]
peer_exchange = false
advertise_url = "wss://node.example/mesh"
max_exchange_peers = 0
`))
	if err != nil {
		t.Fatal(err)
	}
	if override.Mesh.PeerExchange || override.Mesh.MaxExchangePeers != 0 || override.Mesh.AdvertiseURL != "wss://node.example/mesh" {
		t.Fatalf("overrides not preserved: %+v", override.Mesh)
	}
}

func TestMeshPeerExchangeValidationNamesKey(t *testing.T) {
	tests := []struct {
		body, key string
	}{
		{"[mesh]\nmax_exchange_peers = -1\n", "mesh.max_exchange_peers"},
		{"[mesh]\nmax_exchange_peers = 65\n", "mesh.max_exchange_peers"},
		{"[mesh]\nadvertise_url = \"https://node.example/mesh\"\n", "mesh.advertise_url"},
		{"[mesh]\nadvertise_url = \"ws://user@node.example\"\n", "mesh.advertise_url"},
		{"[mesh]\nadvertise_url = \"ws://node.example?query=1\"\n", "mesh.advertise_url"},
		{"[mesh]\nadvertise_url = \"ws://node.example#fragment\"\n", "mesh.advertise_url"},
		{"[mesh]\nadvertise_url = \"ws://" + strings.Repeat("a", 510) + "\"\n", "mesh.advertise_url"},
	}
	for _, test := range tests {
		_, err := Load(writeTestConfig(t, t.TempDir(), test.body))
		if err == nil || !strings.Contains(err.Error(), test.key) {
			t.Fatalf("body %q: error %v does not name %s", test.body, err, test.key)
		}
	}
}
