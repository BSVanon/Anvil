package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

type configBeforeCertificateGate struct {
	Node         NodeConfig
	Identity     IdentityConfig
	Peers        PeersConfig
	Mesh         MeshConfig
	Foundry      MeshConfig
	BSV          BSVConfig
	ARC          ARCConfig
	JungleBus    JungleBusConfig
	Overlay      OverlayConfig
	Envelopes    EnvelopeConfig
	Messaging    MessagingConfig
	Mempool      MempoolConfig
	API          APIConfig
	Capabilities CapabilitiesConfig
	Gateway      GatewayConfig
	Content      ContentConfig
}

func previousConfigFields(c *Config) configBeforeCertificateGate {
	return configBeforeCertificateGate{
		Node: c.Node, Identity: c.Identity, Peers: c.Peers, Mesh: c.Mesh, Foundry: c.Foundry,
		BSV: c.BSV, ARC: c.ARC, JungleBus: c.JungleBus, Overlay: c.Overlay, Envelopes: c.Envelopes,
		Messaging: c.Messaging, Mempool: c.Mempool, API: c.API, Capabilities: c.Capabilities,
		Gateway: c.Gateway, Content: c.Content,
	}
}

func removeExampleCertificateAdditions(raw string) string {
	start := strings.Index(raw, "[gateway]\nenabled = false")
	end := strings.Index(raw, "\n[bsv]")
	if start >= 0 && end > start {
		raw = raw[:start] + raw[end+1:]
	}
	return raw
}

func TestCertificateConfigurationIsInertWhenUsesAreOff(t *testing.T) {
	raw, err := os.ReadFile("../../anvil.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	exampleDir := t.TempDir()
	current, err := Load(writeTestConfig(t, exampleDir, string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	withoutAdditions, err := Load(writeTestConfig(t, exampleDir, removeExampleCertificateAdditions(string(raw))))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(previousConfigFields(current), previousConfigFields(withoutAdditions)) {
		t.Fatal("example configuration changed a pre-existing field")
	}

	gatewayOnly := "[gateway]\nenabled = true\napi_host = \"gateway.example\"\n"
	withUnusedPolicy := gatewayOnly + "[certgate]\ncertifiers = [\"" + testCertifier + "\"]\ntypes = [\"" + testCertificateType + "\"]\n"
	gatewayDir := t.TempDir()
	legacy, err := Load(writeTestConfig(t, gatewayDir, gatewayOnly))
	if err != nil {
		t.Fatal(err)
	}
	configured, err := Load(writeTestConfig(t, gatewayDir, withUnusedPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(previousConfigFields(legacy), previousConfigFields(configured)) {
		t.Fatal("unused certificate policy changed gateway configuration")
	}
}

func TestCertificateConfigurationFailsClosed(t *testing.T) {
	validPolicy := "[certgate]\ncertifiers = [\"" + testCertifier + "\"]\ntypes = [\"" + testCertificateType + "\"]\n"
	otherType := "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	tests := map[string]string{
		"sender switch without policy":       "[messaging]\nrequire_sender_certificate = true\n",
		"registration switch without policy": "[gateway]\nenabled = true\napi_host = \"gateway.example\"\nallow_registration = true\n",
		"registration without gateway":       "[gateway]\nallow_registration = true\n" + validPolicy,
		"invalid certifier":                  "[certgate]\ncertifiers = [\"invalid\"]\ntypes = [\"" + testCertificateType + "\"]\n",
		"invalid type":                       "[certgate]\ncertifiers = [\"" + testCertifier + "\"]\ntypes = [\"invalid\"]\n",
		"reveal type not configured":         validPolicy + "[certgate.reveal_fields]\n\"" + otherType + "\" = [\"role\"]\n",
		"unrevocable type not configured":    validPolicy + "[certgate.allow_unrevocable]\n\"" + otherType + "\" = true\n",
		"bad revocation policy":              "[certgate]\ncertifiers = [\"" + testCertifier + "\"]\ntypes = [\"" + testCertificateType + "\"]\nrevocation_check = \"sometimes\"\n",
		"unparseable recheck":                "[certgate]\ncertifiers = [\"" + testCertifier + "\"]\ntypes = [\"" + testCertificateType + "\"]\nrevocation_recheck = \"soon\"\n",
		"zero recheck":                       "[certgate]\ncertifiers = [\"" + testCertifier + "\"]\ntypes = [\"" + testCertificateType + "\"]\nrevocation_recheck = \"0s\"\n",
		"negative recheck":                   "[certgate]\ncertifiers = [\"" + testCertifier + "\"]\ntypes = [\"" + testCertificateType + "\"]\nrevocation_recheck = \"-1s\"\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTestConfig(t, t.TempDir(), body)); err == nil {
				t.Fatal("invalid certificate configuration loaded")
			}
		})
	}
}
