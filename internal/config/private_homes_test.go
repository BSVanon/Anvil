package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadPrivateHomeConfig(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anvil.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestPrivateHomeConfigurationDefaultsAndClosedMeshRequirement(t *testing.T) {
	cfg, err := loadPrivateHomeConfig(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Messaging.PrivateHomes || cfg.Messaging.PrivateHomeMaxMembers != 10000 || cfg.Messaging.PrivateHomeMaxTTL != 2592000 {
		t.Fatalf("private home defaults = %+v", cfg.Messaging)
	}
	_, err = loadPrivateHomeConfig(t, "[messaging]\nprivate_homes = true\n")
	if err == nil || !strings.Contains(err.Error(), "messaging.private_homes") || !strings.Contains(err.Error(), "mesh.allowed_peers") {
		t.Fatalf("closed mesh error = %v", err)
	}
}

func TestPrivateHomeConfigurationRanges(t *testing.T) {
	peer := "02" + strings.Repeat("a", 64)
	base := "[mesh]\nallowed_peers = [\"" + peer + "\"]\n[messaging]\nprivate_homes = true\n"
	tests := map[string]string{
		"members below range": "private_home_max_members = 0\n",
		"members above range": "private_home_max_members = 1000001\n",
		"ttl below range":     "private_home_max_ttl = 3599\n",
		"ttl above range":     "private_home_max_ttl = 7776001\n",
	}
	for name, setting := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := loadPrivateHomeConfig(t, base+setting)
			key := strings.Fields(setting)[0]
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("range error = %v", err)
			}
		})
	}
	if _, err := loadPrivateHomeConfig(t, base+"private_home_max_members = 1\nprivate_home_max_ttl = 3600\n"); err != nil {
		t.Fatalf("lower bounds refused: %v", err)
	}
}

func TestPrivateHomeCertificateWatchCapacityIsValidated(t *testing.T) {
	peer := "02" + strings.Repeat("a", 64)
	body := "[mesh]\nallowed_peers = [\"" + peer + "\"]\n" +
		"[messaging]\nprivate_homes = true\nprivate_home_max_members = 10001\n" +
		"[certgate]\ncertifiers = [\"" + testCertifier + "\"]\ntypes = [\"" + testCertificateType + "\"]\n"
	_, err := loadPrivateHomeConfig(t, body)
	if err == nil || !strings.Contains(err.Error(), "private_home_max_members (10001)") ||
		!strings.Contains(err.Error(), "spend watch cap (10000)") {
		t.Fatalf("watch capacity error = %v", err)
	}
}
