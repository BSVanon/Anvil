package gateway

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistrationFileExistsOnlyAfterEnabledRegistrationWrites(t *testing.T) {
	dir := t.TempDir()
	path := RegistrationFile(dir)
	registrar := NewRegistrar(filepath.Join(dir, "sites.conf"), path, "api.example", nil, slog.Default())
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("constructing an unused registrar created its file: %v", err)
	}
	status, code, err := registrar.register(registrationIdentity('1'), "site.example")
	if err != nil || status != http.StatusCreated || code != "" {
		t.Fatalf("registration = (%d, %q, %v)", status, code, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("enabled registration did not create its file: %v", err)
	}
}
