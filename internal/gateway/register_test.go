package gateway

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/sitesfile"
)

func testRegistrar(t *testing.T) *Registrar {
	t.Helper()
	dir := t.TempDir()
	return NewRegistrar(filepath.Join(dir, "operator.conf"), filepath.Join(dir, "registrations.conf"), "", nil, slog.Default())
}

func TestRegistrationDoesNotWriteOperatorFile(t *testing.T) {
	operatorDir := t.TempDir()
	r := NewRegistrar(
		filepath.Join(operatorDir, "operator.conf"),
		filepath.Join(t.TempDir(), "gateway-registrations.conf"),
		"",
		nil,
		slog.Default(),
	)
	if err := os.WriteFile(r.operatorPath, []byte("domain operator.example\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(operatorDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(operatorDir, 0o755) })
	status, code, err := r.register(registrationIdentity('1'), "registered.example")
	if err != nil || status != http.StatusCreated || code != "" {
		t.Fatalf("register = %d, %q, %v", status, code, err)
	}
	operator, err := os.ReadFile(r.operatorPath)
	if err != nil || string(operator) != "domain operator.example\n" {
		t.Fatalf("operator file = %q, %v", operator, err)
	}
}

func TestOperatorDomainCannotBeChangedByRegistrationAPI(t *testing.T) {
	r := testRegistrar(t)
	if err := os.WriteFile(r.operatorPath, []byte("domain operator.example\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	identity := registrationIdentity('1')
	for name, change := range map[string]func() (int, string, error){
		"register": func() (int, string, error) { return r.register(identity, "operator.example") },
		"delete":   func() (int, string, error) { return r.unregister(identity, "operator.example") },
	} {
		t.Run(name, func(t *testing.T) {
			status, code, err := change()
			if err != nil || status != http.StatusConflict || code != "ERR_OPERATOR_DOMAIN" {
				t.Fatalf("result = %d, %q, %v", status, code, err)
			}
		})
	}
}

func TestRegistrationReloadsAfterChanges(t *testing.T) {
	r := testRegistrar(t)
	reloads := 0
	r.SetReload(func() { reloads++ })
	identity := registrationIdentity('1')
	_, _, _ = r.register(identity, "site.example")
	_, _, _ = r.unregister(identity, "site.example")
	if reloads != 2 {
		t.Fatalf("reloads = %d, want 2", reloads)
	}
}

func registrationIdentity(digit byte) string { return "02" + strings.Repeat(string(digit), 64) }

func TestRegistrationAddAndRemoveOwnEntry(t *testing.T) {
	r := testRegistrar(t)
	identity := registrationIdentity('1')
	status, code, err := r.register(identity, "site.example")
	if err != nil || status != 201 || code != "" {
		t.Fatalf("register = %d, %q, %v", status, code, err)
	}
	raw, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	want := "domain site.example  # registered-by " + identity + "\n"
	if string(raw) != want {
		t.Fatalf("sites file = %q, want %q", raw, want)
	}
	status, code, err = r.unregister(identity, "site.example")
	if err != nil || status != 200 || code != "" {
		t.Fatalf("unregister = %d, %q, %v", status, code, err)
	}
	entries, err := sitesfile.Read(r.path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries after remove = %#v, %v", entries, err)
	}
}

func TestRegistrationCannotRemoveAnotherIdentity(t *testing.T) {
	r := testRegistrar(t)
	owner := registrationIdentity('1')
	other := registrationIdentity('2')
	if _, _, err := r.register(owner, "site.example"); err != nil {
		t.Fatal(err)
	}
	status, code, err := r.unregister(other, "site.example")
	if err != nil || status != 403 || code != "ERR_NOT_REGISTRATION_OWNER" {
		t.Fatalf("unregister = %d, %q, %v", status, code, err)
	}
}

func TestRegistrationCaps(t *testing.T) {
	t.Run("per identity", func(t *testing.T) {
		r := testRegistrar(t)
		r.maxOwn = 2
		identity := registrationIdentity('1')
		for _, domain := range []string{"one.example", "two.example"} {
			if _, code, err := r.register(identity, domain); err != nil || code != "" {
				t.Fatalf("register %s: %q, %v", domain, code, err)
			}
		}
		status, code, err := r.register(identity, "three.example")
		if err != nil || status != 403 || code != "ERR_DOMAIN_LIMIT" {
			t.Fatalf("third registration = %d, %q, %v", status, code, err)
		}
	})
	t.Run("total", func(t *testing.T) {
		r := testRegistrar(t)
		r.maxTotal = 2
		for i, domain := range []string{"one.example", "two.example"} {
			if _, code, err := r.register(registrationIdentity(byte('1'+i)), domain); err != nil || code != "" {
				t.Fatalf("register %s: %q, %v", domain, code, err)
			}
		}
		status, code, err := r.register(registrationIdentity('3'), "three.example")
		if err != nil || status != 403 || code != "ERR_SITE_LIMIT" {
			t.Fatalf("third registration = %d, %q, %v", status, code, err)
		}
	})
}

func TestRegistrationRevocationRemovesOwnedEntries(t *testing.T) {
	r := testRegistrar(t)
	one, two := registrationIdentity('1'), registrationIdentity('2')
	_, _, _ = r.register(one, "one.example")
	_, _, _ = r.register(two, "two.example")
	r.removeIdentity(one)
	raw, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "one.example") || !strings.Contains(string(raw), "two.example") {
		t.Fatalf("revocation cleanup wrote %q", raw)
	}
}

func TestRegisteredDomainStillUsesTXTPolicy(t *testing.T) {
	r := testRegistrar(t)
	_, _, _ = r.register(registrationIdentity('1'), "site.example")
	allow := NewAllowlistWithRegistrations(r.operatorPath, r.path, "", slog.Default())
	clock := time.Now()
	lookup := &fakeTXTLookup{}
	resolver := newTestResolver(lookup, &clock)
	policy := NewPolicy(allow, resolver)
	if _, ok := policy.Allowed(t.Context(), "site.example"); ok {
		t.Fatal("registration without an authoritative TXT origin was served")
	}
	origin := testOutpoint(42, 0)
	lookup.records = []string{"ordfs=" + origin}
	resolver = newTestResolver(lookup, &clock)
	policy = NewPolicy(allow, resolver)
	if got, ok := policy.Allowed(t.Context(), "site.example"); !ok || got != origin {
		t.Fatalf("registered domain resolved to (%q, %v), want (%q, true)", got, ok, origin)
	}
}
