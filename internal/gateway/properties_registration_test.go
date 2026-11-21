package gateway

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/sitesfile"
)

func propertyRegistrationIdentity(i int) string { return fmt.Sprintf("02%064x", i+1) }

func propertyRegistrationPost(r *Registrar, identity, domain string) *httptest.ResponseRecorder {
	body := []byte(`{"domain":"` + domain + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/gateway/sites", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	r.add(recorder, req, identity)
	return recorder
}

func TestRegistrationProperties(t *testing.T) {
	t.Run("parallel identity cap", func(t *testing.T) {
		r := testRegistrar(t)
		identity := propertyRegistrationIdentity(0)
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				propertyRegistrationPost(r, identity, fmt.Sprintf("identity-%d.example", i))
			}(i)
		}
		wg.Wait()
		raw, err := os.ReadFile(r.path)
		if err != nil {
			t.Fatal(err)
		}
		lines, err := scanSiteLines(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(registeredEntries(lines)); got != maxDomainsPerIdentity {
			t.Fatalf("registrations for one identity = %d, want %d", got, maxDomainsPerIdentity)
		}
	})

	t.Run("parallel total cap", func(t *testing.T) {
		r := testRegistrar(t)
		var wg sync.WaitGroup
		for i := 0; i < maxRegisteredDomains+16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				propertyRegistrationPost(r, propertyRegistrationIdentity(i), fmt.Sprintf("total-%d.example", i))
			}(i)
		}
		wg.Wait()
		raw, err := os.ReadFile(r.path)
		if err != nil {
			t.Fatal(err)
		}
		lines, err := scanSiteLines(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(registeredEntries(lines)); got != maxRegisteredDomains {
			t.Fatalf("total registrations = %d, want %d", got, maxRegisteredDomains)
		}
	})

	t.Run("another identity cannot delete", func(t *testing.T) {
		r := testRegistrar(t)
		if _, _, err := r.register(propertyRegistrationIdentity(1), "owned.example"); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodDelete, "/gateway/sites/owned.example", nil)
		req.SetPathValue("domain", "owned.example")
		response := httptest.NewRecorder()
		r.remove(response, req, propertyRegistrationIdentity(2))
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "ERR_NOT_REGISTRATION_OWNER") {
			t.Fatalf("delete response = %d, %s", response.Code, response.Body.String())
		}
	})

	t.Run("operator domain conflicts", func(t *testing.T) {
		r := testRegistrar(t)
		if err := os.WriteFile(r.operatorPath, []byte("domain operator.example\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		response := propertyRegistrationPost(r, propertyRegistrationIdentity(1), "operator.example")
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "ERR_OPERATOR_DOMAIN") {
			t.Fatalf("response = %d, %s", response.Code, response.Body.String())
		}
	})

	t.Run("request body is bounded", func(t *testing.T) {
		r := testRegistrar(t)
		req := httptest.NewRequest(http.MethodPost, "/gateway/sites", bytes.NewReader(bytes.Repeat([]byte("x"), maxRegistrationBody+1)))
		response := httptest.NewRecorder()
		r.add(response, req, propertyRegistrationIdentity(1))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("oversized body status = %d", response.Code)
		}
	})

	t.Run("domain rules match sites file", func(t *testing.T) {
		label63 := strings.Repeat("a", 63)
		longDomain := strings.Join([]string{label63, label63, label63, label63}, ".")
		for _, input := range []string{"Example.COM", "example.com.", "192.0.2.1", "::1", longDomain} {
			t.Run(input, func(t *testing.T) {
				r := testRegistrar(t)
				response := propertyRegistrationPost(r, propertyRegistrationIdentity(1), input)
				normalized, valid := sitesfile.ValidateDomain(input)
				if valid && response.Code != http.StatusCreated {
					t.Fatalf("valid domain status = %d, body %s", response.Code, response.Body.String())
				}
				if !valid && response.Code != http.StatusBadRequest {
					t.Fatalf("invalid domain status = %d, body %s", response.Code, response.Body.String())
				}
				if valid {
					raw, err := os.ReadFile(r.path)
					if err != nil || !strings.Contains(string(raw), "domain "+normalized+" ") {
						t.Fatalf("registration = %q, %v", raw, err)
					}
				}
			})
		}
	})

	t.Run("registration still requires TXT", func(t *testing.T) {
		r := testRegistrar(t)
		propertyRegistrationPost(r, propertyRegistrationIdentity(1), "notxt.example")
		allow := NewAllowlistWithRegistrations(r.operatorPath, r.path, "", slog.Default())
		clock := time.Now()
		policy := NewPolicy(allow, newTestResolver(&fakeTXTLookup{}, &clock))
		if _, ok := policy.Allowed(t.Context(), "notxt.example"); ok {
			t.Fatal("registered domain without _ordfs TXT was served")
		}
	})

	t.Run("malformed registration keeps merged snapshot", func(t *testing.T) {
		dir := t.TempDir()
		operatorPath := filepath.Join(dir, "operator.conf")
		registrationPath := filepath.Join(dir, "registrations.conf")
		if err := os.WriteFile(operatorPath, []byte("domain operator.example\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		good := "domain registered.example  # registered-by " + propertyRegistrationIdentity(1) + "\n"
		if err := os.WriteFile(registrationPath, []byte(good), 0o640); err != nil {
			t.Fatal(err)
		}
		allow := NewAllowlistWithRegistrations(operatorPath, registrationPath, "", slog.Default())
		if err := os.WriteFile(registrationPath, []byte("malformed\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		allow.Reload()
		if !allow.Snapshot().HasDomain("operator.example") || !allow.Snapshot().HasDomain("registered.example") {
			t.Fatal("malformed registration replaced the last good merged snapshot")
		}
	})

	t.Run("file mode and ownership", func(t *testing.T) {
		r := testRegistrar(t)
		if err := os.WriteFile(r.path, []byte("# existing\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(r.path)
		if err != nil {
			t.Fatal(err)
		}
		propertyRegistrationPost(r, propertyRegistrationIdentity(1), "mode.example")
		after, err := os.Stat(r.path)
		if err != nil {
			t.Fatal(err)
		}
		beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
		afterStat, afterOK := after.Sys().(*syscall.Stat_t)
		if after.Mode().Perm() != 0o640 {
			t.Fatalf("mode = %o, want 640", after.Mode().Perm())
		}
		if !beforeOK || !afterOK || beforeStat.Uid != afterStat.Uid || beforeStat.Gid != afterStat.Gid {
			t.Fatal("registration rewrite changed owner or group")
		}
	})
}
