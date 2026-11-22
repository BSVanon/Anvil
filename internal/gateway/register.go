package gateway

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/BSVanon/Anvil/internal/certgate"
	"github.com/BSVanon/Anvil/internal/sitesfile"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
)

const (
	maxDomainsPerIdentity = 10
	maxRegisteredDomains  = 1000
	maxRegistrationBody   = 4096
)

// Registrar handles certificate-gated changes to the daemon registration file.
type Registrar struct {
	operatorPath string
	path         string
	apiHost      string
	gate         *certgate.Gate
	logger       *slog.Logger
	maxOwn       int
	maxTotal     int
	reloadMu     sync.RWMutex
	reload       func()
}

// NewRegistrar constructs a registrar and attaches its revocation cleanup.
func NewRegistrar(operatorPath, path, apiHost string, gate *certgate.Gate, logger *slog.Logger) *Registrar {
	if logger == nil {
		logger = slog.Default()
	}
	r := &Registrar{operatorPath: operatorPath, path: path, apiHost: normalizeHost(apiHost), gate: gate, logger: logger, maxOwn: maxDomainsPerIdentity, maxTotal: maxRegisteredDomains}
	if gate != nil {
		gate.OnRevoke("gateway", r.removeIdentity)
	}
	return r
}

// SetReload installs the gateway allowlist reload called after file changes.
func (r *Registrar) SetReload(reload func()) {
	r.reloadMu.Lock()
	r.reload = reload
	r.reloadMu.Unlock()
}

func (r *Registrar) reloadAllowlist() {
	r.reloadMu.RLock()
	reload := r.reload
	r.reloadMu.RUnlock()
	if reload != nil {
		reload()
	}
}

// ServeHTTP implements the two registration endpoints.
func (r *Registrar) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	identity, err := middleware.ShouldGetAuthenticatedIdentity(req.Context())
	if err != nil || identity == nil {
		writeRegistrationError(w, http.StatusUnauthorized, "ERR_BRC31_REQUIRED", "BRC-31 authentication is required.")
		return
	}
	identityHex := hex.EncodeToString(identity.Compressed())
	if r.gate == nil || !r.gate.Admitted(req.Context(), identityHex) {
		writeRegistrationError(w, http.StatusForbidden, "ERR_CERTIFICATE_REQUIRED", "A valid certificate is required.")
		return
	}
	switch req.Method {
	case http.MethodPost:
		r.add(w, req, identityHex)
	case http.MethodDelete:
		r.remove(w, req, identityHex)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (r *Registrar) add(w http.ResponseWriter, req *http.Request, identity string) {
	body, err := io.ReadAll(io.LimitReader(req.Body, maxRegistrationBody+1))
	if err != nil || len(body) > maxRegistrationBody {
		writeRegistrationError(w, http.StatusBadRequest, "ERR_INVALID_DOMAIN", "Invalid domain request.")
		return
	}
	var input struct {
		Domain string `json:"domain"`
	}
	if json.Unmarshal(body, &input) != nil {
		writeRegistrationError(w, http.StatusBadRequest, "ERR_INVALID_DOMAIN", "Invalid domain request.")
		return
	}
	domain, ok := sitesfile.ValidateDomain(input.Domain)
	if !ok || domain == r.apiHost {
		writeRegistrationError(w, http.StatusBadRequest, "ERR_INVALID_DOMAIN", "Invalid domain.")
		return
	}
	status, code, err := r.register(identity, domain)
	if err != nil {
		writeRegistrationError(w, http.StatusInternalServerError, "ERR_REGISTRATION_WRITE", "Registration could not be stored.")
		return
	}
	if code != "" {
		writeRegistrationError(w, status, code, "Domain registration was refused.")
		return
	}
	if status == http.StatusCreated && r.gate != nil && !r.gate.Admitted(req.Context(), identity) {
		_, _, _ = r.unregister(identity, domain)
		writeRegistrationError(w, http.StatusForbidden, "ERR_CERTIFICATE_REQUIRED", "A valid certificate is required.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"status":"success"}`))
}

func (r *Registrar) register(identity, domain string) (int, string, error) {
	owned, err := r.operatorHasDomain(domain)
	if err != nil {
		return 0, "", err
	}
	if owned {
		return http.StatusConflict, "ERR_OPERATOR_DOMAIN", nil
	}
	status, code, err := r.update(func(lines []string, entries []registeredDomain) ([]string, int, string) {
		own := 0
		for _, entry := range entries {
			if entry.owner == identity {
				own++
			}
			if entry.domain == domain {
				if entry.owner == identity {
					return lines, http.StatusOK, ""
				}
				return lines, http.StatusConflict, "ERR_DOMAIN_REGISTERED"
			}
		}
		if hasDomainLine(lines, domain) {
			return lines, http.StatusConflict, "ERR_DOMAIN_REGISTERED"
		}
		if own >= r.maxOwn {
			return lines, http.StatusForbidden, "ERR_DOMAIN_LIMIT"
		}
		if len(entries) >= r.maxTotal {
			return lines, http.StatusForbidden, "ERR_SITE_LIMIT"
		}
		return append(lines, fmt.Sprintf("domain %s  # registered-by %s", domain, identity)), http.StatusCreated, ""
	})
	if err == nil && code == "" && status == http.StatusCreated {
		r.reloadAllowlist()
	}
	return status, code, err
}

func (r *Registrar) remove(w http.ResponseWriter, req *http.Request, identity string) {
	domain, ok := sitesfile.ValidateDomain(req.PathValue("domain"))
	if !ok {
		writeRegistrationError(w, http.StatusBadRequest, "ERR_INVALID_DOMAIN", "Invalid domain.")
		return
	}
	status, code, err := r.unregister(identity, domain)
	if err != nil {
		writeRegistrationError(w, http.StatusInternalServerError, "ERR_REGISTRATION_WRITE", "Registration could not be removed.")
		return
	}
	if code != "" {
		writeRegistrationError(w, status, code, "Domain removal was refused.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"success"}`))
}

func (r *Registrar) unregister(identity, domain string) (int, string, error) {
	owned, err := r.operatorHasDomain(domain)
	if err != nil {
		return 0, "", err
	}
	if owned {
		return http.StatusConflict, "ERR_OPERATOR_DOMAIN", nil
	}
	status, code, err := r.update(func(lines []string, entries []registeredDomain) ([]string, int, string) {
		foundOther := false
		kept := make([]string, 0, len(lines))
		removed := false
		for _, line := range lines {
			entry, ok := parseRegisteredDomain(line)
			if ok && entry.domain == domain {
				if entry.owner != identity {
					foundOther = true
				}
				if entry.owner == identity {
					removed = true
					continue
				}
			}
			kept = append(kept, line)
		}
		if foundOther {
			return lines, http.StatusForbidden, "ERR_NOT_REGISTRATION_OWNER"
		}
		if !removed {
			return lines, http.StatusNotFound, "ERR_REGISTRATION_NOT_FOUND"
		}
		return kept, http.StatusOK, ""
	})
	if err == nil && code == "" && status == http.StatusOK {
		r.reloadAllowlist()
	}
	return status, code, err
}

func (r *Registrar) operatorHasDomain(domain string) (bool, error) {
	if r.operatorPath == "" {
		return false, nil
	}
	entries, err := sitesfile.Read(r.operatorPath)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Kind == "domain" && entry.Value == domain {
			return true, nil
		}
	}
	return false, nil
}

type registeredDomain struct{ domain, owner string }

func parseRegisteredDomain(line string) (registeredDomain, bool) {
	fields := strings.Fields(line)
	if len(fields) != 5 || !strings.EqualFold(fields[0], "domain") || fields[2] != "#" || fields[3] != "registered-by" {
		return registeredDomain{}, false
	}
	domain, ok := sitesfile.ValidateDomain(fields[1])
	owner, err := hex.DecodeString(fields[4])
	if !ok || err != nil || len(owner) != 33 {
		return registeredDomain{}, false
	}
	return registeredDomain{domain: domain, owner: strings.ToLower(fields[4])}, true
}

func registeredEntries(lines []string) []registeredDomain {
	entries := make([]registeredDomain, 0)
	for _, line := range lines {
		if entry, ok := parseRegisteredDomain(line); ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

func hasDomainLine(lines []string, domain string) bool {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "domain") {
			if value, ok := sitesfile.ValidateDomain(fields[1]); ok && value == domain {
				return true
			}
		}
	}
	return false
}

func (r *Registrar) update(change func([]string, []registeredDomain) ([]string, int, string)) (status int, code string, err error) {
	err = sitesfile.WithLock(r.path, func() error {
		raw, readErr := os.ReadFile(r.path)
		if readErr != nil && !os.IsNotExist(readErr) {
			return readErr
		}
		lines, scanErr := scanSiteLines(raw)
		if scanErr != nil {
			return scanErr
		}
		updated, resultStatus, resultCode := change(lines, registeredEntries(lines))
		status, code = resultStatus, resultCode
		if resultCode != "" || sameLines(lines, updated) {
			return nil
		}
		text := strings.Join(updated, "\n")
		if len(updated) > 0 {
			text += "\n"
		}
		return sitesfile.AtomicWriteFile(r.path, []byte(text), 0640, -1, -1)
	})
	return status, code, err
}

func scanSiteLines(raw []byte) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func sameLines(a, b []string) bool { return strings.Join(a, "\n") == strings.Join(b, "\n") }

func (r *Registrar) removeIdentity(identity string) {
	removed := 0
	_, _, err := r.update(func(lines []string, _ []registeredDomain) ([]string, int, string) {
		kept := make([]string, 0, len(lines))
		for _, line := range lines {
			entry, ok := parseRegisteredDomain(line)
			if ok && entry.owner == identity {
				removed++
				continue
			}
			kept = append(kept, line)
		}
		return kept, http.StatusOK, ""
	})
	if err != nil {
		r.logger.Warn("gateway certificate revocation cleanup failed", "error", err)
	} else if removed > 0 {
		r.reloadAllowlist()
		r.logger.Info("gateway certificate revocation removed registrations", "count", removed)
	}
}

func writeRegistrationError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "error", "code": code, "description": message})
}
