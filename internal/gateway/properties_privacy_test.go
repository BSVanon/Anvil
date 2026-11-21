package gateway

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistrationLogsOmitPrivateRequestDetails(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	dir := t.TempDir()
	r := NewRegistrar(filepath.Join(dir, "operator.conf"), filepath.Join(dir, "registrations.conf"), "", nil, logger)
	identity := propertyRegistrationIdentity(9)
	domain := "private-registration.example"
	endpoint := "/gateway/sites/private-endpoint"
	clientIP := "203.0.113.88"
	body := bytes.NewBufferString(`{"domain":"` + domain + `"}`)
	req := httptest.NewRequest(http.MethodPost, endpoint, body)
	req.RemoteAddr = clientIP + ":5555"
	r.add(httptest.NewRecorder(), req, identity)
	r.removeIdentity(identity)

	logged := logs.String()
	for _, private := range []string{domain, identity, endpoint, clientIP} {
		if strings.Contains(logged, private) {
			t.Fatalf("registration log exposed private value %q: %s", private, logged)
		}
	}
}
