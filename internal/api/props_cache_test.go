package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/content"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func assertPrivateCachePolicy(t *testing.T, wHeader http.Header) {
	t.Helper()
	if got := wHeader.Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q, want private, no-store", got)
	}
	vary := strings.Join(wHeader.Values("Vary"), ",")
	for _, name := range []string{"Authorization", "X-Anvil-Auth"} {
		if !headerListContains(vary, name) {
			t.Fatalf("Vary = %q, want %s", vary, name)
		}
	}
}

func TestCachePropertyCredentialDependentResponsesArePrivate(t *testing.T) {
	rows := []struct {
		name  string
		setup func(*testing.T) (*Server, string, map[string]string)
		code  int
	}{
		{"payment offer", func(t *testing.T) (*Server, string, map[string]string) {
			return testServerWithPaymentGate(t, 100), "/stats", nil
		}, http.StatusPaymentRequired},
		{"paid response", func(t *testing.T) (*Server, string, map[string]string) {
			usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
				return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
			})
			srv := testServerWithPaymentGate(t, 100)
			srv.paymentGate.arcClient = usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
				return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
			})
			return srv, "/stats", map[string]string{HeaderBSVPayment: signedEFPaying(t, paidOut{testPayeeScript(t), 100})}
		}, http.StatusOK},
		{"operator response", func(t *testing.T) (*Server, string, map[string]string) {
			return testServerWithPaymentGate(t, 100), "/stats", map[string]string{"Authorization": "Bearer test-token"}
		}, http.StatusOK},
		{"token refusal", func(t *testing.T) (*Server, string, map[string]string) {
			srv := testServer(t)
			key, _ := ec.NewPrivateKey()
			seedEnvelopeAt(t, srv.envelopeStore, "example:cache-token-x", `{"value":true}`, time.Now().Unix(), tokenModel(key))
			resolver := NewTopicMonetizationResolver(srv.envelopeStore)
			srv.tokenGate = NewTokenGate(resolver, true)
			rebuildRoutes(srv)
			return srv, "/data?topic=example:cache-token-x", nil
		}, http.StatusUnauthorized},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			srv, path, headers := row.setup(t)
			w := getWithHeaders(srv, path, headers)
			if w.Code != row.code {
				t.Fatalf("status = %d, want %d: %s", w.Code, row.code, w.Body.String())
			}
			assertPrivateCachePolicy(t, w.Header())
		})
	}
}

func TestCachePropertyContentPolicyDependsOnReadTokenGate(t *testing.T) {
	for _, gated := range []bool{false, true} {
		t.Run(map[bool]string{false: "public", true: "credential dependent"}[gated], func(t *testing.T) {
			f := newTipFixture(t, "test-token", 0)
			if gated {
				f.srv.tokenGate = NewTokenGate(NewTopicMonetizationResolver(f.srv.envelopeStore), true)
			}
			w := getWithHeaders(f.srv, "/content/"+op(f.origin, 0), nil)
			if gated {
				assertPrivateCachePolicy(t, w.Header())
			} else if got := w.Header().Get("Cache-Control"); got != content.ImmutableCacheControl {
				t.Fatalf("Cache-Control = %q, want %q", got, content.ImmutableCacheControl)
			}
		})
	}
}
