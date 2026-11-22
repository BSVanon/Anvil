package api

import (
	"context"
	"net/http"

	"github.com/BSVanon/Anvil/internal/certgate"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// CertificateAdmission carries the optional certificate policy and the
// gateway registration handler that uses it. Its zero value changes nothing.
type CertificateAdmission struct {
	Gate          *certgate.Gate
	RequireSender bool
	Registration  http.Handler
}

func (s *Server) certificateAuthOptions() []func(*middleware.AuthMiddlewareConfig) {
	opts := []func(*middleware.AuthMiddlewareConfig){middleware.WithAuthAllowUnauthenticated()}
	if s.certificateGate.Gate == nil || (!s.certificateGate.RequireSender && s.certificateGate.Registration == nil && s.messagingPolicy.PrivateHomes == nil) {
		return opts
	}
	opts = append(opts,
		middleware.WithAuthCertificatesToRequest(s.certificateGate.Gate.RequestedCertificates()),
		middleware.WithAuthCertificatesReceivedListener(s.onCertificatesReceived),
	)
	return opts
}

func (s *Server) onCertificatesReceived(ctx context.Context, identity *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
	if s.certificateGate.Gate == nil {
		return nil
	}
	return s.certificateGate.Gate.VerifyAny(ctx, identity, certs)
}

func (s *Server) senderCertificateAllowed(ctx context.Context, identity string) bool {
	if !s.certificateGate.RequireSender {
		return true
	}
	return s.certificateGate.Gate != nil && s.certificateGate.Gate.Admitted(ctx, identity)
}

func (s *Server) registerCertificateRoutes(sub *http.ServeMux, wrapped http.Handler) {
	if s.certificateGate.Registration == nil {
		return
	}
	sub.Handle("POST /gateway/sites", s.certificateGate.Registration)
	sub.Handle("DELETE /gateway/sites/{domain}", s.certificateGate.Registration)
	s.mux.Handle("/gateway/sites", wrapped)
	s.mux.Handle("/gateway/sites/", wrapped)
}

// SetGatewayRegistrationReload connects successful registration writes to the
// live gateway allowlist after the gateway has constructed it.
func (s *Server) SetGatewayRegistrationReload(reload func()) {
	registrar, ok := s.certificateGate.Registration.(interface{ SetReload(func()) })
	if ok {
		registrar.SetReload(reload)
	}
}

func (s *Server) certificateStats() map[string]int64 {
	if s.certificateGate.Gate == nil {
		return nil
	}
	return s.certificateGate.Gate.Stats()
}

var _ auth.OnCertificateReceivedCallback = (*Server)(nil).onCertificatesReceived
