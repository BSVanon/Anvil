package gossip

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
)

var (
	peerAdvertVerifyInterval = 6 * time.Hour
	peerAdvertRetrySchedule  = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour}
)

type PeerAdvertiseConfig struct {
	ExplicitURL string
	PublicURL   string
	Listen      string
	TLS         bool
}

// StartPeerExchangeAdvertiser publishes the initial non-network state before
// returning, then owns verification and retries in a background goroutine.
// In particular, an explicit URL is available to the first heartbeat.
func (m *Manager) StartPeerExchangeAdvertiser(ctx context.Context, cfg PeerAdvertiseConfig) {
	if m.pex == nil || !m.pex.enabled {
		m.setAdvertiseStatus("", "off")
		return
	}
	if cfg.ExplicitURL != "" {
		m.setAdvertiseStatus(cfg.ExplicitURL, "configured")
	} else {
		closedMode := m.allowlist != nil && m.allowlist.enabled()
		if len(deriveAdvertiseCandidates(cfg.PublicURL, cfg.Listen, cfg.TLS, closedMode)) == 0 {
			m.setAdvertiseStatus("", "none")
		} else {
			m.setAdvertiseStatus("", "unverified")
		}
	}
	go m.RunPeerExchangeAdvertiser(ctx, cfg)
}

// RunPeerExchangeAdvertiser verifies the address this node puts in heartbeat
// records. Explicit addresses remain configured even when their advisory
// self-check fails; derived addresses disappear immediately on a failed check.
func (m *Manager) RunPeerExchangeAdvertiser(ctx context.Context, cfg PeerAdvertiseConfig) {
	if m.pex == nil || !m.pex.enabled {
		m.setAdvertiseStatus("", "off")
		return
	}
	if cfg.ExplicitURL != "" {
		m.setAdvertiseStatus(cfg.ExplicitURL, "configured")
		for {
			if err := m.selfCheckMeshURL(ctx, cfg.ExplicitURL); err != nil && ctx.Err() == nil {
				m.logger.Warn("configured mesh advertise_url self-check failed", "url", cfg.ExplicitURL, "error", err)
			}
			if !waitAdvertise(ctx, peerAdvertVerifyInterval) {
				return
			}
		}
	}

	closedMode := m.allowlist != nil && m.allowlist.enabled()
	candidates := deriveAdvertiseCandidates(cfg.PublicURL, cfg.Listen, cfg.TLS, closedMode)
	if len(candidates) == 0 {
		m.setAdvertiseStatus("", "none")
		return
	}
	retryIndex := 0
	for {
		verified := verifyAdvertiseCandidates(ctx, candidates, m.selfCheckMeshURL)
		if verified != "" {
			m.setAdvertiseStatus(verified, "verified")
			retryIndex = 0
			if !waitAdvertise(ctx, peerAdvertVerifyInterval) {
				return
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}
		m.setAdvertiseStatus("", "unverified")
		delay := peerAdvertRetrySchedule[min(retryIndex, len(peerAdvertRetrySchedule)-1)]
		if retryIndex < len(peerAdvertRetrySchedule)-1 {
			retryIndex++
		}
		if !waitAdvertise(ctx, delay) {
			return
		}
	}
}

func deriveAdvertiseCandidates(publicURL, listen string, tlsEnabled, closedMode bool) []string {
	if closedMode || publicURL == "" || listen == "" {
		return nil
	}
	public, err := url.Parse(publicURL)
	if err != nil || (public.Scheme != "http" && public.Scheme != "https") || public.Hostname() == "" {
		return nil
	}
	hostname := public.Hostname()
	if strings.EqualFold(hostname, "localhost") {
		return nil
	}
	if ip := net.ParseIP(hostname); ip != nil && isUnsafeExchangeIP(ip) {
		return nil
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return nil
	}
	meshHost := net.JoinHostPort(hostname, port)
	if public.Scheme == "http" {
		return []string{"ws://" + meshHost}
	}
	candidates := []string{"wss://" + public.Host + "/mesh"}
	if tlsEnabled {
		candidates = append(candidates, "wss://"+meshHost)
	} else {
		candidates = append(candidates, "ws://"+meshHost)
	}
	return candidates
}

func verifyAdvertiseCandidates(ctx context.Context, candidates []string, check func(context.Context, string) error) string {
	for _, candidate := range candidates {
		if err := check(ctx, candidate); err == nil {
			return candidate
		}
		if ctx.Err() != nil {
			return ""
		}
	}
	return ""
}

func (m *Manager) selfCheckMeshURL(parent context.Context, endpoint string) error {
	if err := parent.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	transport, err := newWSTransportAdapter(endpoint, 10*time.Second, false)
	if err != nil {
		return err
	}
	m.attachTransport(transport)
	defer transport.Close()
	peer := auth.NewPeer(&auth.PeerOptions{Wallet: m.wallet, Transport: transport})
	if err := peer.Start(); err != nil {
		return err
	}
	defer peer.Stop()
	go transport.StartReceive()
	session, err := peer.GetAuthenticatedSession(ctx, nil, 10000)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	identity := fmt.Sprintf("%x", session.PeerIdentityKey.Compressed())
	if identity == "" || identity != m.localIdentity {
		return fmt.Errorf("handshake revealed a different identity")
	}
	return nil
}

func (m *Manager) setAdvertiseStatus(advertisedURL, state string) {
	if m.pex == nil {
		return
	}
	m.pex.mu.Lock()
	m.pex.advertURL = advertisedURL
	m.pex.advertState = state
	m.pex.mu.Unlock()
}

func waitAdvertise(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
