package gossip

import "github.com/BSVanon/Anvil/internal/envelope"

// SetOnEnvelopeHook adds an additional callback invoked for each mesh-received
// envelope. The existing onEnvelope callback (if any) continues to fire.
func (m *Manager) SetOnEnvelopeHook(fn func(*envelope.Envelope)) {
	prev := m.onEnvelope
	m.onEnvelope = func(env *envelope.Envelope) {
		if prev != nil {
			prev(env)
		}
		fn(env)
	}
}

// PeerCount returns the number of connected mesh peers.
func (m *Manager) PeerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.peers)
}
