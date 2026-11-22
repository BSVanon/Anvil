package gossip

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"

	"github.com/BSVanon/Anvil/internal/messaging"
)

const (
	MsgHomeClaim  MessageType = "home_claim"
	MsgHomeRevoke MessageType = "home_revoke"
	MsgHomeAck    MessageType = "home_ack"
	MsgHomeStatus MessageType = "home_status"

	privateHomeProtocolVersion = 1
	maxHomeRecords             = 200
	maxHomeClaimPayload        = 256 << 10
	maxHomeStatusPayload       = 64 << 10
	maxHomeAckIDs              = 1000
	maxHomeAckPayload          = 2 << 20
)

type HomeClaimPayload struct {
	Records []messaging.PrivateHomeRecord `json:"records"`
}

type HomeRevokePayload struct {
	Member         string `json:"member"`
	BeforeIssuedAt int64  `json:"beforeIssuedAt"`
}

type HomeAckPayload struct {
	Recipient  string   `json:"recipient"`
	MessageIDs []string `json:"messageIds"`
}

type HomeApplied struct {
	Member   string `json:"member"`
	IssuedAt int64  `json:"issuedAt"`
}

type HomeStatusPayload struct {
	Version int           `json:"version"`
	Applied []HomeApplied `json:"applied,omitempty"`
}

type homeDropLogState struct {
	mu   sync.Mutex
	last time.Time
}

var homeDropLogs sync.Map

func (m *Manager) privateHomesEnabled() bool {
	return m != nil && m.messagingPolicy.PrivateHomes != nil && m.allowlist != nil && m.allowlist.enabled()
}

func (m *Manager) ownIdentity() string {
	if m == nil || m.identityKey == nil {
		return ""
	}
	return strings.ToLower(m.identityKey.PubKey().ToDERHex())
}

// BroadcastHomeRecord shares one newly accepted local record with allowed peers.
func (m *Manager) BroadcastHomeRecord(record messaging.PrivateHomeRecord) {
	m.broadcastHomeRecords([]messaging.PrivateHomeRecord{record}, "")
}

func (m *Manager) announcePrivateHomes(peer *auth.Peer) {
	target, ok := m.targetForPeer(peer)
	if ok {
		m.announcePrivateHomesToTarget(target)
	}
}

func (m *Manager) announcePrivateHomesToTarget(target peerSendTarget) {
	if !m.privateHomesEnabled() {
		return
	}
	if m.sendHomeStatus(target, nil) != nil {
		return
	}
	pacer := newHomeControlPacer()
	pacer.wait(1)
	registry := m.messagingPolicy.PrivateHomes
	err := registry.ForEachRecordPage(maxHomeRecords, func(records []messaging.PrivateHomeRecord) error {
		signed := records[:0]
		for _, record := range records {
			if record.Signature != "" {
				signed = append(signed, record)
			}
		}
		if len(signed) == 0 {
			return nil
		}
		pacer.wait(len(signed))
		payload, encodeErr := Encode(MsgHomeClaim, HomeClaimPayload{Records: signed})
		if encodeErr != nil || len(payload) > maxHomeClaimPayload {
			return encodeErr
		}
		if err := target.peer.ToPeer(context.Background(), payload, target.identityPK, 5000); err != nil {
			return err
		}
		applied := make([]HomeApplied, 0, len(signed))
		for _, record := range signed {
			if record.Kind == messaging.PrivateHomeClaim {
				applied = append(applied, HomeApplied{Member: record.Member, IssuedAt: record.IssuedAt})
			}
		}
		if len(applied) > 0 {
			pacer.wait(1 + len(applied))
			return m.sendHomeStatus(target, applied)
		}
		return nil
	})
	if err != nil {
		m.logger.Debug("private home sync interrupted", "peer", truncate(target.identity), "error", err)
		return
	}
	_ = registry.ForEachRevocationPage(maxHomeRecords, func(revocations []messaging.PrivateHomeRevocation) error {
		for _, revocation := range revocations {
			pacer.wait(1)
			payload, encodeErr := Encode(MsgHomeRevoke, HomeRevokePayload{
				Member: revocation.Member, BeforeIssuedAt: revocation.BeforeIssuedAt,
			})
			if encodeErr != nil {
				return encodeErr
			}
			if err := target.peer.ToPeer(context.Background(), payload, target.identityPK, 5000); err != nil {
				return err
			}
		}
		return nil
	})
	m.announcePrivateHomeAcks(target, pacer)
}

// ResyncPrivateHomes is idempotent anti-entropy for already-admitted peers.
func (m *Manager) ResyncPrivateHomes() {
	if !m.privateHomesEnabled() {
		return
	}
	targets := m.snapshotAllowedPeers("", nil, false)
	m.forEachTargetConcurrent(targets, m.announcePrivateHomesToTarget)
}

func (m *Manager) sendHomeStatus(target peerSendTarget, applied []HomeApplied) error {
	payload, err := Encode(MsgHomeStatus, HomeStatusPayload{Version: privateHomeProtocolVersion, Applied: applied})
	if err != nil {
		return err
	}
	return target.peer.ToPeer(context.Background(), payload, target.identityPK, 5000)
}

func (m *Manager) onHomeStatus(sender string, raw json.RawMessage) error {
	if !m.privateHomesEnabled() || !m.allowlist.allows(sender) || len(raw) > maxHomeStatusPayload {
		return nil
	}
	var status HomeStatusPayload
	if json.Unmarshal(raw, &status) != nil || status.Version < 1 || len(status.Applied) > maxHomeRecords {
		return nil
	}
	if !m.allowHomeControl(sender, 1+len(status.Applied)) {
		m.logHomeDrop(sender, "private home control rate limited")
		return nil
	}
	sender = strings.ToLower(sender)
	m.mu.Lock()
	peer, ok := m.peers[sender]
	admitted := ok && admittedPrimaryLocked(sender, peer)
	firstStatus := admitted && peer.privateHomeVersion == 0
	if admitted {
		if status.Version > peer.privateHomeVersion {
			peer.privateHomeVersion = status.Version
		}
	}
	members := make([]string, 0, len(status.Applied))
	if admitted {
		for member := range peer.appliedHomeClaims {
			members = append(members, member)
		}
		for _, applied := range status.Applied {
			if isCompressedKeyHex(applied.Member) {
				members = append(members, applied.Member)
			}
		}
	}
	m.mu.Unlock()
	currentClaims, _ := m.messagingPolicy.PrivateHomes.CurrentClaims(members)
	if admitted {
		m.mu.Lock()
		if current, currentOK := m.peers[sender]; currentOK && current == peer && admittedPrimaryLocked(sender, current) {
			kept := make(map[string]int64, len(currentClaims))
			for member, issuedAt := range peer.appliedHomeClaims {
				if claim, live := currentClaims[member]; live && claim.IssuedAt == issuedAt {
					kept[member] = issuedAt
				}
			}
			for _, applied := range status.Applied {
				if claim, live := currentClaims[applied.Member]; live && claim.IssuedAt == applied.IssuedAt {
					kept[applied.Member] = applied.IssuedAt
				}
			}
			peer.appliedHomeClaims = kept
		}
		m.mu.Unlock()
	}
	if firstStatus {
		if target, found := m.targetForIdentity(sender); found {
			go m.announcePrivateHomesToTarget(target)
		}
	}
	return nil
}

func (m *Manager) broadcastHomeRecords(records []messaging.PrivateHomeRecord, source string) {
	if !m.privateHomesEnabled() || len(records) == 0 || len(records) > maxHomeRecords {
		return
	}
	m.pruneAppliedHomeRecords(records)
	payload, err := Encode(MsgHomeClaim, HomeClaimPayload{Records: records})
	if err != nil || len(payload) > maxHomeClaimPayload {
		return
	}
	m.sendToAllowedPeers(payload, source, nil)
}

func (m *Manager) onHomeClaim(sender string, raw json.RawMessage) error {
	if !m.privateHomesEnabled() || !m.allowlist.allows(sender) || len(raw) > maxHomeClaimPayload {
		return nil
	}
	var payload HomeClaimPayload
	if json.Unmarshal(raw, &payload) != nil || len(payload.Records) == 0 || len(payload.Records) > maxHomeRecords {
		m.logHomeDrop(sender, "invalid home_claim payload")
		return nil
	}
	if !m.allowHomeControl(sender, len(payload.Records)) {
		m.logHomeDrop(sender, "private home control rate limited")
		return nil
	}
	results := m.messagingPolicy.PrivateHomes.ApplyBatch(context.Background(), payload.Records)
	accepted := make([]messaging.PrivateHomeRecord, 0, len(payload.Records))
	applied := make([]HomeApplied, 0, len(payload.Records))
	members := make([]string, 0, len(payload.Records))
	for i, record := range payload.Records {
		if results[i] == nil {
			accepted = append(accepted, record)
		} else {
			m.logHomeDrop(sender, "private home record refused")
		}
		if record.Kind == messaging.PrivateHomeClaim {
			members = append(members, record.Member)
		}
	}
	currentClaims, _ := m.messagingPolicy.PrivateHomes.CurrentClaims(members)
	for _, record := range payload.Records {
		if current, ok := currentClaims[record.Member]; ok && current.IssuedAt >= record.IssuedAt {
			applied = append(applied, HomeApplied{Member: record.Member, IssuedAt: current.IssuedAt})
		}
	}
	if len(accepted) > 0 {
		m.broadcastHomeRecords(accepted, sender)
	}
	if target, ok := m.targetForIdentity(sender); ok {
		_ = m.sendHomeStatus(target, applied)
	}
	return nil
}

// BroadcastHomeRevoke shares a certificate revocation cutoff.
func (m *Manager) BroadcastHomeRevoke(member string, beforeIssuedAt int64) {
	m.broadcastHomeRevoke(HomeRevokePayload{Member: member, BeforeIssuedAt: beforeIssuedAt}, "")
}

func (m *Manager) broadcastHomeRevoke(revoke HomeRevokePayload, source string) {
	if !m.privateHomesEnabled() {
		return
	}
	m.dropAppliedHomeClaim(revoke.Member)
	payload, err := Encode(MsgHomeRevoke, revoke)
	if err == nil {
		m.sendToAllowedPeers(payload, source, nil)
	}
}

func (m *Manager) pruneAppliedHomeRecords(records []messaging.PrivateHomeRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, record := range records {
		for _, peer := range m.peers {
			if record.Kind != messaging.PrivateHomeClaim || peer.appliedHomeClaims[record.Member] != record.IssuedAt {
				delete(peer.appliedHomeClaims, record.Member)
			}
		}
	}
}

func (m *Manager) dropAppliedHomeClaim(member string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, peer := range m.peers {
		delete(peer.appliedHomeClaims, member)
	}
}

func (m *Manager) onPrivateHomeRecordChanged(member string, issuedAt int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, peer := range m.peers {
		if issuedAt == 0 || peer.appliedHomeClaims[member] != issuedAt {
			delete(peer.appliedHomeClaims, member)
		}
	}
}

func (m *Manager) onHomeRevoke(sender string, raw json.RawMessage) error {
	if !m.privateHomesEnabled() || !m.allowlist.allows(sender) || len(raw) > 1024 || !m.allowHomeControl(sender, 1) {
		return nil
	}
	var revoke HomeRevokePayload
	if json.Unmarshal(raw, &revoke) != nil {
		return nil
	}
	changed, err := m.messagingPolicy.PrivateHomes.ApplyRevocation(revoke.Member, revoke.BeforeIssuedAt)
	if err != nil {
		m.logHomeDrop(sender, "private home revocation refused")
		return nil
	}
	if changed {
		m.broadcastHomeRevoke(revoke, sender)
	}
	return nil
}

func (m *Manager) logHomeDrop(sender, reason string) {
	value, _ := homeDropLogs.LoadOrStore(m, &homeDropLogState{})
	state := value.(*homeDropLogState)
	state.mu.Lock()
	defer state.mu.Unlock()
	now := time.Now()
	if !state.last.IsZero() && now.Sub(state.last) < time.Minute {
		return
	}
	state.last = now
	m.logger.Warn(reason, "peer", truncate(sender))
}
