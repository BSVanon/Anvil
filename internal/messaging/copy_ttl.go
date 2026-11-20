package messaging

// Per-copy expiry. The "Forward received"/"API send" tables
// (handlers_msg_policy.go, handlers_messaging.go) store two kinds of
// copies at a TTL shorter than the store-wide `[messaging] ttl_seconds`:
// a locally-sent message addressed to a recipient the Home Rule
// resolves Elsewhere, and a forwarded message received for a recipient
// resolved Unadvertised or Elsewhere. Both use the `forward_copy_ttl`
// config key (wired in cmd/anvil) instead of ttl_seconds. Home-row sends
// and deliveries keep using the existing Send and Deliver (store.go),
// unchanged.
//
// The "ex:" index key keeps its exact layout (keys.go, unchanged) and
// ExpireOld's cutoff logic (store.go, unchanged) is untouched. Only the
// TIMESTAMP written into that key changes, from ReceivedAt to an
// "expiry base" = ReceivedAt + copyTTL - ttl_seconds. Since ExpireOld's
// cutoff is `now - ttl_seconds`, a record expires once base <= cutoff,
// i.e. once ReceivedAt + copyTTL <= now — exactly copyTTL after arrival,
// regardless of ttl_seconds. A record whose copyTTL == ttl_seconds
// (every Send/Deliver call, before and after this change) gets
// base == ReceivedAt, so this needs no migration: an old record's "ex:"
// key already equals its ReceivedAt, exactly what decoding an absent
// ExpiryBase field (zero value) falls back to.

import (
	"errors"
	"strings"
)

// expiryBaseFor computes the "ex:" index timestamp for a record received
// at receivedAt and held for copyTTLSeconds, given the store's
// configured ttlSeconds (s.opts.TTLSeconds).
func expiryBaseFor(receivedAt, copyTTLSeconds, ttlSeconds int64) int64 {
	return receivedAt + copyTTLSeconds - ttlSeconds
}

// effectiveExpiryBase returns the "ex:" key timestamp a record was (or
// must be) indexed under: its ExpiryBase when set, or its ReceivedAt
// otherwise. Every record ever written falls into exactly one case —
// absent/zero ExpiryBase is both every older record's real value and
// the default for a record stored at ttl_seconds (Send, Deliver).
func effectiveExpiryBase(record *StoredMessage) int64 {
	if record.ExpiryBase != 0 {
		return record.ExpiryBase
	}
	return record.ReceivedAt
}

// SendElsewhere mints and, when store is true, persists a
// locally-originated message addressed to a recipient the Home Rule
// resolved Elsewhere (the "API send, Elsewhere" row),
// validating exactly as Send does. ttlSeconds is normally the node's
// configured forward_copy_ttl. When store is false (forward_copy_ttl ==
// 0), nothing is persisted and the minted ID is simply returned, so the
// API response and the gossip forward both carry the same MessageID even
// though this node keeps no copy.
func (s *Store) SendElsewhere(msg *Message, originNode string, ttlSeconds int64, store bool) (string, error) {
	id, record, err := s.prepareSend(msg, originNode)
	if err != nil {
		return "", err
	}
	if !store {
		return id, nil
	}
	record.ExpiryBase = expiryBaseFor(record.ReceivedAt, ttlSeconds, s.opts.TTLSeconds)
	inserted, err := s.insertAndNotify(record)
	if err != nil {
		return "", err
	}
	if !inserted {
		return "", errors.New("message ID already exists")
	}
	return id, nil
}

// DeliverCopy stores an incoming forwarded message at a per-copy TTL
// (the "Forward received, Unadvertised or Elsewhere" row),
// validating exactly as Deliver does. ttlSeconds is normally the node's
// configured forward_copy_ttl. Deliver itself remains the Home row's
// path, since a Home delivery always keeps the full ttl_seconds.
func (s *Store) DeliverCopy(msg *Message, attestedBy string, ttlSeconds int64) (bool, error) {
	if err := ValidateForwardMessage(msg); err != nil {
		return false, err
	}
	stored := *msg
	stored.Sender = strings.ToLower(stored.Sender)
	stored.Recipient = strings.ToLower(stored.Recipient)
	receivedAt := s.now().Unix()
	record := &StoredMessage{
		Message:    stored,
		AttestedBy: strings.ToLower(attestedBy),
		ReceivedAt: receivedAt,
		ExpiryBase: expiryBaseFor(receivedAt, ttlSeconds, s.opts.TTLSeconds),
	}
	return s.insertAndNotify(record)
}
